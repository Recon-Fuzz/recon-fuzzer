//! HTTP/WebSocket server for the web UI

use crate::protocol::{CoverageDelta, CoverageSnapshot, ServerMessage, StateUpdatePayload};
use crate::state::{Commandable, Observable};
use crate::ws::handle_websocket;
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::{info, warn};

/// Application state shared between handlers
pub struct AppState<S> {
    /// The observable/commandable fuzzer state
    pub fuzzer_state: Arc<S>,
    /// Broadcast channel for sending updates to all connected clients
    pub broadcast_tx: broadcast::Sender<ServerMessage>,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            fuzzer_state: self.fuzzer_state.clone(),
            broadcast_tx: self.broadcast_tx.clone(),
        }
    }
}

/// Web server configuration
pub struct WebServerConfig {
    /// Port to listen on (ws://)
    pub port: u16,
    /// Port for TLS/wss:// (self-signed cert, for HTTPS pages connecting to localhost)
    pub tls_port: u16,
    /// Address to bind to (default: 0.0.0.0 for external access via tunnels)
    pub bind_address: String,
    /// Optional path to static files directory
    pub static_dir: Option<String>,
    /// State update interval in milliseconds
    pub update_interval_ms: u64,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            port: 4444,
            tls_port: 4445,
            bind_address: "0.0.0.0".to_string(),
            static_dir: None,
            update_interval_ms: 100,
        }
    }
}

/// Web server for the fuzzer UI
pub struct WebServer<S> {
    state: Arc<S>,
    config: WebServerConfig,
    broadcast_tx: broadcast::Sender<ServerMessage>,
}

impl<S: Observable + Commandable> WebServer<S> {
    /// Create a new web server with its own broadcast channel
    pub fn new(state: Arc<S>, config: WebServerConfig) -> Self {
        let (broadcast_tx, _) = broadcast::channel(1024);
        Self {
            state,
            config,
            broadcast_tx,
        }
    }

    /// Create a new web server with an external broadcast channel
    /// Use this when you need to broadcast messages from outside the server
    pub fn new_with_broadcast(
        state: Arc<S>,
        config: WebServerConfig,
        broadcast_tx: broadcast::Sender<ServerMessage>,
    ) -> Self {
        Self {
            state,
            config,
            broadcast_tx,
        }
    }

    /// Create a broadcast channel that can be shared with other components
    /// Returns (sender, WebServer)
    pub fn create_with_shared_broadcast(
        state: Arc<S>,
        config: WebServerConfig,
    ) -> (broadcast::Sender<ServerMessage>, Self) {
        let (broadcast_tx, _) = broadcast::channel(1024);
        let server = Self {
            state,
            config,
            broadcast_tx: broadcast_tx.clone(),
        };
        (broadcast_tx, server)
    }

    /// Create with default configuration
    pub fn with_defaults(state: Arc<S>, port: u16) -> Self {
        Self::new(
            state,
            WebServerConfig {
                port,
                ..Default::default()
            },
        )
    }

    /// Get a sender for broadcasting messages to all clients
    pub fn get_broadcast_sender(&self) -> broadcast::Sender<ServerMessage> {
        self.broadcast_tx.clone()
    }

    /// Start the web server (blocking)
    /// Spawns both ws:// (port) and wss:// (tls_port) listeners
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app_state = AppState {
            fuzzer_state: self.state.clone(),
            broadcast_tx: self.broadcast_tx.clone(),
        };

        // Build router
        let mut app = Router::new()
            .route("/ws", get(ws_handler::<S>))
            .route("/health", get(health_handler))
            .route("/", get(index_handler))
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any),
            )
            .with_state(app_state.clone());

        // Serve static files if configured
        if let Some(ref static_dir) = self.config.static_dir {
            app = app.fallback_service(ServeDir::new(static_dir));
        }

        // Start state sampler task
        let sampler_state = self.state.clone();
        let sampler_tx = self.broadcast_tx.clone();
        let update_interval = Duration::from_millis(self.config.update_interval_ms);
        tokio::spawn(async move {
            state_sampler(sampler_state, sampler_tx, update_interval).await;
        });

        // Start plain ws:// server
        let addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        info!("Web UI server listening on http://{}", addr);
        info!("WebSocket endpoint: ws://{}/ws", addr);

        // Spawn wss:// server with self-signed TLS on tls_port
        let tls_addr = format!("{}:{}", self.config.bind_address, self.config.tls_port);
        let tls_app = app.clone();
        tokio::spawn(async move {
            match generate_self_signed_tls_config() {
                Ok(tls_config) => {
                    info!("WebSocket TLS endpoint: wss://{}/ws", tls_addr);
                    info!(
                        "  (self-signed cert — browser will need to trust it once at https://{})",
                        tls_addr
                    );
                    let server = axum_server::bind_rustls(tls_addr.parse().unwrap(), tls_config)
                        .serve(tls_app.into_make_service());
                    if let Err(e) = server.await {
                        warn!("TLS server error: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to generate self-signed TLS cert, wss:// not available: {}", e);
                }
            }
        });

        // Run plain HTTP server (blocks)
        axum::serve(listener, app).await?;

        Ok(())
    }
}

/// WebSocket upgrade handler
async fn ws_handler<S: Observable + Commandable>(
    ws: WebSocketUpgrade,
    State(state): State<AppState<S>>,
) -> impl IntoResponse {
    let fuzzer_state = state.fuzzer_state.clone();
    let broadcast_rx = state.broadcast_tx.subscribe();

    ws.on_upgrade(move |socket| handle_websocket(socket, fuzzer_state, broadcast_rx))
}

/// Health check endpoint
async fn health_handler() -> &'static str {
    "ok"
}

/// Index page (simple redirect to UI)
async fn index_handler() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Recon Fuzzer Web UI</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0a;
            color: #fafafa;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 2rem;
        }
        h1 {
            color: #3b82f6;
            margin-bottom: 1rem;
        }
        p {
            color: #a1a1aa;
            margin-bottom: 2rem;
        }
        code {
            background: #27272a;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            color: #22c55e;
        }
        .status {
            margin-top: 2rem;
            padding: 1rem;
            background: #18181b;
            border-radius: 0.5rem;
            border: 1px solid #27272a;
        }
        .connected {
            color: #22c55e;
        }
        .disconnected {
            color: #ef4444;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Recon Fuzzer</h1>
        <p>Web UI backend is running. Start the UI with:</p>
        <code>npx recon-ui --port 4444</code>
        <div class="status">
            <p>WebSocket Status: <span id="status" class="disconnected">Checking...</span></p>
        </div>
    </div>
    <script>
        const ws = new WebSocket('ws://' + window.location.host + '/ws');
        const status = document.getElementById('status');
        ws.onopen = () => {
            status.textContent = 'Connected';
            status.className = 'connected';
        };
        ws.onclose = () => {
            status.textContent = 'Disconnected';
            status.className = 'disconnected';
        };
        ws.onerror = () => {
            status.textContent = 'Error';
            status.className = 'disconnected';
        };
    </script>
</body>
</html>"#,
    )
}

/// State sampler that periodically sends updates to connected clients
async fn state_sampler<S: Observable>(
    state: Arc<S>,
    tx: broadcast::Sender<ServerMessage>,
    interval: Duration,
) {
    // Start with empty coverage - first iteration will populate it
    // This avoids blocking the async runtime at startup
    let mut last_coverage: Option<CoverageSnapshot> = None;
    let mut interval_timer = tokio::time::interval(interval);

    loop {
        interval_timer.tick().await;

        // Skip if no clients connected (avoid unnecessary work)
        if tx.receiver_count() == 0 {
            continue;
        }

        // Run all lock-acquiring operations in a blocking task
        // This prevents blocking the single-threaded async runtime
        let state_clone = Arc::clone(&state);
        let last_cov = last_coverage.take();

        let result = tokio::task::spawn_blocking(move || {
            // Get current stats (fast - just atomic reads)
            let (calls, sequences, gas, elapsed_ms) = state_clone.get_stats();

            // Get coverage snapshot
            let current_coverage = state_clone.get_coverage_snapshot();

            // Compute delta (or use empty if first iteration)
            let delta = match &last_cov {
                Some(last) => state_clone.get_coverage_delta(last),
                None => CoverageDelta {
                    new_runtime: current_coverage.runtime.clone(),
                    new_init: current_coverage.init.clone(),
                    new_instructions: current_coverage.total_instructions,
                },
            };

            // Only compute line coverage when there's new coverage
            let source_line_coverage = if delta.new_instructions > 0 {
                Some(state_clone.get_source_line_coverage())
            } else {
                None
            };

            // Build update payload
            let update = StateUpdatePayload {
                elapsed_ms,
                total_calls: calls,
                total_sequences: sequences,
                total_gas: gas,
                coverage_delta: delta,
                workers: state_clone.get_worker_snapshots(),
                revert_hotspots: state_clone.get_revert_hotspots(20),
                corpus_size: state_clone.get_corpus_size(),
                campaign_state: state_clone.get_campaign_state(),
                source_line_coverage,
            };

            (update, current_coverage)
        }).await;

        match result {
            Ok((update, current_coverage)) => {
                // Store for next iteration
                last_coverage = Some(current_coverage);
                // Send to all connected clients
                let _ = tx.send(ServerMessage::StateUpdate(update));
            }
            Err(e) => {
                tracing::warn!("State sampler task failed: {}", e);
            }
        }
    }
}

/// Generate a self-signed TLS config for localhost wss:// connections
fn generate_self_signed_tls_config() -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    use rcgen::{CertificateParams, KeyPair, SanType};
    use std::sync::Arc as StdArc;

    // Ensure rustls has a crypto provider installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Build rustls config synchronously (axum_server wants RustlsConfig but we can build from pem)
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or("no private key found")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(StdArc::new(tls_config)))
}

/// Helper function to open the browser
pub fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }
}
