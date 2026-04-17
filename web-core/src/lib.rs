//! Recon Web - Web UI backend for recon-fuzzer
//!
//! This crate provides the server-side infrastructure for the recon-fuzzer web UI.
//! It includes:
//!
//! - WebSocket server for real-time communication
//! - Protocol types for messages between frontend and backend
//! - Traits for observable/commandable fuzzer state
//! - State sampling and broadcasting
//!
//! # Usage
//!
//! To add web UI support to your fuzzer:
//!
//! 1. Implement the `Observable` trait for your fuzzer state
//! 2. Optionally implement `Commandable` for interactive features
//! 3. Create a `WebServer` and run it
//!
//! ```ignore
//! use recon_web::{WebServer, WebServerConfig, Observable, Commandable};
//! use std::sync::Arc;
//!
//! // Your fuzzer state that implements Observable + Commandable
//! let state = Arc::new(YourFuzzerState::new());
//!
//! // Create and run the server
//! let config = WebServerConfig {
//!     port: 4444,
//!     ..Default::default()
//! };
//! let server = WebServer::new(state, config);
//!
//! // Run in a separate task
//! tokio::spawn(async move {
//!     server.run().await.unwrap();
//! });
//! ```
//!
//! # Quick Start with Builder
//!
//! ```ignore
//! use recon_web::WebServerBuilder;
//!
//! let handle = WebServerBuilder::new(state)
//!     .port(4444)
//!     .open_browser(true)
//!     .spawn()
//!     .await?;
//! ```

pub mod protocol;
pub mod server;
pub mod state;
pub mod ws;

// Re-exports for convenience
pub use protocol::*;
pub use server::{open_browser, WebServer, WebServerConfig};
pub use state::{Commandable, Observable, ReadOnlyState, WebState};

use std::sync::Arc;
use tokio::task::JoinHandle;

/// Builder for easy web server setup
pub struct WebServerBuilder<S> {
    state: Arc<S>,
    port: u16,
    static_dir: Option<String>,
    update_interval_ms: u64,
    open_browser_on_start: bool,
}

impl<S: Observable + Commandable> WebServerBuilder<S> {
    /// Create a new builder with the given state
    pub fn new(state: Arc<S>) -> Self {
        Self {
            state,
            port: 4444,
            static_dir: None,
            update_interval_ms: 100,
            open_browser_on_start: false,
        }
    }

    /// Set the port to listen on (default: 4444)
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the static files directory for serving the UI
    pub fn static_dir(mut self, dir: impl Into<String>) -> Self {
        self.static_dir = Some(dir.into());
        self
    }

    /// Set the state update interval in milliseconds (default: 100)
    pub fn update_interval_ms(mut self, ms: u64) -> Self {
        self.update_interval_ms = ms;
        self
    }

    /// Whether to open the browser on start (default: false)
    pub fn open_browser(mut self, open: bool) -> Self {
        self.open_browser_on_start = open;
        self
    }

    /// Build and spawn the web server in a background task
    pub async fn spawn(self) -> Result<WebServerHandle, Box<dyn std::error::Error + Send + Sync>> {
        let config = WebServerConfig {
            port: self.port,
            static_dir: self.static_dir,
            update_interval_ms: self.update_interval_ms,
            ..Default::default()
        };

        let server = WebServer::new(self.state, config);
        let broadcast_tx = server.get_broadcast_sender();
        let url = format!("http://127.0.0.1:{}", self.port);

        let handle = tokio::spawn(async move {
            server.run().await
        });

        if self.open_browser_on_start {
            open_browser(&url);
        }

        Ok(WebServerHandle {
            url,
            join_handle: handle,
            broadcast_tx,
        })
    }
}

/// Handle to a running web server
pub struct WebServerHandle {
    /// URL where the server is listening
    pub url: String,
    /// Join handle for the server task
    pub join_handle: JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    /// Broadcast sender for pushing messages to all clients
    pub broadcast_tx: tokio::sync::broadcast::Sender<ServerMessage>,
}

impl WebServerHandle {
    /// Get the server URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send a message to all connected clients
    pub fn broadcast(&self, message: ServerMessage) -> Result<usize, tokio::sync::broadcast::error::SendError<ServerMessage>> {
        self.broadcast_tx.send(message)
    }

    /// Check if the server task is still running
    pub fn is_running(&self) -> bool {
        !self.join_handle.is_finished()
    }
}
