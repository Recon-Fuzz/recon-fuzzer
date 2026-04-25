//! Recon CLI
//!
//! Smart contract fuzzer executor for Foundry projects.

use anyhow::{Context, Result};
use campaign::campaign::run_campaign;
use campaign::config::Env;
use campaign::corpus::load_corpus;
use campaign::web::WebObservableState;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use alloy_primitives::{Address, U256};
use evm::{
    exec::EvmState,
    foundry::{deploy_with_linking, find_contract, FoundryProject},
};
// use campaign::{run_campaign, EConfig, Env, corpus::load_corpus};

/// Recon: Smart contract fuzzer
#[derive(Parser, Debug)]
#[command(name = "recon")]
#[command(author = "Recon Contributors")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Smart contract fuzzer for Foundry projects")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Fuzz test a contract (default mode, Echidna-compatible)
    Fuzz(FuzzArgs),
}

/// Arguments for fuzz testing
#[derive(Parser, Debug)]
struct FuzzArgs {
    /// Path to Foundry project (or Solidity files)
    #[arg(required = true)]
    project: PathBuf,

    /// Contract name to fuzz (uses first contract if not specified)
    #[arg(short, long)]
    contract: Option<String>,

    /// Config file (command-line arguments override config options)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Number of fuzzing workers
    #[arg(short, long)]
    workers: Option<u8>,

    /// Maximum number of test iterations (default: 50000)
    #[arg(long, value_parser = parse_capped_usize)]
    test_limit: Option<usize>,

    /// Number of tries to shrink a failing sequence (default: 5000)
    #[arg(long)]
    shrink_limit: Option<usize>,

    /// Sequence length - calls per sequence (default: 100)
    #[arg(long)]
    seq_len: Option<usize>,

    /// Random seed
    #[arg(long)]
    seed: Option<u64>,

    /// Corpus directory for saving/loading corpus (also used by Echidna from shared config)
    #[arg(long)]
    corpus_dir: Option<PathBuf>,

    /// Recon-specific corpus directory. When set, recon reads/writes its corpus here
    /// and auto-exports Echidna-compatible format to --corpus-dir (or config corpusDir).
    /// This allows sharing the same echidna.yaml between recon and Echidna.
    #[arg(long)]
    recon_corpus_dir: Option<PathBuf>,

    /// Test mode: 'property', 'assertion', 'optimization', 'exploration'
    #[arg(long)]
    test_mode: Option<String>,

    /// Timeout in seconds
    #[arg(long)]
    timeout: Option<u64>,

    /// Stop on first failure
    #[arg(long)]
    stop_on_fail: bool,

    /// Output format: 'text', 'json', 'none'
    #[arg(long)]
    format: Option<String>,

    /// Address to deploy the contract to (default: 0x00a329c0648769a73afac7f9381e08fb43dbea72)
    #[arg(long)]
    contract_addr: Option<String>,

    /// Address of the deployer (default: 0x30000)
    #[arg(long)]
    deployer: Option<String>,

    /// Sender addresses for transactions (can be passed multiple times)
    #[arg(long)]
    sender: Vec<String>,

    /// Generate calls to all deployed contracts
    #[arg(long)]
    all_contracts: bool,

    /// RPC URL to fetch contracts over (for forking)
    #[arg(long)]
    rpc_url: Option<String>,

    /// Block number to use when fetching over RPC
    #[arg(long)]
    rpc_block: Option<u64>,

    /// Quiet mode (less output)
    #[arg(short, long)]
    quiet: bool,

    /// Only fuzz state-mutating functions (exclude pure/view)
    #[arg(long)]
    mutable_only: bool,

    /// Replay a corpus file and show traces (e.g., --replay echidna/reproducers/foo.txt)
    #[arg(long)]
    replay: Option<PathBuf>,

    /// Enable LCOV coverage report writing during fuzzing (disabled by default for performance)
    #[arg(long)]
    lcov: bool,

    /// Coverage mode: 'full' (every opcode, default) or 'branch' (only JUMPI/JUMPDEST, faster)
    #[arg(long)]
    coverage_mode: Option<String>,

    /// Fast mode: shorthand for --coverage-mode=branch (faster but less coverage granularity)
    #[arg(long)]
    fast: bool,

    /// Enable shortcuts hoisting: run shortcut_* functions at startup to bootstrap corpus
    #[arg(long)]
    shortcuts: bool,

    /// Enable web UI for interactive fuzzing.
    /// Without a value, opens the default hosted UI (or FUZZER_WEB_URL env var).
    /// With a URL, opens that specific frontend (e.g. --web localhost:3000 for local dev).
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    web: Option<String>,

    /// Port for web UI WebSocket server (default: 4444)
    #[arg(long)]
    web_port: Option<u16>,

    /// Don't open the browser automatically when --web is set
    #[arg(long)]
    no_open: bool,

    /// Shrink-only mode: skip fuzzing, load existing reproducers, and shrink them
    #[arg(long)]
    shrink: bool,

    /// Convert-only mode: export recon corpus to Echidna format and exit (requires --recon-corpus-dir)
    #[arg(long)]
    convert: bool,

    /// Compatibility stub: accepted for compatibility with Echidna-style CLIs but has no effect
    #[arg(long, hide = true)]
    #[allow(dead_code)]
    disable_slither: bool,
}

/// Clap value parser for usize that caps oversized values at usize::MAX
/// (i.e. u64::MAX on 64-bit targets) instead of erroring on overflow.
fn parse_capped_usize(s: &str) -> Result<usize, String> {
    match s.trim().parse::<u128>() {
        Ok(n) => Ok(usize::try_from(n).unwrap_or(usize::MAX)),
        Err(e) => Err(e.to_string()),
    }
}

/// Serde deserializer for `Option<usize>` that accepts integers, floats, or
/// strings that exceed `usize::MAX` and silently caps them at `usize::MAX`,
/// so configs with very large `testLimit` values don't fail to parse.
fn deserialize_capped_usize<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Num {
        Int(i128),
        Float(f64),
        Str(String),
    }

    let opt = Option::<Num>::deserialize(deserializer)?;
    Ok(opt.map(|v| match v {
        Num::Int(n) => {
            if n <= 0 {
                0
            } else {
                usize::try_from(n).unwrap_or(usize::MAX)
            }
        }
        Num::Float(f) => {
            if !f.is_finite() || f <= 0.0 {
                0
            } else if f >= usize::MAX as f64 {
                usize::MAX
            } else {
                f as usize
            }
        }
        Num::Str(s) => s
            .trim()
            .parse::<u128>()
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
            .unwrap_or(usize::MAX),
    }))
}

/// Parse an address from hex string
fn parse_address(s: &str) -> Result<Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("Invalid hex address")?;
    if bytes.len() != 20 {
        anyhow::bail!("Address must be 20 bytes");
    }
    Ok(Address::from_slice(&bytes))
}

// Define a flat configuration struct for parsing echidna.yaml
#[derive(serde::Deserialize)]
struct FlatConfig {
    #[serde(rename = "testMode")]
    test_mode: Option<String>,
    prefix: Option<String>,
    // Note: Echidna's coverage option is not implemented; coverage is always enabled
    #[serde(default, rename = "coverage")]
    _coverage: Option<bool>,
    #[serde(rename = "corpusDir")]
    corpus_dir: Option<PathBuf>,
    #[serde(rename = "contractAddr")]
    contract_addr: Option<String>,
    deployer: Option<String>,
    sender: Option<Vec<String>>,
    #[serde(rename = "testLimit", default, deserialize_with = "deserialize_capped_usize")]
    test_limit: Option<usize>,
    #[serde(rename = "shrinkLimit")]
    shrink_limit: Option<usize>,
    #[serde(rename = "seqLen")]
    seq_len: Option<usize>,
    workers: Option<u8>,
    timeout: Option<u64>,
    #[serde(rename = "stopOnFail")]
    stop_on_fail: Option<bool>,
    // Add other fields as needed
    #[serde(rename = "rpcUrl")]
    rpc_url: Option<String>,
    #[serde(rename = "rpcBlock")]
    rpc_block: Option<u64>,
    #[serde(rename = "allContracts")]
    all_contracts: Option<bool>,
    #[serde(rename = "mutableOnly")]
    mutable_only: Option<bool>,
    // Performance
    #[serde(rename = "lcovEnable")]
    lcov_enable: Option<bool>,
    #[serde(rename = "lcovInterval")]
    lcov_interval: Option<u64>,
    #[serde(rename = "coverageMode")]
    coverage_mode: Option<String>,
    // Shortcuts hoisting
    #[serde(rename = "shortcutsEnable")]
    shortcuts_enable: Option<bool>,
}

/// Default production URL for the hosted web UI
const DEFAULT_WEB_UI_URL: &str = "https://recon-fuzzer.vercel.app";

/// Spawn the WebSocket backend and open the frontend URL in the browser.
/// Returns Arc<WebObservableState> - the web state must be stored in env.
///
/// When web mode is enabled:
/// - N workers are used for fuzzing (0..N-1)
/// - Worker N is the "interactive" worker for web UI commands
///
/// The `frontend_url` is always opened with ?ws=ws://localhost:{port}/ws appended.
fn spawn_web_server(
    env: &Env,
    deployed_addresses: Vec<(Address, String)>,
    port: Option<u16>,
    stop_flag: Option<Arc<AtomicBool>>,
    frontend_url: &str,
    open_browser: bool,
) -> Result<((), Arc<WebObservableState>)> {
    use std::sync::Arc;

    let port = port.unwrap_or(4444);
    // N fuzzing workers + 1 interactive worker for web UI
    let num_fuzzing_workers = env.cfg.campaign_conf.workers as usize;
    let total_workers = num_fuzzing_workers + 1; // +1 for interactive worker

    // Create the observable state wrapper
    // This clones the Arc references from env, so updates are shared
    // The last worker (index N) is marked as the interactive worker
    let mut web_state_inner = WebObservableState::new_with_interactive(
        env,
        num_fuzzing_workers,
        total_workers,
        deployed_addresses,
    );

    // Set up stop flag if provided
    if let Some(ref flag) = stop_flag {
        web_state_inner.set_stop_flag(flag.clone());
    }

    // Build and spawn the WebSocket server
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime for web server")?;

    let config = recon_web::WebServerConfig {
        port,
        bind_address: "0.0.0.0".to_string(),
        static_dir: None,
        update_interval_ms: 100,
        ..Default::default()
    };

    // Create a shared broadcast channel for immediate notifications
    let (broadcast_tx, _) = tokio::sync::broadcast::channel(1024);
    web_state_inner.set_broadcast_sender(broadcast_tx.clone());

    let web_state = Arc::new(web_state_inner);

    // Clone for the server (server takes ownership)
    let web_state_for_server = web_state.clone();

    let server =
        recon_web::WebServer::new_with_broadcast(web_state_for_server, config, broadcast_tx);

    // Spawn the server in a background thread
    std::thread::spawn(move || {
        runtime.block_on(async {
            if let Err(e) = server.run().await {
                error!("Web server error: {}", e);
            }
        });
    });

    info!("WebSocket server started on ws://0.0.0.0:{}/ws", port);

    // Normalize the frontend URL
    let full_url = if !frontend_url.contains("://") {
        format!("http://{}", frontend_url)
    } else {
        frontend_url.to_string()
    };

    if open_browser {
        info!("Opening web UI: {}", full_url);
        recon_web::open_browser(&full_url);
    } else {
        info!("Web UI ready: {} (browser not opened: --no-open)", full_url);
    }

    Ok(((), web_state))
}

fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    match cli.command {
        Commands::Fuzz(args) => run_fuzz(args),
    }
}

/// Run fuzz testing (main fuzzer logic)
fn run_fuzz(args: FuzzArgs) -> Result<()> {
    // Initialize logging
    // Default: info level, but silence rig crate's verbose internal logs
    let default_filter = if args.quiet {
        "warn,rig=off"
    } else {
        "info,rig=off"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into()),
        )
        .init();

    info!("Recon-Fuzzer v{}", env!("CARGO_PKG_VERSION"));
    info!("Project: {:?}", args.project);

    // Initialize default config
    let mut config = config::global::EConfig::default();

    // Load config from file if specified
    if let Some(config_path) = &args.config {
        info!("Loading config from {:?}", config_path);
        let file = std::fs::File::open(config_path).context("Failed to open config file")?;

        // Parse into flat config
        let flat: FlatConfig =
            yaml_serde::from_reader(file).context("Failed to parse config file")?;

        // Map flat config to EConfig structure
        if let Some(mode) = flat.test_mode {
            if let Some(parsed) = config::solidity::TestMode::from_str(&mode) {
                config.sol_conf.test_mode = parsed;
            }
        }
        if let Some(prefix) = flat.prefix {
            config.sol_conf.prefix = prefix;
        }
        if let Some(corpus_dir) = flat.corpus_dir {
            config.campaign_conf.corpus_dir = Some(corpus_dir);
        }
        if let Some(addr) = flat.contract_addr {
            config.sol_conf.contract_addr = parse_address(&addr)?;
        }
        if let Some(deployer) = flat.deployer {
            config.sol_conf.deployer = parse_address(&deployer)?;
        }
        if let Some(senders) = flat.sender {
            config.sol_conf.sender = senders
                .iter()
                .map(|s| parse_address(s))
                .collect::<Result<_>>()?;
        }
        if let Some(limit) = flat.test_limit {
            config.campaign_conf.test_limit = limit;
        }
        if let Some(limit) = flat.shrink_limit {
            config.campaign_conf.shrink_limit = limit;
        }
        if let Some(len) = flat.seq_len {
            config.campaign_conf.seq_len = len;
        }
        if let Some(workers) = flat.workers {
            config.campaign_conf.workers = workers;
        }
        if let Some(timeout) = flat.timeout {
            config.campaign_conf.timeout = Some(timeout);
        }
        if let Some(stop) = flat.stop_on_fail {
            config.campaign_conf.stop_on_fail = stop;
        }
        if let Some(url) = flat.rpc_url {
            config.rpc_url = Some(url);
        }
        if let Some(block) = flat.rpc_block {
            config.rpc_block = Some(block);
        }
        if let Some(all) = flat.all_contracts {
            config.sol_conf.all_contracts = all;
        }
        if let Some(mutable) = flat.mutable_only {
            config.sol_conf.mutable_only = mutable;
        }

        // Note: coverage option from config is parsed but coverage is always enabled
        // Coverage tracking is handled internally via Env.coverage_ref_*

        // Performance configuration
        if let Some(enable) = flat.lcov_enable {
            config.campaign_conf.lcov_enable = enable;
        }
        if let Some(interval) = flat.lcov_interval {
            config.campaign_conf.lcov_interval = interval;
        }
        if let Some(mode) = flat.coverage_mode {
            config.campaign_conf.coverage_mode = mode;
        }

        // Shortcuts hoisting
        if let Some(enable) = flat.shortcuts_enable {
            config.campaign_conf.shortcuts_enable = enable;
        }
    }

    // Override config with CLI arguments
    if let Some(limit) = args.test_limit {
        config.campaign_conf.test_limit = limit;
    }
    if let Some(limit) = args.shrink_limit {
        config.campaign_conf.shrink_limit = limit;
    }
    if let Some(len) = args.seq_len {
        config.campaign_conf.seq_len = len;
    }
    if let Some(seed) = args.seed {
        config.campaign_conf.seed = Some(seed);
    }
    if let Some(dir) = args.corpus_dir {
        config.campaign_conf.corpus_dir = Some(dir);
    }
    if let Some(workers) = args.workers {
        config.campaign_conf.workers = workers;
    }
    if let Some(timeout) = args.timeout {
        config.campaign_conf.timeout = Some(timeout);
    }
    if args.stop_on_fail {
        config.campaign_conf.stop_on_fail = true;
    }

    if let Some(mode) = args.test_mode {
        if let Some(parsed) = config::solidity::TestMode::from_str(&mode) {
            config.sol_conf.test_mode = parsed;
        }
    }
    if args.all_contracts {
        config.sol_conf.all_contracts = true;
    }
    if args.mutable_only {
        config.sol_conf.mutable_only = true;
    }
    if args.lcov {
        config.campaign_conf.lcov_enable = true;
    }
    if let Some(mode) = args.coverage_mode {
        config.campaign_conf.coverage_mode = mode;
    }
    if args.fast {
        config.campaign_conf.coverage_mode = "branch".to_string();
    }
    if args.shortcuts {
        config.campaign_conf.shortcuts_enable = true;
    }

    if let Some(addr_str) = args.contract_addr {
        config.sol_conf.contract_addr = parse_address(&addr_str)?;
    }
    if let Some(addr_str) = args.deployer {
        config.sol_conf.deployer = parse_address(&addr_str)?;
    }
    if !args.sender.is_empty() {
        config.sol_conf.sender = args
            .sender
            .iter()
            .map(|s| parse_address(s))
            .collect::<Result<Vec<_>>>()?;
    }

    if let Some(url) = args.rpc_url {
        config.rpc_url = Some(url);
    }
    if let Some(block) = args.rpc_block {
        config.rpc_block = Some(block);
    }

    // Handle --recon-corpus-dir: recon uses this dir for its corpus, and
    // auto-exports Echidna format to the original corpus_dir so both tools
    // can share the same config file.
    if let Some(recon_dir) = args.recon_corpus_dir {
        // The resolved corpus_dir (from config or CLI) becomes the Echidna export target
        let echidna_dir = config
            .campaign_conf
            .corpus_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("echidna"));
        config.campaign_conf.export_dir = Some(echidna_dir);
        // Recon uses recon_corpus_dir for all internal corpus operations
        config.campaign_conf.corpus_dir = Some(recon_dir);
    }

    // Compile project
    info!("Compiling project...");
    let mut project =
        FoundryProject::compile(&args.project).context("Failed to compile project")?;

    if project.contracts.is_empty() {
        error!("No contracts found in project");
        return Ok(());
    }

    info!("Found {} contracts", project.contracts.len());

    // Find main contract
    let mut main_contract = find_contract(&project.contracts, args.contract.as_deref())
        .context("Contract not found")?
        .clone();

    info!("Fuzzing contract: {}", main_contract.name);

    // Load slither/recon-generate info for source analysis 
    // This provides precise constants from source code analysis
    let project_path = args.project.to_string_lossy();
    let slither_info = match analysis::slither::SlitherInfo::load_from_recon_generate(
        &project_path,
        &main_contract.name,
    ) {
        Ok(info) => {
            let constants_count: usize = info
                .constants_used
                .values()
                .map(|funcs| funcs.values().map(|v| v.len()).sum::<usize>())
                .sum();
            info!(
                "Loaded slither info: {} functions with {} constants",
                info.constants_used.values().map(|f| f.len()).sum::<usize>(),
                constants_count
            );

            // Auto-adjust max_time_delay and max_block_delay based on constants
            // This allows reaching exact timestamps/blocks found in source code
            let required_delays = analysis::slither::calculate_required_delays(&info);
            if required_delays.max_time_delay > config.tx_conf.max_time_delay {
                info!(
                    "Auto-adjusting max_time_delay: {} -> {} (to reach timestamp constants)",
                    config.tx_conf.max_time_delay, required_delays.max_time_delay
                );
                config.tx_conf.max_time_delay = required_delays.max_time_delay;
            }
            if required_delays.max_block_delay > config.tx_conf.max_block_delay {
                info!(
                    "Auto-adjusting max_block_delay: {} -> {} (to reach block number constants)",
                    config.tx_conf.max_block_delay, required_delays.max_block_delay
                );
                config.tx_conf.max_block_delay = required_delays.max_block_delay;
            }

            Some(info)
        }
        Err(e) => {
            // Retry: rebuild with --build-info and try again
            let build_info_dir = args.project.join("out").join("build-info");

            // Delete build-info if it exists (may be corrupted)
            if build_info_dir.exists() {
                info!("recon-generate info failed, removing build-info...");
                if let Err(rm_err) = std::fs::remove_dir_all(&build_info_dir) {
                    warn!("Failed to remove build-info: {}", rm_err);
                }
            }

            // Rebuild project with --build-info
            info!("Rebuilding project with --build-info...");
            let rebuild_result = std::process::Command::new("forge")
                .arg("build")
                .arg("--build-info")
                .arg("-o")
                .arg("out")
                .current_dir(&args.project)
                .output();

            match rebuild_result {
                Ok(output) if output.status.success() => {
                    // Retry recon-generate info
                    match analysis::slither::SlitherInfo::load_from_recon_generate(
                        &project_path,
                        &main_contract.name,
                    ) {
                        Ok(info) => {
                            info!("recon-generate info succeeded on retry");
                            let constants_count: usize = info
                                .constants_used
                                .values()
                                .map(|funcs| funcs.values().map(|v| v.len()).sum::<usize>())
                                .sum();
                            info!(
                                "Loaded slither info: {} functions with {} constants",
                                info.constants_used.values().map(|f| f.len()).sum::<usize>(),
                                constants_count
                            );

                            // Auto-adjust max_time_delay and max_block_delay based on constants
                            let required_delays =
                                analysis::slither::calculate_required_delays(&info);
                            if required_delays.max_time_delay > config.tx_conf.max_time_delay {
                                info!(
                                    "Auto-adjusting max_time_delay: {} -> {} (to reach timestamp constants)",
                                    config.tx_conf.max_time_delay, required_delays.max_time_delay
                                );
                                config.tx_conf.max_time_delay = required_delays.max_time_delay;
                            }
                            if required_delays.max_block_delay > config.tx_conf.max_block_delay {
                                info!(
                                    "Auto-adjusting max_block_delay: {} -> {} (to reach block number constants)",
                                    config.tx_conf.max_block_delay, required_delays.max_block_delay
                                );
                                config.tx_conf.max_block_delay = required_delays.max_block_delay;
                            }

                            Some(info)
                        }
                        Err(retry_err) => {
                            warn!("Failed to load slither info: {}. Fuzzing will continue with bytecode constants only.", retry_err);
                            None
                        }
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("forge build --build-info failed: {}. Fuzzing will continue with bytecode constants only.", stderr);
                    None
                }
                Err(rebuild_err) => {
                    warn!("Failed to run forge build: {}. Original error: {}. Fuzzing will continue with bytecode constants only.", rebuild_err, e);
                    None
                }
            }
        }
    };

    // Set exclude_from_fuzzing from slither info if available
    if let Some(ref info) = slither_info {
        let excluded = info.get_excluded_functions();
        if !excluded.is_empty() {
            info!(
                "Excluding {} functions from fuzzing: {:?}",
                excluded.len(),
                excluded
            );
            main_contract.exclude_from_fuzzing = excluded.to_vec();
        }
    }

    // Discover tests based on test mode (createTests)
    let prefix = &config.sol_conf.prefix;
    // Filter functions manually as CompiledContract doesn't have functions_by_name
    let echidna_funcs: Vec<&alloy_json_abi::Function> = main_contract
        .abi
        .functions()
        .filter(|f| f.name.starts_with(prefix))
        .collect();

    let fuzzable_funcs = main_contract.fuzzable_functions(config.sol_conf.mutable_only);

    info!(
        "Found {} tests with prefix '{}'",
        echidna_funcs.len(),
        prefix
    );

    // Show smart-filtered count if slither info is available
    // In assertion mode, we ONLY want to fuzz/test functions that have assertions
    // or can affect state (non-view/pure functions)
    let assert_functions: std::collections::HashSet<String> = slither_info
        .as_ref()
        .map(|info| {
            info.assert_functions(&main_contract.name)
                .into_iter()
                .collect()
        })
        .unwrap_or_default();

    // Use smart filtering if we have assertion info, otherwise use all fuzzable
    let fuzzable_sigs: Vec<(String, Vec<String>)> = if !assert_functions.is_empty() {
        let smart_fuzzable =
            main_contract.fuzzable_functions_smart(config.sol_conf.mutable_only, &assert_functions);
        info!(
            "Found {} fuzzable functions (smart filtered from {} total, {} view/pure with assertions)",
            smart_fuzzable.len(),
            fuzzable_funcs.len(),
            assert_functions.len()
        );
        smart_fuzzable
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    // Use resolve() to get full type like "(uint128,uint128,uint128)" for tuples
                    // instead of just "tuple" from p.ty
                    f.inputs
                        .iter()
                        .filter_map(|p| {
                            use alloy_dyn_abi::Specifier;
                            p.resolve().ok().map(|t| t.sol_type_name().to_string())
                        })
                        .collect(),
                )
            })
            .collect()
    } else {
        info!("Found {} fuzzable functions", fuzzable_funcs.len());
        fuzzable_funcs
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    // Use resolve() to get full type like "(uint128,uint128,uint128)" for tuples
                    // instead of just "tuple" from p.ty
                    f.inputs
                        .iter()
                        .filter_map(|p| {
                            use alloy_dyn_abi::Specifier;
                            p.resolve().ok().map(|t| t.sol_type_name().to_string())
                        })
                        .collect(),
                )
            })
            .collect()
    };

    // Create environment
    let mut env = Env::new(config, project.contracts.clone());
    env.main_contract = Some(main_contract.clone());
    env.slither_info = slither_info;

    // Populate view_pure_functions for shrinking optimization
    // These functions don't modify state, so they can be replaced with NoCall during shrinking
    use alloy_json_abi::StateMutability;
    for func in main_contract.abi.functions() {
        if matches!(
            func.state_mutability,
            StateMutability::View | StateMutability::Pure
        ) {
            env.world.view_pure_functions.insert(func.name.clone());
        }
        // Track payable functions for value generation
        if matches!(func.state_mutability, StateMutability::Payable) {
            let selector = func.selector();
            info!(
                "Payable function detected: {} (selector: 0x{})",
                func.name,
                hex::encode(selector.as_slice())
            );
            env.world.payable_sigs.push(selector);
        }
    }
    if !env.world.view_pure_functions.is_empty() {
        info!(
            "Found {} view/pure functions (will be removed during shrinking)",
            env.world.view_pure_functions.len()
        );
    }
    if !env.world.payable_sigs.is_empty() {
        info!(
            "Found {} payable functions (will receive non-zero msg.value)",
            env.world.payable_sigs.len()
        );
    } else {
        info!("No payable functions found - all transactions will have value=0");
    }

    // NOTE: Tests will be created AFTER deployment so they use the actual deployed address

    // Initialize EVM - use fork mode if RPC URL is provided
    let mut vm = if let Some(ref rpc_url) = env.cfg.rpc_url {
        info!(
            "Initializing fork mode from RPC: {} at block {:?}",
            rpc_url, env.cfg.rpc_block
        );
        match EvmState::new_fork(rpc_url, env.cfg.rpc_block, evm::fork::ForkOptions::default()) {
            Ok(fork_vm) => {
                info!(
                    "Fork initialized: chain_id={:?}, rpc_calls={}",
                    fork_vm.chain_id(),
                    fork_vm.db.rpc_call_count()
                );
                fork_vm
            }
            Err(e) => {
                error!("Failed to initialize fork: {}", e);
                error!("Falling back to empty database (external calls will fail!)");
                EvmState::new()
            }
        }
    } else {
        EvmState::new()
    };

    // Set coverage mode (branch mode is faster but less granular)
    vm.set_coverage_mode(evm::coverage::CoverageMode::from_str(
        &env.cfg.campaign_conf.coverage_mode,
    ));

    // Fund deployer and senders with max balance to avoid funding issues
    let deployer = env.cfg.sol_conf.deployer;
    let _contract_addr = env.cfg.sol_conf.contract_addr;

    // Use U256::MAX / 2 to allow for some accumulation without overflow if receiving
    let funding = U256::MAX / U256::from(2);

    vm.fund_account(deployer, funding);
    for sender in &env.cfg.sol_conf.sender {
        vm.fund_account(*sender, funding);
    }

    // Deploy contract at configured address 
    // Echidna deploys contracts at a specific address from config
    let target_addr = env.cfg.sol_conf.contract_addr;
    info!(
        "Deploying contract at configured address: {:?}",
        target_addr
    );

    // Log constructor and bytecode info
    println!("Bytecode length: {} bytes", main_contract.bytecode.len());
    println!(
        "Deployed bytecode length: {} bytes",
        main_contract.deployed_bytecode.len()
    );

    // Print first 64 bytes of bytecode for debugging
    println!(
        "Bytecode prefix (first 64 bytes): 0x{}",
        hex::encode(&main_contract.bytecode[..64.min(main_contract.bytecode.len())])
    );

    if let Some(constructor) = main_contract.abi.constructor() {
        println!(
            "Constructor has {} inputs: {:?}",
            constructor.inputs.len(),
            constructor
                .inputs
                .iter()
                .map(|p| format!("{} {}", p.ty, p.name))
                .collect::<Vec<_>>()
        );
        if !constructor.inputs.is_empty() {
            return Err(anyhow::anyhow!(
                "Constructor has {} parameters but constructor arguments are not yet supported. \
                Consider using a setUp() function to initialize state instead.",
                constructor.inputs.len()
            ));
        }
    } else {
        println!("Contract has no constructor (or empty constructor)");
    }

    // Deploy with automatic library linking
    // Pass init coverage ref to track constructor coverage (init bytecode, not runtime)
    // Returns traces from constructor execution for dictionary extraction
    let (deployed_addr, constructor_traces) = deploy_with_linking(
        &mut vm,
        &mut project,
        &main_contract.name,
        deployer,
        target_addr,
        &env.coverage_ref_init,
        &env.codehash_map,
    )?;

    info!("Contract deployed at: {:?}", deployed_addr);

    // Extract dictionary values from constructor traces
    // This captures struct values passed to external calls and event parameters
    // during constructor execution (e.g., createMarket(MarketParams{...}))
    let constructor_extracted = campaign::execution::extract_values_from_traces(
        &constructor_traces,
        &env.event_map,
        &env.function_map,
    );
    info!(
        "Constructor dictionary extraction: {} uint values, {} addresses, {} signed values, {} tuples",
        constructor_extracted.uint_values.len(),
        constructor_extracted.addresses.len(),
        constructor_extracted.int_values.len(),
        constructor_extracted.tuples.len()
    );

    // Seed env with constructor-extracted values
    env.setup_dict_values = constructor_extracted.uint_values;
    env.setup_dict_addresses = constructor_extracted.addresses;
    env.setup_dict_signed = constructor_extracted.int_values;
    env.setup_dict_tuples = constructor_extracted.tuples;

    // Track deployed addresses for trace decoding (main contract + libraries)
    let mut deployed_addresses: Vec<(alloy_primitives::Address, String)> =
        vec![(deployed_addr, main_contract.name.clone())];
    // Add library addresses
    deployed_addresses.extend(project.get_deployed_library_addresses());

    // Run setUp if present and track any contracts created during setUp
    // (In some projects, setUp is separate from constructor; in others like Echidna
    // the setUp logic runs in the constructor, which we already handled above)
    if main_contract.has_setup() {
        info!("Running setUp()...");
        let setup_tx = evm::types::Tx::call("setUp", vec![], deployer, deployed_addr, (0, 0));

        // Run setUp with tracing to capture created contracts
        match vm.exec_tx_with_revm_tracing(&setup_tx) {
            Ok((_result, traces, _storage_changes, _storage_reads, _output, _logs, pcs)) => {
                // Merge setUp coverage into init coverage map (captures constructor coverage)
                // PCs from setUp include both init code (CREATE/CREATE2) and runtime calls
                // The codehash-based lookup will correctly attribute coverage
                if !pcs.is_empty() {
                    let mut init_cov = env.coverage_ref_init.write();
                    for (codehash, pc) in &pcs {
                        let contract_cov = init_cov.entry(*codehash).or_default();
                        let entry = contract_cov.entry(*pc).or_insert((0, 0));
                        entry.0 |= 1; // Mark as covered at depth 0
                        entry.1 |= 1; // Mark as successful execution
                    }
                    info!("setUp coverage: {} PCs tracked", pcs.len());
                }

                // Extract vm.label() calls from setUp
                let extracted_labels = evm::tracing::extract_labels_from_traces(&traces);
                for (addr, label) in extracted_labels {
                    vm.labels.insert(addr, label.clone());
                    // Also add to deployed_addresses if not already there
                    if !deployed_addresses.iter().any(|(a, _)| *a == addr) {
                        deployed_addresses.push((addr, label));
                    }
                }

                // Extract contracts created during setUp
                let created_addrs = evm::tracing::extract_created_contracts(&traces);
                for (idx, addr) in created_addrs.iter().enumerate() {
                    // Try to identify contract by matching codehash
                    let label = if let Some(account) = vm.db.get_cached_account(addr) {
                        let codehash = alloy_primitives::keccak256(
                            &account
                                .info
                                .code
                                .clone()
                                .unwrap_or_default()
                                .original_bytes(),
                        );
                        env.contracts
                            .iter()
                            .find(|c| alloy_primitives::keccak256(&c.deployed_bytecode) == codehash)
                            .map(|c| c.name.clone())
                            .unwrap_or_else(|| format!("Contract_{}", idx))
                    } else {
                        format!("Contract_{}", idx)
                    };

                    info!("  setUp deployed: {} at {:?}", label, addr);
                    deployed_addresses.push((*addr, label));
                }

                // Extract dictionary values from setUp traces at ALL depths
                // This captures struct values passed to external calls and event parameters
                // Merge with constructor-extracted values (don't overwrite)
                let extracted = campaign::execution::extract_values_from_traces(
                    &traces,
                    &env.event_map,
                    &env.function_map,
                );
                info!(
                    "setUp dictionary extraction: {} uint values, {} addresses, {} signed values, {} tuples",
                    extracted.uint_values.len(),
                    extracted.addresses.len(),
                    extracted.int_values.len(),
                    extracted.tuples.len()
                );
                env.setup_dict_values.extend(extracted.uint_values);
                env.setup_dict_addresses.extend(extracted.addresses);
                env.setup_dict_signed.extend(extracted.int_values);
                env.setup_dict_tuples.extend(extracted.tuples);
            }
            Err(e) => {
                warn!(
                    "setUp with tracing failed, falling back to normal exec: {}",
                    e
                );
                vm.exec_tx(&setup_tx)?;
            }
        }
    }

    // Build TraceDecoder for address -> contract name resolution (same as campaign)
    // This uses multiple hash methods: CBOR, selector hash, partial codehash
    let mut trace_decoder = evm::tracing::TraceDecoder::new();
    for contract in &env.contracts {
        trace_decoder.add_contract_by_codehash(contract);
    }

    // Add dictionary addresses to deployed_addresses for LLM context
    // These come from constructor/setUp traces and include deployed contracts, actors, etc.
    for addr in &env.setup_dict_addresses {
        if !deployed_addresses.iter().any(|(a, _)| a == addr) {
            // Try to identify contract by:
            // 1. VM label (set by vm.label() in tests)
            // 2. Bytecode hash lookup via TraceDecoder (same as campaign)
            // 3. Fall back to hex address
            let label = vm.labels.get(addr).cloned().unwrap_or_else(|| {
                // Use TraceDecoder's resolution logic with the VM's database
                // This uses CBOR hash, selector hash, and partial codehash (same as campaign)
                trace_decoder.resolve_address_with_state(addr, &mut vm.db)
            });
            deployed_addresses.push((*addr, label));
        }
    }

    info!(
        "Known addresses for LLM: {} total",
        deployed_addresses.len()
    );
    for (addr, label) in &deployed_addresses {
        tracing::debug!("  {} = {:?}", label, addr);
    }

    // Now create tests with the ACTUAL deployed address
    let tests = campaign::testing::create_tests(
        &env.cfg.sol_conf.test_mode,
        deployed_addr, // Use actual deployed address
        &echidna_funcs,
        &fuzzable_sigs,
    );

    info!(
        "Created {} tests for mode '{}'",
        tests.len(),
        env.cfg.sol_conf.test_mode
    );
    for test in tests {
        info!("  - {}", test.test_type.name());
        env.add_test(test);
    }

    // Handle replay mode: just replay the sequence and show traces, then exit
    if let Some(replay_file) = &args.replay {
        return replay_sequence(
            replay_file,
            &mut vm,
            &main_contract.name,
            &env.contracts,
            &deployed_addresses,
        );
    }

    // Handle convert-only mode: export recon corpus to Echidna format and exit
    if args.convert {
        let export_dir = env.cfg.campaign_conf.export_dir.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "--convert requires --recon-corpus-dir to specify the recon corpus location"
            )
        })?;
        let corpus_dir = env
            .cfg
            .campaign_conf
            .corpus_dir
            .as_ref()
            .map(|p| p.as_path())
            .unwrap_or(std::path::Path::new("echidna"));
        let count = campaign::export::export_corpus_to_echidna(corpus_dir, export_dir)?;
        println!(
            "Exported {} corpus files to {}",
            count,
            export_dir.display()
        );
        return Ok(());
    }

    // Handle shrink-only mode: load reproducers, match to tests, shrink
    if args.shrink {
        return run_shrink_mode(&mut env, &mut vm, &main_contract, &deployed_addresses);
    }

    // Set up stop flags for graceful shutdown
    // stop_flag: First Ctrl+C, triggers graceful stop + shrinking
    // force_stop: Second Ctrl+C, immediate stop (skip/abort shrinking)
    let stop_flag = Arc::new(AtomicBool::new(false));
    let force_stop = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();
    let force_stop_clone = force_stop.clone();

    ctrlc::set_handler(move || {
        if stop_flag_clone.load(Ordering::Relaxed) {
            // Second Ctrl+C - force immediate stop
            eprintln!("\nReceived second Ctrl+C, stopping immediately...");
            force_stop_clone.store(true, Ordering::Relaxed);
        } else {
            // First Ctrl+C - graceful stop with shrinking
            eprintln!(
                "\nReceived Ctrl+C, shrinking tests... (press Ctrl+C again to stop immediately)"
            );
            stop_flag_clone.store(true, Ordering::Relaxed);
        }
    })?;

    // Run campaign
    info!("Starting fuzzing campaign...");

    // Load corpus from disk
    let initial_corpus = load_corpus(&env).unwrap_or_else(|e| {
        tracing::warn!("Failed to load corpus: {}", e);
        Vec::new()
    });

    // Save initial VM state for trace generation at the end
    let initial_vm = vm.clone();

    // Spawn web UI server if --web is set
    let web_mode = args.web.is_some();
    if web_mode {
        // Resolve the frontend URL:
        // --web <url>  →  use that URL directly
        // --web        →  FUZZER_WEB_URL env var, or production default
        let web_url_arg = args.web.as_deref().unwrap_or("");
        let frontend_url = if !web_url_arg.is_empty() {
            web_url_arg.to_string()
        } else {
            std::env::var("FUZZER_WEB_URL")
                .unwrap_or_else(|_| DEFAULT_WEB_UI_URL.to_string())
        };

        let ((), web_state) = spawn_web_server(
            &env,
            deployed_addresses.clone(),
            args.web_port,
            Some(stop_flag.clone()),
            &frontend_url,
            !args.no_open,
        )?;
        // Store web_state in env so workers can record statistics
        env.web_state = Some(web_state.clone());

        // Set initial VM state for replay functionality
        web_state.set_initial_vm(initial_vm.clone());
    }

    let stop_flag_check = stop_flag.clone();

    // Set campaign state to Running just before starting (starts the timer)
    if let Some(ref web_state) = env.web_state {
        web_state.set_campaign_state(recon_web::CampaignState::Running);
    }

    // Run the campaign
    run_campaign(
        &mut env,
        vm.clone(),
        initial_corpus,
        stop_flag.clone(),
        force_stop.clone(),
    )?;

    // Update campaign state if in web mode
    if let Some(ref web_state) = env.web_state {
        if stop_flag_check.load(Ordering::Relaxed) {
            web_state.set_campaign_state(recon_web::CampaignState::Finished);
        } else {
            web_state.set_campaign_state(recon_web::CampaignState::Finished);
        }
    }

    // Export corpus to Echidna format if requested
    if let Some(ref export_dir) = env.cfg.campaign_conf.export_dir {
        let corpus_dir = env
            .cfg
            .campaign_conf
            .corpus_dir
            .as_ref()
            .map(|p| p.as_path())
            .unwrap_or(std::path::Path::new("echidna"));
        match campaign::export::export_corpus_to_echidna(corpus_dir, export_dir) {
            Ok(count) => println!(
                "Exported {} corpus files to {}",
                count,
                export_dir.display()
            ),
            Err(e) => warn!("Failed to export corpus: {}", e),
        }
    }

    if stop_flag_check.load(Ordering::Relaxed) {
        println!("Killed (thread killed). Stopping");
    } else {
        println!("Test limit reached. Stopping.");
    }

    // Report results (Echidna-compatible format)
    println!();
    let tests = env.get_tests();
    let mut any_failed = false;

    let contract_name = main_contract.name.as_str();

    for test in &tests {
        let test_name = test.test_type.name();
        let is_optimization = matches!(
            test.test_type,
            campaign::testing::TestType::OptimizationTest { .. }
        );

        match &test.state {
            campaign::testing::TestState::Passed | campaign::testing::TestState::Open => {
                if is_optimization {
                    // For optimization tests, show max value like Echidna
                    if let campaign::testing::TestValue::IntValue(v) = &test.value {
                        println!("{}(): max value: {}", test_name, v);
                        if !test.reproducer.is_empty() {
                            print_call_sequence(&test.reproducer, contract_name);
                        }
                    } else {
                        println!("{}(): passing", test_name);
                    }
                } else {
                    println!("{}(): passing", test_name);
                }
            }
            campaign::testing::TestState::Solved => {
                if is_optimization {
                    if let campaign::testing::TestValue::IntValue(v) = &test.value {
                        println!("{}(): max value: {}", test_name, v);
                    } else {
                        any_failed = true;
                        println!("{}(): failed!💥", test_name);
                    }
                } else {
                    any_failed = true;
                    println!("{}(): failed!💥", test_name);
                }
                print_call_sequence(&test.reproducer, contract_name);

                // Print detailed traces for the falsified sequence
                if !is_optimization && !test.reproducer.is_empty() {
                    campaign::output::print_traces(
                        &mut initial_vm.clone(),
                        &test.reproducer,
                        contract_name,
                        &env.contracts,
                        &deployed_addresses,
                        Some(&main_contract),
                    );
                }
            }

            campaign::testing::TestState::Large(n) => {
                let shrink_limit = env.cfg.campaign_conf.shrink_limit;
                if is_optimization {
                    if let campaign::testing::TestValue::IntValue(v) = &test.value {
                        println!(
                            "{}(): max value: {} (shrinking {}/{})",
                            test_name, v, n, shrink_limit
                        );
                    } else {
                        any_failed = true;
                        println!("{}(): failed!💥", test_name);
                        println!("  Call sequence, shrinking {}/{}:", n, shrink_limit);
                    }
                } else {
                    any_failed = true;
                    println!("{}(): failed!💥", test_name);
                    println!("  Call sequence, shrinking {}/{}:", n, shrink_limit);
                }
                print_call_sequence(&test.reproducer, contract_name);

                // Print detailed traces for the falsified sequence (even while shrinking)
                if !is_optimization && !test.reproducer.is_empty() {
                    campaign::output::print_traces(
                        &mut initial_vm.clone(),
                        &test.reproducer,
                        contract_name,
                        &env.contracts,
                        &deployed_addresses,
                        Some(&main_contract),
                    );
                }
            }
            campaign::testing::TestState::Failed(e) => {
                println!("{}(): could not evaluate ☣", test_name);
                println!("  {}", e);
            }
        }
    }

    // Print coverage stats
    {
        let init_cov = env.coverage_ref_init.read();
        let runtime_cov = env.coverage_ref_runtime.read();
        let (points, codehashes) = evm::coverage::coverage_stats(&init_cov, &runtime_cov);
        println!();
        println!("Unique instructions: {}", points);

        println!("Unique codehashes: {}", codehashes);

        // Generate coverage reports (LCOV + HTML) - default to "echidna" directory
        let corpus_dir = env
            .cfg
            .campaign_conf
            .corpus_dir
            .as_ref()
            .map(|p| p.as_path())
            .unwrap_or(std::path::Path::new("echidna"));
        match generate_coverage_reports(
            &args.project,
            &init_cov,
            &runtime_cov,
            &env.contracts,
            corpus_dir,
        ) {
            Ok((lcov_path, html_path)) => {
                info!("Saved LCOV coverage report to {:?}", lcov_path);
                println!("Coverage report: {}", html_path.display());
            }
            Err(e) => {
                tracing::warn!("Failed to generate coverage reports: {}", e);
            }
        }
    }

    // Save fork cache if in fork mode (persists RPC data for future runs)
    if initial_vm.is_fork() {
        match initial_vm.save_fork_cache() {
            Ok(()) => {
                info!("Saved fork cache to disk for future runs");
            }
            Err(e) => {
                tracing::warn!("Failed to save fork cache: {}", e);
            }
        }
    }

    // Print corpus size
    {
        let corpus = env.corpus_ref.read();
        println!("Corpus size: {}", corpus.len());
    }

    // Print seed (will always be Some after campaign runs, since we generate one if not provided)
    let seed = env
        .cfg
        .campaign_conf
        .seed
        .expect("Seed should be set after campaign");
    println!("Seed: {}", seed);

    println!();

    // If in web mode, keep running so user can investigate results
    if web_mode {
        info!(
            "Campaign finished. Web UI is still running for investigation. Press Ctrl+C to exit."
        );

        // Keep the web server alive until user exits
        loop {
            // Check if user wants to exit
            if force_stop.load(Ordering::Relaxed) {
                info!("Received exit signal, shutting down...");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    // Exit with appropriate code
    if any_failed {
        std::process::exit(1);
    }

    Ok(())
}

/// Replay a corpus/reproducer file and show traces
/// This allows debugging specific sequences by running:
///   recon-fuzzer . --contract MyContract --replay echidna/reproducers/foo.txt
fn replay_sequence(
    replay_file: &PathBuf,
    vm: &mut EvmState,
    contract_name: &str,
    contracts: &[evm::foundry::CompiledContract],
    deployed_addresses: &[(Address, String)],
) -> Result<()> {
    info!("Replay mode: loading sequence from {:?}", replay_file);

    // Read the file
    let content = std::fs::read_to_string(replay_file)
        .with_context(|| format!("Failed to read replay file: {:?}", replay_file))?;

    // Parse as JSON array of transactions
    let txs: Vec<evm::types::Tx> = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse replay file as JSON: {:?}", replay_file))?;

    if txs.is_empty() {
        println!("Replay file contains no transactions");
        return Ok(());
    }

    println!(
        "Replaying {} transactions from {:?}",
        txs.len(),
        replay_file
    );
    println!();

    // Print the call sequence first
    println!("Call sequence:");
    for (i, tx) in txs.iter().enumerate() {
        println!(
            "  [{}] {}",
            i,
            campaign::output::format_tx(tx, contract_name)
        );
    }
    println!();

    // Now replay with traces
    // Note: reentrancy call context is not available in standalone replay mode
    // Use fuzzing mode to see reentrancy calls in traces
    println!("Execution traces:");
    campaign::output::print_traces(vm, &txs, contract_name, contracts, deployed_addresses, None);

    Ok(())
}

/// Shrink-only mode: load existing reproducers, match to tests, and shrink them
fn run_shrink_mode(
    env: &mut Env,
    vm: &mut EvmState,
    main_contract: &evm::foundry::CompiledContract,
    deployed_addresses: &[(Address, String)],
) -> Result<()> {
    use campaign::testing::check_etest;
    use std::collections::HashMap;

    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("echidna"));

    let target_address = env.cfg.sol_conf.contract_addr;

    // Load reproducers from disk
    let reproducers =
        campaign::corpus::load_reproducers_for_shrinking(&corpus_dir, target_address)?;

    if reproducers.is_empty() {
        println!("No reproducers found. Nothing to shrink.");
        return Ok(());
    }

    println!(
        "Matching {} reproducers to {} tests...",
        reproducers.len(),
        env.test_refs.len()
    );

    // Collect the original test templates before clearing
    let original_tests: Vec<campaign::testing::EchidnaTest> = env.get_tests();
    env.test_refs.clear();

    // Match reproducers to tests, keeping only the shortest reproducer per test
    // This deduplicates when multiple reproducers falsify the same test
    let mut best_per_test: HashMap<
        String,
        (
            campaign::testing::EchidnaTest,
            Vec<evm::types::Tx>,
            campaign::testing::TestValue,
        ),
    > = HashMap::new();

    for (repro_idx, repro_txs) in reproducers.iter().enumerate() {
        // Execute the sequence on a fresh VM clone
        let mut vm_clone = vm.clone();
        let mut exec_ok = true;
        for tx in repro_txs {
            if let Err(e) = vm_clone.exec_tx(tx) {
                tracing::warn!("Failed to execute tx in reproducer {}: {}", repro_idx, e);
                exec_ok = false;
                break;
            }
        }
        if !exec_ok {
            continue;
        }

        // Check each test to see which one this reproducer falsifies
        let sender = repro_txs.last().map(|t| t.src).unwrap_or(Address::ZERO);
        for test_template in &original_tests {
            let (val, _res) = match check_etest(&mut vm_clone.clone(), test_template, sender) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let is_falsified = match &val {
                campaign::testing::TestValue::BoolValue(false) => true,
                campaign::testing::TestValue::IntValue(new) => {
                    matches!(&test_template.value, campaign::testing::TestValue::IntValue(old) if new >= old)
                }
                _ => false,
            };

            if is_falsified {
                let test_name = test_template.test_type.name().to_string();
                // Keep the shortest reproducer per test
                let dominated = match best_per_test.get(&test_name) {
                    Some((_, existing_txs, _)) => repro_txs.len() < existing_txs.len(),
                    None => true,
                };
                if dominated {
                    if best_per_test.contains_key(&test_name) {
                        println!(
                            "  Reproducer {} ({} txs) -> {} (shorter than previous, replacing)",
                            repro_idx,
                            repro_txs.len(),
                            test_name
                        );
                    } else {
                        println!(
                            "  Matched reproducer {} ({} txs) -> {}",
                            repro_idx,
                            repro_txs.len(),
                            test_name
                        );
                    }
                    best_per_test
                        .insert(test_name, (test_template.clone(), repro_txs.clone(), val));
                }
                break; // Only match to first falsified test
            }
        }
    }

    if best_per_test.is_empty() {
        println!("No reproducers matched any tests. Nothing to shrink.");
        return Ok(());
    }

    // Create deduplicated test entries with round-robin worker assignment
    let num_workers = env.cfg.campaign_conf.workers as usize;
    let mut test_names: Vec<String> = best_per_test.keys().cloned().collect();
    test_names.sort(); // deterministic ordering

    for (idx, test_name) in test_names.iter().enumerate() {
        let (template, repro_txs, val) = best_per_test.remove(test_name).unwrap();
        let mut test = template;
        test.state = campaign::testing::TestState::Large(0);
        test.reproducer = repro_txs;
        test.worker_id = Some(idx % num_workers);
        test.value = val;
        println!(
            "  {} ({} txs) -> worker {}",
            test_name,
            test.reproducer.len(),
            idx % num_workers
        );
        env.add_test(test);
    }

    println!(
        "\n{} unique tests to shrink across {} workers. Starting shrink campaign...\n",
        test_names.len(),
        num_workers
    );

    // Set up stop flags
    let force_stop = Arc::new(AtomicBool::new(false));
    let force_stop_clone = force_stop.clone();

    ctrlc::set_handler(move || {
        eprintln!("\nReceived Ctrl+C, stopping shrinking...");
        force_stop_clone.store(true, Ordering::Relaxed);
    })?;

    // Save initial VM for traces at the end
    let initial_vm = vm.clone();

    // Run the shrink campaign (workers save intermediate results via save_shrunk_reproducer_worker)
    campaign::campaign::run_shrink_campaign(env, vm.clone(), force_stop)?;

    // After all workers finish: collect results, pick the best per test, save final reproducers
    println!();
    let tests = env.get_tests();
    let contract_name = main_contract.name.as_str();

    // Group finished tests by name and pick the best (shortest reproducer) per test
    let mut best_results: HashMap<String, campaign::testing::EchidnaTest> = HashMap::new();
    for test in &tests {
        let name = test.test_type.name().to_string();
        let is_better = match best_results.get(&name) {
            Some(existing) => test.reproducer.len() < existing.reproducer.len(),
            None => true,
        };
        if is_better {
            best_results.insert(name, test.clone());
        }
    }

    let mut any_failed = false;
    let mut sorted_names: Vec<String> = best_results.keys().cloned().collect();
    sorted_names.sort();

    for name in &sorted_names {
        let test = &best_results[name];
        match &test.state {
            campaign::testing::TestState::Solved | campaign::testing::TestState::Large(_) => {
                any_failed = true;
                let state_msg = match &test.state {
                    campaign::testing::TestState::Solved => "shrunk!💥".to_string(),
                    campaign::testing::TestState::Large(n) => format!(
                        "shrinking incomplete ({}/{})",
                        n, env.cfg.campaign_conf.shrink_limit
                    ),
                    _ => unreachable!(),
                };
                println!("{}(): {}", name, state_msg);
                print_call_sequence(&test.reproducer, contract_name);

                // Save the best reproducer to disk
                if !test.reproducer.is_empty() {
                    match campaign::output::save_shrunk_reproducer(env, &test.reproducer) {
                        Ok(()) => {}
                        Err(e) => {
                            tracing::error!("Failed to save final reproducer for {}: {}", name, e)
                        }
                    }
                }

                // Print traces for completed shrinks
                if matches!(test.state, campaign::testing::TestState::Solved)
                    && !test.reproducer.is_empty()
                {
                    campaign::output::print_traces(
                        &mut initial_vm.clone(),
                        &test.reproducer,
                        contract_name,
                        &env.contracts,
                        deployed_addresses,
                        Some(main_contract),
                    );
                }
            }
            _ => {
                println!(
                    "{}(): {}",
                    name,
                    match &test.state {
                        campaign::testing::TestState::Passed => "passing",
                        campaign::testing::TestState::Open => "open",
                        _ => "unknown",
                    }
                );
            }
        }
    }

    // Print seed
    if let Some(seed) = env.cfg.campaign_conf.seed {
        println!("\nSeed: {}", seed);
    }

    if any_failed {
        std::process::exit(1);
    }

    Ok(())
}

/// Pretty-print a call sequence (Echidna format)
fn print_call_sequence(txs: &[evm::types::Tx], contract_name: &str) {
    if txs.is_empty() {
        println!("  (no transactions)");
        return;
    }

    println!("  Call sequence:");
    for tx in txs {
        println!("    {}", campaign::output::format_tx(tx, contract_name));
    }
}

/// Generate LCOV and HTML coverage reports
fn generate_coverage_reports(
    project_path: &std::path::Path,
    init_coverage: &evm::exec::CoverageMap,
    runtime_coverage: &evm::exec::CoverageMap,
    contracts: &[evm::foundry::CompiledContract],
    corpus_dir: &std::path::Path,
) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
    use evm::coverage::{
        build_codehash_to_source_info, build_init_codehash_to_source_info,
        generate_source_coverage_multi, load_source_info, save_html_report, save_lcov_report,
    };

    // Load source file information
    let (source_files, _) = load_source_info(project_path)?;

    // Build codehash -> source info maps for runtime and init code
    // Runtime uses deployed bytecode source maps, init uses constructor source maps
    let runtime_source_info = build_codehash_to_source_info(contracts);
    let init_source_info = build_init_codehash_to_source_info(contracts);

    // Generate source-level coverage separately for init and runtime
    // Init code has different source maps than runtime code
    let mut source_coverage =
        generate_source_coverage_multi(runtime_coverage, &runtime_source_info, &source_files);

    // Generate init code coverage and merge
    let init_source_coverage =
        generate_source_coverage_multi(init_coverage, &init_source_info, &source_files);

    // Merge init coverage into runtime coverage
    for (path, init_file_cov) in init_source_coverage.files {
        let file_cov = source_coverage.files.entry(path).or_default();
        for (line, hits) in init_file_cov.line_hits {
            *file_cov.line_hits.entry(line).or_insert(0) += hits;
        }
    }

    // Filter to only show relevant sources (src/ + files with hits)
    source_coverage.filter_relevant_sources(project_path);

    // Save LCOV report
    let lcov_path = save_lcov_report(&source_coverage, project_path, corpus_dir)?;

    // Save HTML report (Echidna-style with hit counts)
    let html_path = save_html_report(&source_coverage, project_path, corpus_dir, &source_files)?;

    Ok((lcov_path, html_path))
}
