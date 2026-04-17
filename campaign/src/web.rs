//! Web UI integration for the campaign crate
//!
//! This module provides the Observable and Commandable trait implementations
//! for exposing fuzzer state to the web UI.

use alloy_primitives::{Address, B256, U256};
use parking_lot::RwLock;
use recon_web::{
    CampaignState, Commandable, ConfigSummary, ContractCoverage, ContractInfo,
    ContractPcMapping, ContractSummary, CorpusEntryPayload, CoverageDelta, CoverageSnapshot,
    InitPayload, LineCoverage, Observable, PcSourceEntry, RevertHotspot,
    SourceFile, SourceFileSummary, SourceLineCoverage, TestInfo, TxPayload, TxRequest,
    WorkerInfo, WorkerSnapshot, WorkerStatus,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::config::Env;
use crate::injection::{JsonTransaction, JsonSequence, SequenceInjector, TypeRegistry};
use crate::testing::{TestState, TestType, TestValue};

/// Wrapper that implements Observable and Commandable for web UI integration
///
/// This struct holds shared references to the campaign state and additional runtime
/// statistics needed for the web UI.
pub struct WebObservableState {
    /// Coverage map for runtime (shared with fuzzer)
    coverage_ref_runtime: Arc<parking_lot::RwLock<evm::exec::CoverageMap>>,

    /// Coverage map for init code (shared with fuzzer)
    coverage_ref_init: Arc<parking_lot::RwLock<evm::exec::CoverageMap>>,

    /// Corpus (shared with fuzzer)
    corpus_ref: Arc<parking_lot::RwLock<Vec<crate::worker_env::CorpusEntry>>>,

    /// Test references (shared with fuzzer)
    test_refs: Vec<Arc<parking_lot::RwLock<crate::testing::EchidnaTest>>>,

    /// Compiled contracts
    contracts: Vec<evm::foundry::CompiledContract>,

    /// Configuration
    config: config::global::EConfig,

    /// Start time of the campaign (None if no campaign running)
    start_time: RwLock<Option<Instant>>,

    /// Elapsed time from previous campaigns (accumulated when campaigns finish)
    accumulated_elapsed_ms: AtomicU64,

    /// Total calls executed (across all workers)
    total_calls: AtomicU64,

    /// Total sequences executed
    total_sequences: AtomicU64,

    /// Total gas consumed
    total_gas: AtomicU64,

    /// Number of workers
    num_workers: usize,

    /// Worker statistics: (calls, sequences, gas, is_interactive, status)
    worker_stats: RwLock<Vec<WorkerStat>>,

    /// Revert hotspot tracking: (codehash, pc) -> count (shared with fuzzer)
    revert_hotspots: Arc<parking_lot::RwLock<std::collections::HashMap<(B256, usize), u32>>>,

    /// Source files (loaded once at initialization)
    source_files: Vec<SourceFile>,

    /// Deployed contract addresses: (address, contract_name)
    deployed_addresses: Vec<(Address, String)>,

    /// Shared injected dictionary values (workers periodically poll and drain)
    injected_dict_values: Arc<RwLock<Vec<U256>>>,

    /// Argument clamps for interactive fuzzing: (function_name, param_idx) -> clamped_value
    arg_clamps: Arc<RwLock<HashMap<(String, usize), String>>>,

    /// Target functions for focused fuzzing (if non-empty, only these are fuzzed)
    target_functions: Arc<RwLock<HashSet<String>>>,

    /// Fuzz transaction templates with wildcards
    fuzz_templates: Arc<RwLock<Vec<crate::transaction::FuzzSequenceTemplate>>>,

    /// Sequence injector for parsing and validating transaction sequences
    sequence_injector: Option<SequenceInjector>,

    /// Corpus seen set for deduplication when injecting sequences
    corpus_seen: Arc<RwLock<HashSet<u64>>>,

    /// Current campaign state
    campaign_state: RwLock<CampaignState>,

    /// Stop flag for graceful campaign stop (shared with campaign runner)
    stop_flag: Option<Arc<std::sync::atomic::AtomicBool>>,

    /// Broadcast sender for sending messages to all connected WebSocket clients
    /// Used for immediate test state change notifications
    broadcast_tx: Option<tokio::sync::broadcast::Sender<recon_web::ServerMessage>>,

    /// Source folder path from forge config (e.g., "src")
    src_folder: String,

    /// Test folder path from forge config (e.g., "test" or "tests")
    test_folder: String,

    /// Initial VM state snapshot for replay (set after deployment)
    initial_vm: RwLock<Option<evm::exec::EvmState>>,

    /// Main contract name for formatting
    #[allow(dead_code)]
    main_contract_name: String,

    /// Shrink limit from config (for displaying progress)
    shrink_limit: usize,

    /// Codehash to source info mapping (includes both runtime and init bytecode for coverage)
    codehash_to_source_info: evm::coverage::CodehashToSourceInfo,

    /// Source files by file ID (for line coverage computation)
    source_files_by_id: HashMap<i32, evm::coverage::SourceFile>,

    /// Project path for coverage filtering
    project_path: std::path::PathBuf,
}

struct WorkerStat {
    calls: u64,
    sequences: u64,
    gas: u64,
    is_interactive: bool,
    status: WorkerStatus,
}

/// Forge configuration (subset of fields we care about)
#[derive(serde::Deserialize, Default)]
struct ForgeConfig {
    #[serde(default = "default_src")]
    src: String,
    #[serde(default = "default_test")]
    test: String,
}

fn default_src() -> String {
    "src".to_string()
}

fn default_test() -> String {
    "test".to_string()
}

/// Load forge config from the current directory
fn load_forge_config() -> ForgeConfig {
    // Try to run forge config --json
    match std::process::Command::new("forge")
        .args(["config", "--json"])
        .output()
    {
        Ok(output) if output.status.success() => {
            match serde_json::from_slice::<ForgeConfig>(&output.stdout) {
                Ok(config) => {
                    tracing::info!("Loaded forge config: src={}, test={}", config.src, config.test);
                    config
                }
                Err(e) => {
                    tracing::warn!("Failed to parse forge config: {}", e);
                    ForgeConfig::default()
                }
            }
        }
        Ok(output) => {
            tracing::warn!(
                "forge config failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            ForgeConfig::default()
        }
        Err(e) => {
            tracing::warn!("Failed to run forge config: {}", e);
            ForgeConfig::default()
        }
    }
}

impl WebObservableState {
    /// Create a new WebObservableState from the shared campaign state
    pub fn new(
        env: &Env,
        num_workers: usize,
        deployed_addresses: Vec<(alloy_primitives::Address, String)>,
    ) -> Self {
        // No interactive worker in basic mode
        Self::new_with_interactive(env, num_workers, num_workers, deployed_addresses)
    }

    /// Create a new WebObservableState with separate fuzzing and interactive workers
    ///
    /// When web mode is enabled:
    /// - `num_fuzzing_workers` workers (0..N-1) are for fuzzing
    /// - Worker N (at index `total_workers - 1`) is the interactive worker for web UI commands
    pub fn new_with_interactive(
        env: &Env,
        num_fuzzing_workers: usize,
        total_workers: usize,
        deployed_addresses: Vec<(alloy_primitives::Address, String)>,
    ) -> Self {
        // Load source files from the project directory
        let source_files = Self::load_source_files();

        // Load forge config to get src/test folder paths
        let forge_config = load_forge_config();

        // Build codehash-to-source-info map for line coverage computation
        // Includes both runtime bytecode and init/constructor bytecode (for CREATE/CREATE2 coverage)
        let mut codehash_to_source_info = evm::coverage::build_codehash_to_source_info(&env.contracts);
        let init_codehash_to_source_info = evm::coverage::build_init_codehash_to_source_info(&env.contracts);
        // Merge init code mappings into the main map (different codehashes, so no conflicts)
        codehash_to_source_info.extend(init_codehash_to_source_info);

        // Load source files by ID for line coverage
        let project_path = std::env::current_dir().unwrap_or_default();
        let source_files_by_id = match evm::coverage::load_source_info(&project_path) {
            Ok((files, _)) => files,
            Err(_) => HashMap::new(),
        };

        // Initialize worker stats
        // Workers 0..num_fuzzing_workers are fuzzing workers
        // Worker num_fuzzing_workers (if total_workers > num_fuzzing_workers) is the interactive worker
        let worker_stats: Vec<WorkerStat> = (0..total_workers)
            .map(|i| WorkerStat {
                calls: 0,
                sequences: 0,
                gas: 0,
                is_interactive: i >= num_fuzzing_workers, // Last worker(s) are interactive
                status: if i >= num_fuzzing_workers {
                    WorkerStatus::Idle // Interactive worker starts idle
                } else {
                    WorkerStatus::Fuzzing
                },
            })
            .collect();

        // Build type registry from deployed contracts for sequence injection
        let abis: Vec<(Address, &alloy_json_abi::JsonAbi)> = deployed_addresses
            .iter()
            .filter_map(|(addr, name)| {
                env.contracts
                    .iter()
                    .find(|c| &c.name == name)
                    .map(|c| (*addr, &c.abi))
            })
            .collect();

        let senders = env.cfg.sol_conf.sender.clone();
        let type_registry = TypeRegistry::from_abis(&abis, senders);
        let sequence_injector = Some(SequenceInjector::new(type_registry));

        // Get main contract name from the first deployed address
        let main_contract_name = deployed_addresses
            .first()
            .map(|(_, name)| name.clone())
            .unwrap_or_else(|| "Contract".to_string());

        Self {
            coverage_ref_runtime: env.coverage_ref_runtime.clone(),
            coverage_ref_init: env.coverage_ref_init.clone(),
            corpus_ref: env.corpus_ref.clone(),
            test_refs: env.test_refs.clone(),
            contracts: env.contracts.clone(),
            config: env.cfg.clone(),
            start_time: RwLock::new(None),
            accumulated_elapsed_ms: AtomicU64::new(0),
            total_calls: AtomicU64::new(0),
            total_sequences: AtomicU64::new(0),
            total_gas: AtomicU64::new(0),
            num_workers: total_workers,
            worker_stats: RwLock::new(worker_stats),
            revert_hotspots: env.revert_hotspots.clone(),
            source_files,
            deployed_addresses,
            injected_dict_values: env.injected_dict_values.clone(),
            arg_clamps: env.arg_clamps.clone(),
            target_functions: env.target_functions.clone(),
            fuzz_templates: env.fuzz_templates.clone(),
            sequence_injector,
            corpus_seen: env.corpus_seen.clone(),
            campaign_state: RwLock::new(CampaignState::Idle),
            stop_flag: None,
            broadcast_tx: None,
            src_folder: forge_config.src,
            test_folder: forge_config.test,
            initial_vm: RwLock::new(None),
            main_contract_name,
            shrink_limit: env.cfg.campaign_conf.shrink_limit,
            codehash_to_source_info,
            source_files_by_id,
            project_path,
        }
    }

    /// Set the stop flag for campaign control
    pub fn set_stop_flag(&mut self, stop_flag: Arc<std::sync::atomic::AtomicBool>) {
        self.stop_flag = Some(stop_flag);
    }

    /// Set the broadcast sender for immediate notifications
    pub fn set_broadcast_sender(&mut self, tx: tokio::sync::broadcast::Sender<recon_web::ServerMessage>) {
        self.broadcast_tx = Some(tx);
    }

    /// Set the initial VM state snapshot for replay
    /// This should be called after contract deployment
    pub fn set_initial_vm(&self, vm: evm::exec::EvmState) {
        *self.initial_vm.write() = Some(vm);
    }

    /// Broadcast a test state change to all connected clients
    pub fn broadcast_test_state_change(&self, test_id: &str, state: &crate::testing::TestState, reproducer: Option<&[evm::types::Tx]>) {
        self.broadcast_test_state_change_with_value(test_id, state, reproducer, None);
    }

    /// Broadcast a test state change with an optional value (for optimization tests)
    pub fn broadcast_test_state_change_with_value(
        &self,
        test_id: &str,
        state: &crate::testing::TestState,
        reproducer: Option<&[evm::types::Tx]>,
        value: Option<&crate::testing::TestValue>,
    ) {
        if let Some(ref tx) = self.broadcast_tx {
            let (failure_sequence, failure_sequence_json) = match reproducer {
                Some(txs) => {
                    let seq: Vec<recon_web::TxPayload> = txs.iter().map(|t| t.into()).collect();
                    let json = serde_json::to_string(txs).unwrap_or_else(|_| "[]".to_string());
                    (Some(seq), Some(json))
                }
                None => (None, None),
            };

            let msg = recon_web::ServerMessage::TestStateChanged(recon_web::TestStatePayload {
                id: test_id.to_string(),
                state: Self::test_state_to_string_with_limit(state, self.shrink_limit),
                value: value.and_then(Self::test_value_to_string),
                failure_sequence,
                failure_sequence_json,
            });

            // Ignore send errors (no receivers is OK)
            let _ = tx.send(msg);
        }
    }


    /// Set the campaign state and manage the elapsed timer
    pub fn set_campaign_state(&self, state: CampaignState) {
        let old_state = *self.campaign_state.read();

        // Handle timer based on state transitions
        match (old_state, state) {
            // Starting a campaign: reset and start the timer
            (CampaignState::Idle | CampaignState::Finished, CampaignState::Running) => {
                // Reset accumulated time for new campaign
                self.accumulated_elapsed_ms.store(0, Ordering::Relaxed);
                // Start the timer
                *self.start_time.write() = Some(Instant::now());
                tracing::info!("Campaign timer started");
            }
            // Stopping/finishing a campaign: stop the timer and accumulate
            (CampaignState::Running, CampaignState::Stopping | CampaignState::Finished) => {
                // Stop the timer and add elapsed time to accumulated
                if let Some(start) = self.start_time.write().take() {
                    let elapsed = start.elapsed().as_millis() as u64;
                    self.accumulated_elapsed_ms.fetch_add(elapsed, Ordering::Relaxed);
                    tracing::info!("Campaign timer stopped, elapsed: {}ms", elapsed);
                }
            }
            // Stopping -> Finished: timer already stopped, nothing to do
            (CampaignState::Stopping, CampaignState::Finished) => {}
            // Other transitions: no timer changes needed
            _ => {}
        }

        *self.campaign_state.write() = state;
    }

    /// Reset the campaign timer (for starting a new campaign)
    pub fn reset_timer(&self) {
        self.accumulated_elapsed_ms.store(0, Ordering::Relaxed);
        *self.start_time.write() = None;
    }

    /// Get the current campaign state
    pub fn campaign_state(&self) -> CampaignState {
        *self.campaign_state.read()
    }

    /// Increment call counter for a worker
    pub fn record_call(&self, worker_id: usize, gas: u64) {
        self.total_calls.fetch_add(1, Ordering::Relaxed);
        self.total_gas.fetch_add(gas, Ordering::Relaxed);

        if let Some(stat) = self.worker_stats.write().get_mut(worker_id) {
            stat.calls += 1;
            stat.gas += gas;
        }
    }

    /// Increment sequence counter for a worker
    pub fn record_sequence(&self, worker_id: usize) {
        self.total_sequences.fetch_add(1, Ordering::Relaxed);

        if let Some(stat) = self.worker_stats.write().get_mut(worker_id) {
            stat.sequences += 1;
        }
    }

    /// Record a revert at a specific location (for hotspot tracking)
    pub fn record_revert(&self, codehash: B256, pc: usize) {
        let mut reverts = self.revert_hotspots.write();
        *reverts.entry((codehash, pc)).or_insert(0) += 1;
    }

    /// Update worker status
    pub fn set_worker_status(&self, worker_id: usize, status: WorkerStatus) {
        if let Some(stat) = self.worker_stats.write().get_mut(worker_id) {
            stat.status = status;
        }
    }

    /// Load source files from the project directory
    fn load_source_files() -> Vec<SourceFile> {
        let project_path = std::env::current_dir().unwrap_or_default();

        // Try to load source info using evm's coverage utilities
        match evm::coverage::load_source_info(&project_path) {
            Ok((source_map, _)) => source_map
                .into_iter()
                .map(|(_file_id, evm_source)| {
                    // Make path relative to project root for consistency with line coverage
                    let path_str = evm_source.path
                        .strip_prefix(&project_path)
                        .unwrap_or(&evm_source.path)
                        .to_string_lossy()
                        .to_string();
                    let language = if evm_source.path
                        .extension()
                        .map(|e| e == "sol")
                        .unwrap_or(false)
                    {
                        "solidity".to_string()
                    } else if evm_source.path
                        .extension()
                        .map(|e| e == "vy")
                        .unwrap_or(false)
                    {
                        "vyper".to_string()
                    } else {
                        "unknown".to_string()
                    };
                    SourceFile {
                        path: path_str,
                        content: evm_source.content,
                        language,
                    }
                })
                .collect(),
            Err(_) => {
                // Source info not available
                vec![]
            }
        }
    }

    /// Convert internal TestState to string (with shrink_limit for progress display)
    fn test_state_to_string_with_limit(state: &TestState, shrink_limit: usize) -> String {
        match state {
            TestState::Open => "open".to_string(),
            TestState::Large(n) => format!("shrinking:{}/{}", n, shrink_limit),
            TestState::Passed => "passed".to_string(),
            TestState::Solved => "solved".to_string(),
            TestState::Failed(msg) => format!("failed:{}", msg),
        }
    }


    /// Convert internal TestType to string
    fn test_type_to_string(test_type: &TestType) -> String {
        match test_type {
            TestType::PropertyTest { .. } => "property".to_string(),
            TestType::AssertionTest { .. } => "assertion".to_string(),
            TestType::OptimizationTest { .. } => "optimization".to_string(),
            TestType::CallTest { .. } => "call".to_string(),
            TestType::Exploration => "exploration".to_string(),
        }
    }

    /// Convert internal TestValue to optional string
    fn test_value_to_string(value: &TestValue) -> Option<String> {
        match value {
            TestValue::BoolValue(b) => Some(b.to_string()),
            TestValue::IntValue(i) => Some(i.to_string()),
            TestValue::NoValue => None,
        }
    }

    /// Get set of file paths that have at least one coverage hit
    fn get_files_with_coverage_hits(&self) -> HashSet<String> {
        let runtime_cov = self.coverage_ref_runtime.read();
        let init_cov = self.coverage_ref_init.read();

        // Generate source coverage to find files with hits
        let mut source_coverage = evm::coverage::generate_source_coverage_multi(
            &runtime_cov,
            &self.codehash_to_source_info,
            &self.source_files_by_id,
        );

        let init_coverage = evm::coverage::generate_source_coverage_multi(
            &init_cov,
            &self.codehash_to_source_info,
            &self.source_files_by_id,
        );

        // Merge init coverage
        for (path, init_file_cov) in init_coverage.files {
            let file_coverage = source_coverage.files
                .entry(path)
                .or_insert_with(evm::coverage::FileCoverage::default);
            for (line, hits) in init_file_cov.line_hits {
                *file_coverage.line_hits.entry(line).or_insert(0) += hits;
            }
        }

        // Collect paths with at least one hit
        source_coverage
            .files
            .iter()
            .filter(|(_, file_cov)| file_cov.line_hits.values().any(|&hits| hits > 0))
            .map(|(path, _)| {
                path.strip_prefix(&self.project_path)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string()
            })
            .collect()
    }

    /// Get set of codehashes that have at least one coverage hit
    fn get_codehashes_with_coverage(&self) -> HashSet<B256> {
        let runtime_cov = self.coverage_ref_runtime.read();
        let init_cov = self.coverage_ref_init.read();

        let mut codehashes = HashSet::new();

        // Collect codehashes from runtime coverage
        for (codehash, pcs) in runtime_cov.iter() {
            if !pcs.is_empty() {
                codehashes.insert(*codehash);
            }
        }

        // Collect codehashes from init coverage
        for (codehash, pcs) in init_cov.iter() {
            if !pcs.is_empty() {
                codehashes.insert(*codehash);
            }
        }

        codehashes
    }

    /// Get contract summaries using pre-computed codehashes (optimized)
    fn get_contract_summaries_cached(&self, codehashes_with_coverage: &HashSet<B256>) -> Vec<ContractSummary> {
        let src_prefix = format!("{}/", self.src_folder);

        self.contracts
            .iter()
            .filter(|contract| {
                // Always include src/ contracts
                if contract.qualified_name.starts_with(&src_prefix) {
                    return true;
                }
                // Include contracts with coverage hits
                let codehash = alloy_primitives::keccak256(&contract.deployed_bytecode);
                codehashes_with_coverage.contains(&codehash)
            })
            .map(|contract| {
                let address = self
                    .deployed_addresses
                    .iter()
                    .find(|(_, name)| name == &contract.name)
                    .map(|(addr, _)| *addr);
                ContractSummary::from_compiled(contract, address)
            })
            .collect()
    }

    /// Get source file summaries using pre-computed files with hits (optimized)
    fn get_source_file_summaries_cached(&self, files_with_hits: &HashSet<String>) -> Vec<SourceFileSummary> {
        self.source_files
            .iter()
            .filter(|f| {
                // Include all src/ files
                if f.path.starts_with("src/") || f.path.starts_with("src\\") {
                    return true;
                }
                // Include files with coverage hits
                files_with_hits.contains(&f.path)
            })
            .map(SourceFileSummary::from_source_file)
            .collect()
    }

    /// Get limited corpus entries (last N entries for performance)
    fn get_corpus_entries_limited(&self, limit: usize) -> Vec<CorpusEntryPayload> {
        let corpus = self.corpus_ref.read();
        let total = corpus.len();
        let skip = total.saturating_sub(limit);

        corpus
            .iter()
            .enumerate()
            .skip(skip)
            .map(|(idx, (priority, txs))| {
                let sequence: Vec<TxPayload> = txs.iter().map(|tx| tx.into()).collect();
                let sequence_json = serde_json::to_string(txs.as_ref())
                    .unwrap_or_else(|_| "[]".to_string());
                CorpusEntryPayload {
                    id: format!("corpus_{}", idx),
                    priority: *priority,
                    sequence,
                    sequence_json,
                    coverage_contribution: 0,
                }
            })
            .collect()
    }

    /// Get PC mappings only for contracts with coverage (optimized)
    fn get_pc_mappings_filtered(&self, codehashes_with_coverage: &HashSet<B256>) -> Vec<ContractPcMapping> {
        self.codehash_to_source_info
            .iter()
            .filter(|(codehash, _)| codehashes_with_coverage.contains(*codehash))
            .filter_map(|(codehash, info)| {
                let pc_to_idx = evm::coverage::build_pc_to_index(&info.deployed_bytecode);
                let source_file = self.source_files_by_id.get(&info.file_id)?;

                let pc_to_source: Vec<PcSourceEntry> = pc_to_idx
                    .iter()
                    .filter_map(|(pc, idx)| {
                        let loc = info.source_map.locations.get(*idx)?;
                        if loc.file_id < 0 || loc.file_id != info.file_id {
                            return None;
                        }
                        let line = source_file.offset_to_line(loc.start as usize);
                        let rel_path = source_file.path
                            .strip_prefix(&self.project_path)
                            .unwrap_or(&source_file.path)
                            .to_string_lossy()
                            .to_string();
                        Some(PcSourceEntry {
                            pc: *pc,
                            file: rel_path,
                            line: line as u32,
                            column: 1,
                            offset: loc.start,
                            length: loc.length,
                        })
                    })
                    .collect();

                if pc_to_source.is_empty() {
                    return None;
                }

                Some(ContractPcMapping {
                    codehash: format!("0x{}", hex::encode(codehash)),
                    pc_to_source,
                })
            })
            .collect()
    }
}

/// Maximum number of corpus entries to send in init payload
const MAX_CORPUS_ENTRIES: usize = 50;

impl Observable for WebObservableState {
    fn get_init_payload(&self) -> InitPayload {
        // === FAST PATH: Minimal lock time, defer expensive computation ===
        // The UI will receive detailed coverage via periodic StateUpdate messages

        // Quick read of coverage data - just extract what we need for basic info
        let (codehashes_with_coverage, coverage) = {
            let runtime_cov = self.coverage_ref_runtime.read();
            let init_cov = self.coverage_ref_init.read();

            // Collect codehashes with coverage (fast iteration)
            let mut codehashes = HashSet::new();
            for (codehash, pcs) in runtime_cov.iter() {
                if !pcs.is_empty() {
                    codehashes.insert(*codehash);
                }
            }
            for (codehash, pcs) in init_cov.iter() {
                if !pcs.is_empty() {
                    codehashes.insert(*codehash);
                }
            }

            // Build coverage snapshot (fast - just keys and counts)
            let runtime: Vec<ContractCoverage> = runtime_cov
                .iter()
                .map(|(codehash, pc_map)| ContractCoverage {
                    codehash: format!("0x{}", hex::encode(codehash)),
                    covered_pcs: pc_map.keys().copied().collect(),
                })
                .collect();
            let init: Vec<ContractCoverage> = init_cov
                .iter()
                .map(|(codehash, pc_map)| ContractCoverage {
                    codehash: format!("0x{}", hex::encode(codehash)),
                    covered_pcs: pc_map.keys().copied().collect(),
                })
                .collect();
            let total_instructions: usize = runtime_cov.values().map(|m| m.len()).sum::<usize>()
                + init_cov.values().map(|m| m.len()).sum::<usize>();
            let total_contracts = runtime_cov.len() + init_cov.len();

            // Locks released here when guards go out of scope
            (codehashes, CoverageSnapshot {
                runtime,
                init,
                total_instructions,
                total_contracts,
            })
        };

        // === REST OF COMPUTATION WITHOUT LOCKS ===
        // For init payload, skip expensive source line coverage computation
        // The UI will receive it via periodic updates (StateUpdate messages)

        // Get files that are in src/ folder (fast - no coverage computation needed)
        let files_with_hits: HashSet<String> = self.source_files
            .iter()
            .filter(|f| f.path.starts_with("src/") || f.path.starts_with("src\\"))
            .map(|f| f.path.clone())
            .collect();

        // Use cached data for filtering
        let contracts = self.get_contract_summaries_cached(&codehashes_with_coverage);
        let total_contracts = contracts.len();
        let source_files = self.get_source_file_summaries_cached(&files_with_hits);
        let corpus = self.get_corpus_entries_limited(MAX_CORPUS_ENTRIES);
        let tests = self.get_test_states();

        let workers: Vec<WorkerInfo> = (0..self.num_workers)
            .map(|i| WorkerInfo {
                id: i,
                is_interactive: i == 0,
            })
            .collect();

        let config = ConfigSummary {
            test_mode: format!("{:?}", self.config.sol_conf.test_mode),
            workers: if self.num_workers > 0 {
                self.num_workers
            } else {
                self.config.campaign_conf.workers as usize
            },
            test_limit: self.config.campaign_conf.test_limit,
            seq_len: self.config.campaign_conf.seq_len,
            coverage_mode: "coverage".to_string(),
            target_contracts: self
                .deployed_addresses
                .iter()
                .map(|(addr, _)| *addr)
                .collect(),
            senders: self.config.sol_conf.sender.clone(),
            src_folder: self.src_folder.clone(),
            test_folder: self.test_folder.clone(),
        };

        // Skip expensive source_line_coverage and pc_mappings in init payload
        // The UI will receive source_line_coverage via periodic StateUpdate messages
        // PC mappings can be requested on-demand if needed
        let source_line_coverage: Vec<SourceLineCoverage> = vec![];
        let pc_mappings: Vec<ContractPcMapping> = vec![];

        InitPayload {
            contracts,
            total_contracts,
            config,
            source_files,
            coverage,
            corpus,
            tests,
            workers,
            campaign_state: *self.campaign_state.read(),
            source_line_coverage,
            pc_mappings,
        }
    }

    fn get_coverage_snapshot(&self) -> CoverageSnapshot {
        let runtime_cov = self.coverage_ref_runtime.read();
        let init_cov = self.coverage_ref_init.read();

        let runtime: Vec<ContractCoverage> = runtime_cov
            .iter()
            .map(|(codehash, pc_map)| ContractCoverage {
                codehash: format!("0x{}", hex::encode(codehash)),
                covered_pcs: pc_map.keys().copied().collect(),
            })
            .collect();

        let init: Vec<ContractCoverage> = init_cov
            .iter()
            .map(|(codehash, pc_map)| ContractCoverage {
                codehash: format!("0x{}", hex::encode(codehash)),
                covered_pcs: pc_map.keys().copied().collect(),
            })
            .collect();

        let total_instructions: usize =
            runtime.iter().map(|c| c.covered_pcs.len()).sum::<usize>()
                + init.iter().map(|c| c.covered_pcs.len()).sum::<usize>();

        let total_contracts = runtime.len() + init.len();

        CoverageSnapshot {
            runtime,
            init,
            total_instructions,
            total_contracts,
        }
    }

    fn get_coverage_delta(&self, since: &CoverageSnapshot) -> CoverageDelta {
        // Build a set of previously covered PCs for quick lookup
        let mut prev_runtime: HashMap<String, std::collections::HashSet<usize>> = HashMap::new();
        for cov in &since.runtime {
            prev_runtime
                .entry(cov.codehash.clone())
                .or_default()
                .extend(cov.covered_pcs.iter().copied());
        }

        let mut prev_init: HashMap<String, std::collections::HashSet<usize>> = HashMap::new();
        for cov in &since.init {
            prev_init
                .entry(cov.codehash.clone())
                .or_default()
                .extend(cov.covered_pcs.iter().copied());
        }

        // Get current coverage and compute delta
        let current = self.get_coverage_snapshot();

        let mut new_runtime = Vec::new();
        let mut new_instructions = 0;

        for cov in &current.runtime {
            let prev_pcs = prev_runtime.get(&cov.codehash);
            let new_pcs: Vec<usize> = cov
                .covered_pcs
                .iter()
                .filter(|pc| {
                    prev_pcs
                        .map(|set| !set.contains(*pc))
                        .unwrap_or(true)
                })
                .copied()
                .collect();

            if !new_pcs.is_empty() {
                new_instructions += new_pcs.len();
                new_runtime.push(ContractCoverage {
                    codehash: cov.codehash.clone(),
                    covered_pcs: new_pcs,
                });
            }
        }

        let mut new_init = Vec::new();
        for cov in &current.init {
            let prev_pcs = prev_init.get(&cov.codehash);
            let new_pcs: Vec<usize> = cov
                .covered_pcs
                .iter()
                .filter(|pc| {
                    prev_pcs
                        .map(|set| !set.contains(*pc))
                        .unwrap_or(true)
                })
                .copied()
                .collect();

            if !new_pcs.is_empty() {
                new_instructions += new_pcs.len();
                new_init.push(ContractCoverage {
                    codehash: cov.codehash.clone(),
                    covered_pcs: new_pcs,
                });
            }
        }

        CoverageDelta {
            new_runtime,
            new_init,
            new_instructions,
        }
    }

    fn get_worker_snapshots(&self) -> Vec<WorkerSnapshot> {
        let stats = self.worker_stats.read();
        stats
            .iter()
            .enumerate()
            .map(|(id, stat)| WorkerSnapshot {
                id,
                calls: stat.calls,
                sequences: stat.sequences,
                gas: stat.gas,
                is_interactive: stat.is_interactive,
                status: stat.status.clone(),
            })
            .collect()
    }

    fn get_corpus_entries(&self) -> Vec<CorpusEntryPayload> {
        let corpus = self.corpus_ref.read();
        corpus
            .iter()
            .enumerate()
            .map(|(idx, (priority, txs))| {
                let sequence: Vec<TxPayload> = txs.iter().map(|tx| tx.into()).collect();
                // Serialize to JSON in the same format as corpus files
                let sequence_json = serde_json::to_string(txs.as_ref())
                    .unwrap_or_else(|_| "[]".to_string());
                CorpusEntryPayload {
                    id: format!("corpus_{}", idx),
                    priority: *priority,
                    sequence,
                    sequence_json,
                    coverage_contribution: 0, // Would need to track this separately
                }
            })
            .collect()
    }

    fn get_corpus_size(&self) -> usize {
        self.corpus_ref.read().len()
    }

    fn get_test_states(&self) -> Vec<TestInfo> {
        let shrink_limit = self.shrink_limit;
        self.test_refs
            .iter()
            .map(|test_ref| {
                let test = test_ref.read();
                // Include sequence if test failed OR if it's an optimization test with a reproducer
                // (optimization tests stay "Open" while improving, but still have reproducers)
                let should_include_sequence = test.state.did_fail()
                    || (matches!(test.test_type, TestType::OptimizationTest { .. }) && !test.reproducer.is_empty());
                let (failure_sequence, failure_sequence_json) = if should_include_sequence {
                    let seq: Vec<TxPayload> = test.reproducer.iter().map(|tx| tx.into()).collect();
                    let json = serde_json::to_string(&test.reproducer)
                        .unwrap_or_else(|_| "[]".to_string());
                    (Some(seq), Some(json))
                } else {
                    (None, None)
                };

                TestInfo {
                    id: test.test_type.name().to_string(),
                    test_type: Self::test_type_to_string(&test.test_type),
                    state: Self::test_state_to_string_with_limit(&test.state, shrink_limit),
                    value: Self::test_value_to_string(&test.value),
                    failure_sequence,
                    failure_sequence_json,
                    worker_id: test.worker_id,
                }
            })
            .collect()
    }

    fn get_revert_hotspots(&self, top_n: usize) -> Vec<RevertHotspot> {
        let reverts = self.revert_hotspots.read();

        // Sort by count and take top N
        let mut hotspots: Vec<_> = reverts.iter().collect();
        hotspots.sort_by(|a, b| b.1.cmp(a.1));

        hotspots
            .into_iter()
            .take(top_n)
            .map(|((codehash, pc), count)| RevertHotspot {
                codehash: format!("0x{}", hex::encode(codehash)),
                pc: *pc,
                count: *count,
                function_name: None, // Would need source map resolution
                source_location: None,
            })
            .collect()
    }

    fn get_stats(&self) -> (u64, u64, u64, u64) {
        let campaign_state = *self.campaign_state.read();

        // Only show elapsed time based on campaign state
        let elapsed_ms = match campaign_state {
            CampaignState::Running | CampaignState::Stopping => {
                // Campaign is active - show accumulated + current elapsed
                let accumulated = self.accumulated_elapsed_ms.load(Ordering::Relaxed);
                let current_elapsed = self.start_time.read()
                    .map(|start| start.elapsed().as_millis() as u64)
                    .unwrap_or(0);
                accumulated + current_elapsed
            }
            CampaignState::Finished => {
                // Campaign finished - show final accumulated time
                self.accumulated_elapsed_ms.load(Ordering::Relaxed)
            }
            CampaignState::Idle => {
                // No campaign running - show 0
                0
            }
        };

        (
            self.total_calls.load(Ordering::Relaxed),
            self.total_sequences.load(Ordering::Relaxed),
            self.total_gas.load(Ordering::Relaxed),
            elapsed_ms,
        )
    }

    fn get_contract_summaries(&self) -> Vec<ContractSummary> {
        // Delegate to cached version with fresh codehashes
        let codehashes = self.get_codehashes_with_coverage();
        self.get_contract_summaries_cached(&codehashes)
    }

    fn get_contract_details(&self, name: &str) -> Option<ContractInfo> {
        self.contracts
            .iter()
            .find(|c| c.name == name)
            .map(|contract| {
                let address = self
                    .deployed_addresses
                    .iter()
                    .find(|(_, n)| n == &contract.name)
                    .map(|(addr, _)| *addr);
                ContractInfo::from_compiled(contract, address)
            })
    }

    fn get_source_file_summaries(&self) -> Vec<SourceFileSummary> {
        // Delegate to cached version with fresh file coverage data
        let files_with_hits = self.get_files_with_coverage_hits();
        self.get_source_file_summaries_cached(&files_with_hits)
    }

    fn get_source_file_content(&self, path: &str) -> Option<SourceFile> {
        self.source_files
            .iter()
            .find(|f| f.path == path)
            .cloned()
    }

    fn get_campaign_state(&self) -> CampaignState {
        *self.campaign_state.read()
    }

    fn get_source_line_coverage(&self) -> Vec<SourceLineCoverage> {
        // Generate line coverage from PC coverage using the source maps
        // codehash_to_source_info contains both runtime and init bytecode mappings
        let runtime_cov = self.coverage_ref_runtime.read();
        let init_cov = self.coverage_ref_init.read();

        // Get runtime coverage (deployed bytecode)
        let mut source_coverage = evm::coverage::generate_source_coverage_multi(
            &runtime_cov,
            &self.codehash_to_source_info,
            &self.source_files_by_id,
        );

        // Get init/constructor coverage (CREATE/CREATE2 calls) using same merged map
        let init_coverage = evm::coverage::generate_source_coverage_multi(
            &init_cov,
            &self.codehash_to_source_info,
            &self.source_files_by_id,
        );

        // Merge init coverage into runtime coverage
        for (path, init_file_cov) in init_coverage.files {
            let file_coverage = source_coverage.files
                .entry(path)
                .or_insert_with(evm::coverage::FileCoverage::default);

            for (line, hits) in init_file_cov.line_hits {
                *file_coverage.line_hits.entry(line).or_insert(0) += hits;
            }
        }

        // Filter to only show relevant sources (src/ + files with hits)
        source_coverage.filter_relevant_sources(&self.project_path);

        // Convert to protocol format
        let project_path = &self.project_path;
        source_coverage
            .files
            .into_iter()
            .map(|(path, file_cov)| {
                // Make path relative to project root
                let rel_path = path
                    .strip_prefix(&project_path)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                SourceLineCoverage {
                    path: rel_path,
                    lines: file_cov
                        .line_hits
                        .into_iter()
                        .map(|(line, hits)| LineCoverage {
                            line: line as u32,
                            hits: hits as u32,
                        })
                        .collect(),
                }
            })
            .collect()
    }

    fn get_pc_mappings(&self) -> Vec<ContractPcMapping> {
        // Delegate to filtered version with fresh codehashes
        let codehashes = self.get_codehashes_with_coverage();
        self.get_pc_mappings_filtered(&codehashes)
    }
}

impl Commandable for WebObservableState {
    fn inject_dictionary(&self, values: Vec<U256>, _broadcast: bool) -> Result<(), String> {
        if values.is_empty() {
            return Ok(());
        }

        // Add values to shared container - workers will poll and drain
        let mut injected = self.injected_dict_values.write();
        let count = values.len();
        injected.extend(values);
        tracing::info!("Injected {} dictionary values for workers to consume", count);

        Ok(())
    }

    fn inject_sequence(&self, sequence: Vec<TxRequest>) -> Result<(), String> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let injector = self
            .sequence_injector
            .as_ref()
            .ok_or("Sequence injector not configured")?;

        // Convert TxRequest to JsonTransaction
        let transactions: Vec<JsonTransaction> = sequence
            .into_iter()
            .map(|req| JsonTransaction {
                function: req.function,
                args: req.args.into_iter().map(|s| serde_json::Value::String(s)).collect(),
                sender: req.sender,
                value: req.value,
                delay: None,
                cheatcode: false,
            })
            .collect();

        let json_seq = JsonSequence {
            transactions,
            reasoning: Some("Injected via web UI".to_string()),
        };

        // Parse the sequence
        let txs = injector
            .parse_json_sequence(&json_seq)
            .map_err(|e| format!("Failed to parse sequence: {}", e))?;

        if txs.is_empty() {
            return Ok(());
        }

        // Compute hash for deduplication
        let mut hasher = DefaultHasher::new();
        for tx in &txs {
            format!("{:?}", tx.call).hash(&mut hasher);
            tx.src.hash(&mut hasher);
            tx.dst.hash(&mut hasher);
        }
        let seq_hash = hasher.finish();

        // Check if already seen
        {
            let seen = self.corpus_seen.read();
            if seen.contains(&seq_hash) {
                tracing::debug!("Sequence already in corpus (deduplicated)");
                return Ok(());
            }
        }

        // Add to seen set
        {
            let mut seen = self.corpus_seen.write();
            seen.insert(seq_hash);
        }

        // Add to corpus with priority (current corpus size as priority)
        let priority = self.corpus_ref.read().len();
        {
            let mut corpus = self.corpus_ref.write();
            corpus.push((priority, Arc::new(txs)));
        }

        tracing::info!("Injected new sequence into corpus");
        Ok(())
    }

    fn clamp_argument(
        &self,
        function: &str,
        param_idx: usize,
        value: &str,
    ) -> Result<(), String> {
        let mut clamps = self.arg_clamps.write();
        clamps.insert((function.to_string(), param_idx), value.to_string());
        tracing::info!(
            "Clamped argument: {}[{}] = {}",
            function,
            param_idx,
            value
        );
        Ok(())
    }

    fn unclamp_argument(&self, function: &str, param_idx: usize) -> Result<(), String> {
        let mut clamps = self.arg_clamps.write();
        if clamps.remove(&(function.to_string(), param_idx)).is_some() {
            tracing::info!("Unclamped argument: {}[{}]", function, param_idx);
            Ok(())
        } else {
            Err(format!(
                "No clamp found for {}[{}]",
                function, param_idx
            ))
        }
    }

    fn clear_clamps(&self) -> Result<(), String> {
        let mut clamps = self.arg_clamps.write();
        let count = clamps.len();
        clamps.clear();
        tracing::info!("Cleared {} argument clamps", count);
        Ok(())
    }

    fn set_target_functions(&self, functions: Vec<String>) -> Result<(), String> {
        let mut targets = self.target_functions.write();
        targets.clear();
        if functions.is_empty() {
            tracing::info!("Cleared target functions - fuzzing all functions");
        } else {
            tracing::info!("Set target functions: {:?}", functions);
            targets.extend(functions);
        }
        Ok(())
    }

    fn inject_fuzz_transactions(&self, template: &str, priority: usize) -> Result<(), String> {
        // Parse the template string
        let tx_templates = crate::transaction::parse_fuzz_template(template)
            .map_err(|e| format!("Failed to parse template: {}", e))?;

        if tx_templates.is_empty() {
            return Err("No valid transactions in template".to_string());
        }

        let template = crate::transaction::FuzzSequenceTemplate {
            transactions: tx_templates,
            priority: priority.max(1), // Ensure at least priority 1
        };

        let mut templates = self.fuzz_templates.write();
        templates.push(template);
        tracing::info!(
            "Added fuzz template with {} transactions and priority {}",
            templates.last().map(|t| t.transactions.len()).unwrap_or(0),
            priority
        );
        Ok(())
    }

    fn clear_fuzz_templates(&self) -> Result<(), String> {
        let mut templates = self.fuzz_templates.write();
        let count = templates.len();
        templates.clear();
        tracing::info!("Cleared {} fuzz templates", count);
        Ok(())
    }

    fn replay_sequence(&self, sequence_json: &str) -> Result<Vec<recon_web::TxTraceResult>, String> {
        use recon_web::{TxTraceResult, CallTraceEntry, EventEntry, StorageChange};

        tracing::debug!("replay_sequence: acquiring initial_vm lock");

        // Get the initial VM state
        let initial_vm = self.initial_vm.read();
        let vm = initial_vm.as_ref()
            .ok_or("Initial VM state not set - replay not available")?;

        tracing::debug!("replay_sequence: cloning VM state");

        // Clone the VM for replay (don't affect the running campaign)
        let mut replay_vm = vm.clone();

        // Release the lock early - we have our own copy now
        drop(initial_vm);

        tracing::debug!("replay_sequence: VM cloned, parsing JSON");

        // Parse the raw JSON directly - same format as corpus files
        let txs: Vec<evm::types::Tx> = serde_json::from_str(sequence_json)
            .map_err(|e| format!("Failed to parse sequence JSON: {}", e))?;

        tracing::debug!("replay_sequence: parsed {} transactions", txs.len());

        if txs.is_empty() {
            return Ok(vec![]);
        }

        // Build trace decoder for address/function resolution
        tracing::debug!("replay_sequence: building trace decoder");
        let _deployed_refs: Vec<(Address, &alloy_json_abi::JsonAbi)> = self.deployed_addresses
            .iter()
            .filter_map(|(addr, name)| {
                self.contracts
                    .iter()
                    .find(|c| &c.name == name)
                    .map(|c| (*addr, &c.abi))
            })
            .collect();

        let mut decoder = crate::output::build_trace_decoder(&self.contracts, &self.deployed_addresses);

        // Add labels from vm state
        for (addr, label) in &replay_vm.labels {
            decoder.labels.insert(*addr, label.clone());
        }

        let mut results = Vec::with_capacity(txs.len());

        tracing::debug!("replay_sequence: starting execution of {} transactions", txs.len());

        for (i, tx) in txs.iter().enumerate() {
            tracing::debug!("replay_sequence: executing tx {}/{}", i + 1, txs.len());
            let tx_payload: recon_web::TxPayload = tx.into();

            // Execute with tracing
            match replay_vm.exec_tx_with_revm_tracing(tx) {
                Ok((result, mut traces, storage_changes, _storage_reads, output_bytes, logs, _pcs)) => {
                    // Extract vm.label() calls from traces
                    let extracted_labels = evm::tracing::extract_labels_from_traces(&traces);
                    for (addr, label) in extracted_labels {
                        decoder.labels.insert(addr, label.clone());
                        replay_vm.labels.insert(addr, label);
                    }

                    // Format traces
                    let trace_output = evm::tracing::format_traces_decoded_with_state(
                        &mut traces, &mut decoder, &mut replay_vm.db, true
                    );

                    // Build call trace entries from trace output (simplified - parse the formatted string)
                    let call_trace: Vec<CallTraceEntry> = trace_output
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .enumerate()
                        .map(|(_depth, line)| {
                            // Simplified parsing - just use the line as-is
                            CallTraceEntry {
                                depth: line.chars().take_while(|c| c.is_whitespace()).count() / 2,
                                call_type: "CALL".to_string(),
                                from: Address::ZERO,
                                to: Address::ZERO,
                                function: Some(line.trim().to_string()),
                                input: String::new(),
                                output: String::new(),
                                gas_used: 0,
                                success: true,
                                revert_reason: None,
                            }
                        })
                        .collect();

                    // Build events
                    let events: Vec<EventEntry> = logs
                        .iter()
                        .take(20) // Limit to avoid huge payloads
                        .map(|log| {
                            let event_str = crate::output::format_log_event(log, &self.contracts);
                            EventEntry {
                                address: log.address,
                                name: Some(event_str),
                                topics: log.topics().iter().map(|t| format!("{:?}", t)).collect(),
                                data: format!("0x{}", hex::encode(&log.data.data)),
                            }
                        })
                        .collect();

                    // Build storage changes
                    let storage_changes_result: Vec<StorageChange> = storage_changes
                        .iter()
                        .take(20) // Limit
                        .map(|(addr, slot, old_val, new_val)| {
                            let contract_name = decoder.labels.get(addr).cloned();
                            StorageChange {
                                address: *addr,
                                contract_name,
                                slot: format!("{:#x}", slot),
                                previous: format!("{:#x}", old_val),
                                current: format!("{:#x}", new_val),
                            }
                        })
                        .collect();

                    // Determine success and result string
                    let (success, result_str) = match result {
                        evm::types::TxResult::Stop => (true, "Stop".to_string()),
                        evm::types::TxResult::ReturnTrue => (true, "Return: true".to_string()),
                        evm::types::TxResult::ReturnFalse => (false, "Return: false".to_string()),
                        evm::types::TxResult::ErrorRevert => {
                            let reason = crate::output::decode_revert_with_abi_public(&output_bytes, &self.contracts)
                                .unwrap_or_else(|| {
                                    if !output_bytes.is_empty() {
                                        format!("0x{}", hex::encode(&output_bytes))
                                    } else {
                                        "Revert".to_string()
                                    }
                                });
                            (false, format!("Revert: {}", reason))
                        }
                        evm::types::TxResult::ErrorAssertionFailed => (false, "Assertion Failed".to_string()),
                        evm::types::TxResult::ErrorOutOfGas => (false, "Out of Gas".to_string()),
                        _ => (false, "Error".to_string()),
                    };

                    results.push(TxTraceResult {
                        index: i,
                        tx: tx_payload,
                        success,
                        result: result_str,
                        gas_used: tx.gas,
                        call_trace,
                        events,
                        storage_changes: storage_changes_result,
                    });
                }
                Err(e) => {
                    results.push(TxTraceResult {
                        index: i,
                        tx: tx_payload,
                        success: false,
                        result: format!("Execution error: {}", e),
                        gas_used: 0,
                        call_trace: vec![],
                        events: vec![],
                        storage_changes: vec![],
                    });
                }
            }
        }

        tracing::info!("replay_sequence: completed {} transactions successfully", results.len());
        Ok(results)
    }
}