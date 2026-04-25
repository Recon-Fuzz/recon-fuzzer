//! Worker-local environment for fuzzing threads
//!
//! Contains cloned Arc refs for thread-safe access to shared state.

use std::sync::Arc;

use alloy_primitives::{Address, B256, I256, U256};
use evm::{coverage::MetadataToCodehash, exec::CoverageMap, foundry::CompiledContract, types::Tx};
use parking_lot::RwLock;

use crate::config::Env;
use crate::repro::ReproWriter;
use crate::testing::EchidnaTest;
use crate::web::WebObservableState;
use crate::world::World;

/// Corpus entry type: (priority, Arc-wrapped transaction sequence)
/// Using Arc<Vec<Tx>> allows cheap cloning of the corpus list without
/// cloning the actual transaction data - only when mutation is needed.
pub type CorpusEntry = (usize, Arc<Vec<Tx>>);

/// Worker-local environment (contains cloned Arc refs)
/// Implements the same interface as Env for use in worker threads
pub struct WorkerEnv {
    pub cfg: config::global::EConfig,
    pub test_refs: Vec<Arc<RwLock<EchidnaTest>>>,
    pub coverage_ref_runtime: Arc<RwLock<CoverageMap>>,
    pub coverage_ref_init: Arc<RwLock<CoverageMap>>,
    pub corpus_ref: Arc<RwLock<Vec<CorpusEntry>>>,
    pub corpus_seen: Arc<RwLock<std::collections::HashSet<u64>>>,
    pub main_contract: Option<CompiledContract>,
    pub world: World,
    pub event_map: std::collections::HashMap<B256, alloy_json_abi::Event>,
    pub codehash_map: Arc<RwLock<MetadataToCodehash>>,
    pub slither_info: Option<analysis::slither::SlitherInfo>,
    /// All compiled contracts (for LCOV generation)
    pub contracts: Arc<Vec<CompiledContract>>,
    /// Project path (for LCOV generation)
    pub project_path: std::path::PathBuf,
    /// Revert hotspot tracking (shared with web UI)
    pub revert_hotspots: Arc<RwLock<std::collections::HashMap<(B256, usize), u32>>>,
    /// Injected dictionary values (from web UI, polled by workers)
    pub injected_dict_values: Arc<RwLock<Vec<U256>>>,
    /// Argument clamps for interactive fuzzing: (function_name, param_idx) -> clamped_value
    pub arg_clamps: Arc<RwLock<std::collections::HashMap<(String, usize), String>>>,
    /// Target functions for focused fuzzing (from web UI)
    pub target_functions: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Fuzz transaction templates with wildcards
    pub fuzz_templates: Arc<RwLock<Vec<crate::transaction::FuzzSequenceTemplate>>>,
    /// Web UI state (for recording statistics from workers)
    pub web_state: Option<Arc<WebObservableState>>,
    /// Dictionary values extracted from setUp traces (U256)
    pub setup_dict_values: Vec<U256>,
    /// Dictionary addresses extracted from setUp traces
    pub setup_dict_addresses: Vec<Address>,
    /// Dictionary signed values extracted from setUp traces
    pub setup_dict_signed: Vec<I256>,
    /// Dictionary tuples/structs extracted from setUp traces (e.g., MarketParams)
    pub setup_dict_tuples: Vec<alloy_dyn_abi::DynSolValue>,
    /// Foundry repro writer (--repro flag)
    pub repro_writer: Option<ReproWriter>,
}

impl From<&Env> for WorkerEnv {
    fn from(env: &Env) -> Self {
        WorkerEnv {
            cfg: env.cfg.clone(),
            test_refs: env.test_refs.clone(),
            coverage_ref_runtime: env.coverage_ref_runtime.clone(),
            coverage_ref_init: env.coverage_ref_init.clone(),
            corpus_ref: env.corpus_ref.clone(),
            corpus_seen: env.corpus_seen.clone(),
            main_contract: env.main_contract.clone(),
            world: env.world.clone(),
            event_map: env.event_map.clone(),
            codehash_map: env.codehash_map.clone(),
            slither_info: env.slither_info.clone(),
            contracts: Arc::new(env.contracts.clone()),
            project_path: std::env::current_dir().unwrap_or_default(),
            revert_hotspots: env.revert_hotspots.clone(),
            injected_dict_values: env.injected_dict_values.clone(),
            arg_clamps: env.arg_clamps.clone(),
            target_functions: env.target_functions.clone(),
            fuzz_templates: env.fuzz_templates.clone(),
            web_state: env.web_state.clone(),
            setup_dict_values: env.setup_dict_values.clone(),
            setup_dict_addresses: env.setup_dict_addresses.clone(),
            setup_dict_signed: env.setup_dict_signed.clone(),
            setup_dict_tuples: env.setup_dict_tuples.clone(),
            repro_writer: env.repro_writer.clone(),
        }
    }
}

/// Record a revert at a specific location for hotspot tracking
pub fn record_revert_hotspot(env: &WorkerEnv, codehash: B256, pc: usize) {
    let mut hotspots = env.revert_hotspots.write();
    *hotspots.entry((codehash, pc)).or_insert(0) += 1;
}
