//! Configuration and runtime environment types
//!
//! Configuration types are re-exported from the `config` crate.
//! This module also contains the `Env` runtime environment struct.

use alloy_primitives::{Address, FixedBytes, I256, U256};
use config::global::EConfig;
use evm::foundry::CompiledContract;
use evm::exec::CoverageMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::repro::ReproWriter;
use crate::testing::EchidnaTest;
use crate::web::WebObservableState;
use crate::worker_env::CorpusEntry;
use crate::world::World;

/// Runtime environment
pub struct Env {
    /// Global configuration
    pub cfg: EConfig,

    /// Compiled contracts
    pub contracts: Vec<CompiledContract>,

    /// Main contract
    pub main_contract: Option<CompiledContract>,

    /// Test references (shared across workers)
    pub test_refs: Vec<Arc<RwLock<EchidnaTest>>>,

    /// Coverage map for init code
    pub coverage_ref_init: Arc<RwLock<CoverageMap>>,

    /// Coverage map for runtime
    pub coverage_ref_runtime: Arc<RwLock<CoverageMap>>,

    /// Corpus (shared transaction sequences with their discovery priority)
    /// Priority = ncallseqs when the sequence was discovered 
    /// Uses Arc<Vec<Tx>> for cheap cloning during corpus mutation selection
    pub corpus_ref: Arc<RwLock<Vec<CorpusEntry>>>,

    /// Set of seen corpus hashes (for deduplication)
    pub corpus_seen: Arc<RwLock<std::collections::HashSet<u64>>>,

    /// Map from runtime metadata hash to compile-time codehash
    /// This allows tracking coverage by contract type, not by address
    /// (same contract deployed multiple times = same codehash)
    /// Multiple contracts may share the same metadata hash, so we store (bytecode_len, codehash) pairs
    pub codehash_map: Arc<RwLock<evm::coverage::MetadataToCodehash>>,

    /// World state
    pub world: World,

    /// Chain ID (from RPC)
    pub chain_id: Option<U256>,

    /// Event map for decoding logs
    pub event_map: HashMap<alloy_primitives::B256, alloy_json_abi::Event>,

    /// Function map for decoding call inputs/outputs (selector -> Function)
    pub function_map: HashMap<FixedBytes<4>, alloy_json_abi::Function>,

    /// Dictionary values extracted from setUp traces (U256 values)
    /// Used to seed worker dictionaries with values from constructor/setUp execution
    pub setup_dict_values: Vec<U256>,

    /// Dictionary addresses extracted from setUp traces
    pub setup_dict_addresses: Vec<Address>,

    /// Dictionary signed values extracted from setUp traces
    pub setup_dict_signed: Vec<I256>,

    /// Dictionary tuples/structs extracted from setUp traces (e.g., MarketParams)
    pub setup_dict_tuples: Vec<alloy_dyn_abi::DynSolValue>,

    /// Slither/recon-generate info (source analysis data)
    pub slither_info: Option<analysis::slither::SlitherInfo>,

    /// Revert hotspot tracking: (codehash, pc) -> count
    /// Used by the web UI to show frequently reverting locations
    pub revert_hotspots: Arc<RwLock<HashMap<(alloy_primitives::B256, usize), u32>>>,

    /// Injected dictionary values (from web UI)
    /// Workers periodically poll and drain this to add values to their dictionaries
    pub injected_dict_values: Arc<RwLock<Vec<alloy_primitives::U256>>>,

    /// Argument clamps for interactive fuzzing: (function_name, param_idx) -> clamped_value
    /// When set, the corresponding argument will always use the clamped value
    pub arg_clamps: Arc<RwLock<HashMap<(String, usize), String>>>,

    /// Target functions for focused fuzzing (from web UI)
    /// If non-empty, only these functions will be fuzzed
    pub target_functions: Arc<RwLock<std::collections::HashSet<String>>>,

    /// Fuzz transaction templates (from web UI)
    /// Prioritized sequences with wildcards like "f(1,?,?) ; g(?,2,5)"
    pub fuzz_templates: Arc<RwLock<Vec<crate::transaction::FuzzSequenceTemplate>>>,

    /// Web UI state (for recording statistics from workers)
    /// Set by spawn_web_server, accessed by workers to record call/sequence stats
    pub web_state: Option<Arc<WebObservableState>>,

    /// Foundry repro writer (--repro flag)
    pub repro_writer: Option<ReproWriter>,
}

impl Env {
    pub fn new(cfg: EConfig, contracts: Vec<CompiledContract>) -> Self {
        let mut event_map = HashMap::new();
        let mut function_map = HashMap::new();
        for contract in &contracts {
            for event in contract.abi.events() {
                event_map.insert(event.selector(), event.clone());
            }
            for func in contract.abi.functions() {
                function_map.insert(func.selector(), func.clone());
            }
        }

        // Build codehash map: metadata_hash -> compile_time_codehash
        // This allows us to map runtime bytecode back to the original contract
        let codehash_map = evm::coverage::build_codehash_map(&contracts);

        let senders = cfg.sol_conf.sender.clone();

        Self {
            cfg,
            contracts,
            main_contract: None,
            test_refs: Vec::new(),
            coverage_ref_init: Arc::new(RwLock::new(HashMap::new())),
            coverage_ref_runtime: Arc::new(RwLock::new(HashMap::new())),
            corpus_ref: Arc::new(RwLock::new(Vec::new())), // Vec<(priority, txs)>
            corpus_seen: Arc::new(RwLock::new(std::collections::HashSet::new())),
            codehash_map: Arc::new(RwLock::new(codehash_map)),
            world: World::new().with_senders(senders),
            chain_id: None,
            event_map,
            function_map,
            setup_dict_values: Vec::new(),
            setup_dict_addresses: Vec::new(),
            setup_dict_signed: Vec::new(),
            setup_dict_tuples: Vec::new(),
            slither_info: None,
            revert_hotspots: Arc::new(RwLock::new(HashMap::new())),
            injected_dict_values: Arc::new(RwLock::new(Vec::new())),
            arg_clamps: Arc::new(RwLock::new(HashMap::new())),
            target_functions: Arc::new(RwLock::new(std::collections::HashSet::new())),
            fuzz_templates: Arc::new(RwLock::new(Vec::new())),
            web_state: None,
            repro_writer: None,
        }
    }

    /// Add a test
    pub fn add_test(&mut self, test: EchidnaTest) {
        self.test_refs.push(Arc::new(RwLock::new(test)));
    }

    /// Get all tests
    pub fn get_tests(&self) -> Vec<EchidnaTest> {
        self.test_refs.iter().map(|r| r.read().clone()).collect()
    }
}
