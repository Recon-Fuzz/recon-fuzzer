#![feature(thread_local)]

#[allow(dead_code)]
mod abi;
mod evm;
mod campaign;

use alloy_primitives::{Address, Bytes, U256};
use wasm_bindgen::prelude::*;

// Force LLVM to emit __wasm_init_tls (required for --shared-memory + --import-memory).
// Without at least one thread-local variable, the TLS section is empty and wasm-bindgen
// fails with "failed to find __wasm_init_tls".
#[thread_local]
static TLS_WORKER_ID: std::cell::Cell<u32> = std::cell::Cell::new(0);

use crate::evm::{
    EvmState, DEFAULT_DEPLOYER, DEFAULT_SENDERS, INITIAL_BLOCK_NUMBER,
    INITIAL_TIMESTAMP, MAX_GAS_PER_BLOCK, DEFAULT_CONTRACT_ADDR,
};
use crate::campaign::{CampaignState, EConfig, ExportedState, StateSync};
use crate::campaign::testing::TestMode;

/// Parse a hex string (with or without 0x prefix) into an Address.
fn parse_address(s: &str) -> Result<Address, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex address: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", bytes.len()));
    }
    Ok(Address::from_slice(&bytes))
}

/// Parse a hex string into Bytes.
fn parse_bytes(s: &str) -> Result<Bytes, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(Bytes::new());
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    Ok(Bytes::from(bytes))
}

/// Parse a hex or decimal string into U256.
fn parse_u256(s: &str) -> Result<U256, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex_str = &s[2..];
        U256::from_str_radix(hex_str, 16).map_err(|e| format!("invalid hex u256: {e}"))
    } else {
        U256::from_str_radix(s, 10).map_err(|e| format!("invalid decimal u256: {e}"))
    }
}

fn err_json(msg: &str) -> String {
    let escaped = serde_json::to_string(msg).unwrap_or_else(|_| format!("\"{}\"", msg.replace('"', "'")));
    format!(r#"{{"success":false,"error":{}}}"#, escaped)
}

// =========================================================================
// WasmEvm — low-level EVM API
// =========================================================================

#[wasm_bindgen]
pub struct WasmEvm {
    inner: EvmState,
}

#[wasm_bindgen]
impl WasmEvm {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: EvmState::new(),
        }
    }

    pub fn deploy(&mut self, deployer: &str, bytecode: &str) -> String {
        let deployer = match parse_address(deployer) {
            Ok(a) => a,
            Err(e) => return err_json(&e),
        };
        let bytecode = match parse_bytes(bytecode) {
            Ok(b) => b,
            Err(e) => return err_json(&e),
        };
        let result = self.inner.deploy_contract(deployer, bytecode);
        let json_result = crate::evm::tracing::exec_result_to_json(&result);
        serde_json::to_string(&json_result).unwrap_or_else(|e| err_json(&format!("serialize: {e}")))
    }

    pub fn call(&mut self, from: &str, to: &str, calldata: &str, value: &str) -> String {
        let from = match parse_address(from) {
            Ok(a) => a,
            Err(e) => return err_json(&e),
        };
        let to = match parse_address(to) {
            Ok(a) => a,
            Err(e) => return err_json(&e),
        };
        let calldata = match parse_bytes(calldata) {
            Ok(b) => b,
            Err(e) => return err_json(&e),
        };
        let value = match parse_u256(value) {
            Ok(v) => v,
            Err(e) => return err_json(&e),
        };
        let result = self.inner.exec_tx(from, to, calldata, value);
        let json_result = crate::evm::tracing::exec_result_to_json(&result);
        serde_json::to_string(&json_result).unwrap_or_else(|e| err_json(&format!("serialize: {e}")))
    }

    pub fn set_balance(&mut self, addr: &str, balance: &str) -> String {
        let addr = match parse_address(addr) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let balance = match parse_u256(balance) {
            Ok(v) => v,
            Err(e) => return e,
        };
        self.inner.set_balance(addr, balance);
        String::new()
    }

    pub fn set_code(&mut self, addr: &str, code: &str) -> String {
        let addr = match parse_address(addr) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let code = match parse_bytes(code) {
            Ok(b) => b,
            Err(e) => return e,
        };
        self.inner.set_code(addr, code);
        String::new()
    }

    pub fn get_storage(&self, addr: &str, slot: &str) -> String {
        let addr = match parse_address(addr) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let slot = match parse_u256(slot) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let val = self.inner.get_storage(addr, slot);
        format!("{val:#066x}")
    }

    pub fn set_storage(&mut self, addr: &str, slot: &str, value: &str) -> String {
        let addr = match parse_address(addr) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let slot = match parse_u256(slot) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let value = match parse_u256(value) {
            Ok(v) => v,
            Err(e) => return e,
        };
        self.inner.set_storage(addr, slot, value);
        String::new()
    }

    pub fn snapshot(&mut self) -> u32 {
        self.inner.snapshot()
    }

    pub fn revert_to(&mut self, id: u32) -> bool {
        self.inner.revert_to(id)
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }

    pub fn assume_rejected(&mut self) -> bool {
        self.inner.assume_rejected()
    }

    pub fn get_nonce(&self, addr: &str) -> String {
        let addr = match parse_address(addr) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let nonce = self
            .inner
            .db()
            .cache
            .accounts
            .get(&addr)
            .map(|a| a.info.nonce)
            .unwrap_or(0);
        nonce.to_string()
    }

    pub fn set_nonce(&mut self, addr: &str, nonce: &str) -> String {
        let addr = match parse_address(addr) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let nonce: u64 = match nonce.parse() {
            Ok(n) => n,
            Err(e) => return format!("invalid nonce: {e}"),
        };
        let current = self
            .inner
            .db_mut()
            .cache
            .accounts
            .get(&addr)
            .map(|a| a.info.clone())
            .unwrap_or_default();
        let info = revm::state::AccountInfo {
            nonce,
            ..current
        };
        self.inner.db_mut().insert_account_info(addr, info);
        String::new()
    }

    pub fn defaults(&self) -> String {
        let senders: Vec<String> = DEFAULT_SENDERS.iter().map(|a| format!("{a:?}")).collect();
        format!(
            r#"{{"deployer":"{:?}","contract_addr":"{:?}","senders":{},"block_number":{},"timestamp":{},"gas_limit":{},"hevm_addr":"{:?}"}}"#,
            DEFAULT_DEPLOYER,
            DEFAULT_CONTRACT_ADDR,
            serde_json::to_string(&senders).unwrap(),
            INITIAL_BLOCK_NUMBER,
            INITIAL_TIMESTAMP,
            MAX_GAS_PER_BLOCK,
            crate::evm::cheatcodes::HEVM_ADDRESS,
        )
    }
}

// =========================================================================
// WasmFuzzer — high-level fuzzer API
// =========================================================================

#[wasm_bindgen]
pub struct WasmFuzzer {
    inner: CampaignState,
}

#[wasm_bindgen]
impl WasmFuzzer {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str) -> Self {
        let config: EConfig =
            serde_json::from_str(config_json).unwrap_or_else(|_| EConfig::default());
        Self {
            inner: CampaignState::new(config),
        }
    }

    fn format_load_result(
        inner: &mut CampaignState,
        project: crate::evm::foundry::FoundryProject,
    ) -> String {
        let names: Vec<String> = project.contracts.iter().map(|c| c.name.clone()).collect();
        let test_contract = project.find_test_contract().map(|c| c.name.clone());
        let has_echidna_tests = test_contract.is_some();

        let recommended_mode = if has_echidna_tests {
            "property"
        } else {
            "assertion"
        };

        inner.project = Some(project);
        format!(
            r#"{{"success":true,"contracts":{},"test_contract":{},"has_echidna_tests":{},"recommended_mode":"{}"}}"#,
            serde_json::to_string(&names).unwrap_or_default(),
            serde_json::to_string(&test_contract).unwrap_or("null".to_string()),
            has_echidna_tests,
            recommended_mode,
        )
    }

    pub fn load_config(&mut self, yaml_str: &str) -> String {
        let mut test_mode = None;
        let mut seq_len = None;
        let mut test_limit = None;
        let mut shrink_limit = None;
        let mut workers: Option<u32> = None;
        let mut seed: Option<u64> = None;
        let mut max_time_delay: Option<u64> = None;
        let mut max_block_delay: Option<u64> = None;

        for line in yaml_str.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                match key {
                    "testMode" => test_mode = Some(value.to_string()),
                    "seqLen" => seq_len = value.parse().ok(),
                    "testLimit" => test_limit = value.parse().ok(),
                    "shrinkLimit" => shrink_limit = value.parse().ok(),
                    "workers" => workers = value.parse().ok(),
                    "seed" => seed = value.parse().ok(),
                    "maxTimeDelay" => max_time_delay = value.parse().ok(),
                    "maxBlockDelay" => max_block_delay = value.parse().ok(),
                    "contractAddr" | "deployer" | "sender" | "prefix" => {}
                    _ => {}
                }
            }
        }

        if let Some(len) = seq_len { self.inner.config.seq_len = len; }
        if let Some(limit) = test_limit { self.inner.config.test_limit = limit; }
        if let Some(limit) = shrink_limit { self.inner.config.shrink_limit = limit; }
        if let Some(s) = seed { self.inner.config.seed = s; }
        if let Some(d) = max_time_delay { self.inner.config.max_time_delay = d; }
        if let Some(d) = max_block_delay { self.inner.config.max_block_delay = d; }

        format!(
            r#"{{"success":true,"test_mode":{},"seq_len":{},"test_limit":{},"shrink_limit":{},"workers":{},"seed":{},"max_time_delay":{},"max_block_delay":{}}}"#,
            serde_json::to_string(&test_mode).unwrap_or("null".to_string()),
            self.inner.config.seq_len,
            self.inner.config.test_limit,
            self.inner.config.shrink_limit,
            serde_json::to_string(&workers).unwrap_or("null".to_string()),
            self.inner.config.seed,
            self.inner.config.max_time_delay,
            self.inner.config.max_block_delay,
        )
    }

    pub fn load_build_info(&mut self, build_info_json: &str) -> String {
        match crate::evm::foundry::FoundryProject::from_build_info(build_info_json) {
            Ok(project) => Self::format_load_result(&mut self.inner, project),
            Err(e) => err_json(&e),
        }
    }

    pub fn load_artifacts(&mut self, artifacts_json_array: &str) -> String {
        let artifact_strings: Vec<String> = match serde_json::from_str(artifacts_json_array) {
            Ok(a) => a,
            Err(e) => return err_json(&format!("JSON array parse error: {e}")),
        };
        let refs: Vec<&str> = artifact_strings.iter().map(|s| s.as_str()).collect();
        match crate::evm::foundry::FoundryProject::from_artifacts(&refs) {
            Ok(project) => Self::format_load_result(&mut self.inner, project),
            Err(e) => err_json(&e),
        }
    }

    pub fn load_artifact(&mut self, artifact_json: &str) -> String {
        self.load_artifacts(&format!("[{}]", serde_json::to_string(artifact_json).unwrap_or_default()))
    }

    pub fn deploy(&mut self, contract_name: &str) -> String {
        match self.inner.deploy_contract(contract_name) {
            Ok(addr) => format!(r#"{{"success":true,"address":"{:?}"}}"#, addr),
            Err(e) => err_json(&e),
        }
    }

    pub fn deploy_raw(&mut self, name: &str, abi_json: &str, bytecode_hex: &str) -> String {
        match self.inner.deploy_raw(name, abi_json, bytecode_hex) {
            Ok(addr) => format!(r#"{{"success":true,"address":"{:?}"}}"#, addr),
            Err(e) => err_json(&e),
        }
    }

    pub fn set_mode(&mut self, mode: &str) -> String {
        let test_mode = match mode.to_lowercase().as_str() {
            "property" => TestMode::Property,
            "assertion" => TestMode::Assertion,
            "optimization" => TestMode::Optimization,
            "exploration" => TestMode::Exploration,
            _ => return err_json(&format!("unknown mode: {mode}")),
        };
        self.inner.setup_tests(test_mode);
        format!(r#"{{"success":true,"tests_created":{}}}"#, self.inner.tests.len())
    }

    pub fn run_steps(&mut self, n: u32) -> String {
        let status = self.inner.run_steps(n);
        serde_json::to_string(&status).unwrap_or_else(|e| err_json(&format!("serialize: {e}")))
    }

    pub fn get_tests(&self) -> String {
        let statuses: Vec<crate::campaign::types::TestStatus> =
            self.inner.tests.iter().map(|t| t.into()).collect();
        serde_json::to_string(&statuses).unwrap_or_else(|e| err_json(&format!("serialize: {e}")))
    }

    pub fn get_corpus_size(&self) -> u32 { self.inner.corpus.len() as u32 }
    pub fn get_call_count(&self) -> u32 { self.inner.call_count as u32 }

    pub fn get_reproducer(&mut self, test_idx: u32) -> String {
        self.inner.format_reproducer(test_idx as usize)
    }

    pub fn stop(&mut self) { self.inner.stop(); }
    pub fn is_running(&self) -> bool { self.inner.running }

    pub fn get_final_results(&mut self) -> String {
        self.inner.format_final_results()
    }

    // Multi-worker support
    pub fn export_state(&self) -> String {
        match self.inner.export_state() {
            Ok(state) => serde_json::to_string(&state)
                .unwrap_or_else(|e| err_json(&format!("serialize: {e}"))),
            Err(e) => err_json(&e),
        }
    }

    pub fn import_state(&mut self, state_json: &str, worker_id: u32, seed: f64) -> String {
        let state: ExportedState = match serde_json::from_str(state_json) {
            Ok(s) => s,
            Err(e) => return err_json(&format!("parse state: {e}")),
        };
        match self.inner.import_state(&state, worker_id as usize, seed as u64) {
            Ok(()) => format!(r#"{{"success":true,"worker_id":{}}}"#, worker_id),
            Err(e) => err_json(&e),
        }
    }

    pub fn run_batch(&mut self, n: u32, worker_id: u32) -> String {
        let delta = self.inner.run_batch(n, worker_id as usize);
        serde_json::to_string(&delta)
            .unwrap_or_else(|e| err_json(&format!("serialize: {e}")))
    }

    pub fn apply_sync(&mut self, sync_json: &str) -> String {
        let sync: StateSync = match serde_json::from_str(sync_json) {
            Ok(s) => s,
            Err(e) => return err_json(&format!("parse sync: {e}")),
        };
        self.inner.apply_sync(&sync);
        r#"{"success":true}"#.to_string()
    }

    pub fn format_final_results_from_merged(&mut self, merged_json: &str) -> String {
        match self.inner.set_merged_results_and_format(merged_json) {
            Ok(results) => results,
            Err(e) => format!("Error formatting results: {e}"),
        }
    }
}

// =========================================================================
// WasmSharedFuzzer — SharedArrayBuffer-based multi-worker fuzzer
// =========================================================================
//
// Architecture (mirrors main fuzzer exactly):
//   1. Coordinator creates WasmSharedFuzzer, deploys contract, sets up tests
//   2. SharedState is created with all shared data behind wasm_safe_mutex::RwLock
//   3. Each worker creates a WasmFuzzWorker with Arc<SharedState> ref
//   4. Workers read/write shared state directly through RwLock — no postMessage sync needed
//
// WASM threading: All worker WASM instances share the same WebAssembly.Memory
// (via SharedArrayBuffer). wasm_safe_mutex uses Atomics.wait for blocking locks
// in worker threads, falling back to spinning on main thread.

use std::sync::Arc;
use crate::campaign::worker_env::{SharedState, WorkerEnv};

/// Global shared state — initialized once, shared across all workers via Arc.
/// We use a global because wasm_bindgen doesn't support passing Arc across workers directly.
/// Instead, each worker gets a reference to the same SharedState through shared WASM memory.
/// OnceLock is safe for concurrent access (no UB from shared mutable static).
static SHARED_STATE: std::sync::OnceLock<Arc<SharedState>> = std::sync::OnceLock::new();

fn get_shared_state() -> Result<Arc<SharedState>, String> {
    SHARED_STATE.get().cloned().ok_or_else(|| "SharedState not initialized. Call WasmSharedFuzzer.init_shared_state() first.".to_string())
}

/// Coordinator-side API for setting up the shared fuzzing campaign.
/// Used on the main thread to deploy contracts, create tests, and initialize SharedState.
#[wasm_bindgen]
pub struct WasmSharedFuzzer {
    inner: CampaignState,
    /// Gas tracking for delta-based gas/s calculation (matches main fuzzer)
    last_gas_total: u64,
    last_gas_time_ms: f64,
    /// Coverage tracking for "New coverage" events (coordinator reports, not workers)
    last_reported_coverage: usize,
}

#[wasm_bindgen]
impl WasmSharedFuzzer {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str) -> Self {
        let config: EConfig =
            serde_json::from_str(config_json).unwrap_or_else(|_| EConfig::default());
        Self {
            inner: CampaignState::new(config),
            last_gas_total: 0,
            last_gas_time_ms: 0.0,
            last_reported_coverage: 0,
        }
    }

    // --- Same setup API as WasmFuzzer ---

    pub fn load_config(&mut self, yaml_str: &str) -> String {
        // Delegate to same logic (reuse WasmFuzzer's config parsing)
        let mut test_mode = None;
        let mut seq_len = None;
        let mut test_limit = None;
        let mut shrink_limit = None;
        let mut workers: Option<u32> = None;
        let mut seed: Option<u64> = None;
        let mut max_time_delay: Option<u64> = None;
        let mut max_block_delay: Option<u64> = None;

        for line in yaml_str.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                match key {
                    "testMode" => test_mode = Some(value.to_string()),
                    "seqLen" => seq_len = value.parse().ok(),
                    "testLimit" => test_limit = value.parse().ok(),
                    "shrinkLimit" => shrink_limit = value.parse().ok(),
                    "workers" => workers = value.parse().ok(),
                    "seed" => seed = value.parse().ok(),
                    "maxTimeDelay" => max_time_delay = value.parse().ok(),
                    "maxBlockDelay" => max_block_delay = value.parse().ok(),
                    _ => {}
                }
            }
        }

        if let Some(len) = seq_len { self.inner.config.seq_len = len; }
        if let Some(limit) = test_limit { self.inner.config.test_limit = limit; }
        if let Some(limit) = shrink_limit { self.inner.config.shrink_limit = limit; }
        if let Some(s) = seed { self.inner.config.seed = s; }
        if let Some(d) = max_time_delay { self.inner.config.max_time_delay = d; }
        if let Some(d) = max_block_delay { self.inner.config.max_block_delay = d; }

        format!(
            r#"{{"success":true,"test_mode":{},"seq_len":{},"test_limit":{},"shrink_limit":{},"workers":{},"seed":{}}}"#,
            serde_json::to_string(&test_mode).unwrap_or("null".to_string()),
            self.inner.config.seq_len,
            self.inner.config.test_limit,
            self.inner.config.shrink_limit,
            serde_json::to_string(&workers).unwrap_or("null".to_string()),
            self.inner.config.seed,
        )
    }

    pub fn load_build_info(&mut self, build_info_json: &str) -> String {
        match crate::evm::foundry::FoundryProject::from_build_info(build_info_json) {
            Ok(project) => {
                let names: Vec<String> = project.contracts.iter().map(|c| c.name.clone()).collect();
                let test_contract = project.find_test_contract().map(|c| c.name.clone());
                let has_echidna_tests = test_contract.is_some();
                let recommended_mode = if has_echidna_tests { "property" } else { "assertion" };
                self.inner.project = Some(project);
                format!(
                    r#"{{"success":true,"contracts":{},"test_contract":{},"has_echidna_tests":{},"recommended_mode":"{}"}}"#,
                    serde_json::to_string(&names).unwrap_or_default(),
                    serde_json::to_string(&test_contract).unwrap_or("null".to_string()),
                    has_echidna_tests, recommended_mode,
                )
            }
            Err(e) => err_json(&e),
        }
    }

    pub fn load_artifacts(&mut self, artifacts_json_array: &str) -> String {
        let artifact_strings: Vec<String> = match serde_json::from_str(artifacts_json_array) {
            Ok(a) => a,
            Err(e) => return err_json(&format!("JSON array parse error: {e}")),
        };
        let refs: Vec<&str> = artifact_strings.iter().map(|s| s.as_str()).collect();
        match crate::evm::foundry::FoundryProject::from_artifacts(&refs) {
            Ok(project) => {
                let names: Vec<String> = project.contracts.iter().map(|c| c.name.clone()).collect();
                let test_contract = project.find_test_contract().map(|c| c.name.clone());
                let has_echidna_tests = test_contract.is_some();
                let recommended_mode = if has_echidna_tests { "property" } else { "assertion" };
                self.inner.project = Some(project);
                format!(
                    r#"{{"success":true,"contracts":{},"test_contract":{},"has_echidna_tests":{},"recommended_mode":"{}"}}"#,
                    serde_json::to_string(&names).unwrap_or_default(),
                    serde_json::to_string(&test_contract).unwrap_or("null".to_string()),
                    has_echidna_tests, recommended_mode,
                )
            }
            Err(e) => err_json(&e),
        }
    }

    pub fn deploy(&mut self, contract_name: &str) -> String {
        match self.inner.deploy_contract(contract_name) {
            Ok(addr) => format!(r#"{{"success":true,"address":"{:?}"}}"#, addr),
            Err(e) => err_json(&e),
        }
    }

    pub fn set_mode(&mut self, mode: &str) -> String {
        let test_mode = match mode.to_lowercase().as_str() {
            "property" => TestMode::Property,
            "assertion" => TestMode::Assertion,
            "optimization" => TestMode::Optimization,
            "exploration" => TestMode::Exploration,
            _ => return err_json(&format!("unknown mode: {mode}")),
        };
        self.inner.setup_tests(test_mode);
        format!(r#"{{"success":true,"tests_created":{}}}"#, self.inner.tests.len())
    }

    /// Initialize SharedState from current CampaignState.
    /// Must be called after deploy + set_mode, before creating workers.
    /// Transfers tests, coverage, codehash_map into the global SharedState.
    pub fn init_shared_state(&mut self) -> String {
        let mut shared = SharedState::new();

        // Transfer tests into shared state (wrapped in RwLock)
        let tests = std::mem::take(&mut self.inner.tests);
        shared.init_tests(tests);

        // Transfer init coverage from EVM
        let init_cov = self.inner.evm.init_coverage.clone();
        shared.set_init_coverage(init_cov);

        // Transfer codehash map
        if let Some(ref project) = self.inner.project {
            let codehash_map = crate::evm::coverage::build_codehash_map(&project.contracts);
            shared.set_codehash_map(codehash_map);
        }

        // Seed shared dictionary from worker-local dictionary
        {
            let mut dict = shared.dict_values.lock_sync_write();
            for val in &self.inner.dictionary.dict_values {
                dict.insert(*val);
            }
        }

        shared.set_running(true);

        let num_tests = shared.tests.len();
        let arc = Arc::new(shared);
        SHARED_STATE.set(arc).map_err(|_| "SharedState already initialized").ok();

        format!(r#"{{"success":true,"tests":{}}}"#, num_tests)
    }

    /// Export EVM state for workers to clone (each worker needs its own EVM).
    /// Returns serialized state that workers use to initialize their EVM.
    pub fn export_state(&self) -> String {
        match self.inner.export_state() {
            Ok(state) => serde_json::to_string(&state)
                .unwrap_or_else(|e| err_json(&format!("serialize: {e}"))),
            Err(e) => err_json(&e),
        }
    }

    /// Get status from shared state (coordinator reads shared data).
    /// Format matches main fuzzer's output::print_status exactly.
    pub fn status(&mut self) -> String {
        match get_shared_state() {
            Ok(shared) => {
                use crate::campaign::testing::{TestType, TestValue, TestState};

                let total_calls = shared.get_total_calls();
                let (cov, _codehashes) = shared.coverage_stats();
                let corpus_size = shared.corpus_size();
                let tests_failed = shared.tests_failed();
                let total_tests = shared.num_tests();
                let shrink_limit = self.inner.config.shrink_limit;

                let test_statuses: Vec<crate::campaign::types::TestStatus> = shared.tests.iter()
                    .map(|t| {
                        let test = t.lock_sync_read();
                        crate::campaign::types::TestStatus::from(&*test)
                    })
                    .collect();

                // Collect optimization values (i128, matches main fuzzer)
                let opt_values: Vec<i128> = shared.tests.iter()
                    .filter_map(|t| {
                        let test = t.lock_sync_read();
                        if matches!(test.test_type, TestType::OptimizationTest { .. }) {
                            if let TestValue::IntValue(v) = &test.value {
                                let val: i128 = (*v).try_into().unwrap_or_else(|_| {
                                    if v.is_negative() { i128::MIN } else { i128::MAX }
                                });
                                Some(val)
                            } else { None }
                        } else { None }
                    })
                    .collect();

                // Collect shrinking info
                let shrinking_part: String = {
                    let shrinking: Vec<String> = shared.tests.iter()
                        .enumerate()
                        .filter_map(|(i, t)| {
                            let test = t.lock_sync_read();
                            if let TestState::Large(n) = &test.state {
                                Some(format!("W{}:{}/{} ({})",
                                    test.worker_id.unwrap_or(i), n, shrink_limit, test.reproducer.len()))
                            } else { None }
                        })
                        .collect();
                    if shrinking.is_empty() {
                        String::new()
                    } else {
                        format!(", shrinking: {}", shrinking.join(" "))
                    }
                };

                // Calculate gas/s (delta-based, matches main fuzzer's campaign.rs:683-692)
                let current_gas = shared.get_total_gas();
                let now_ms = js_sys::Date::now();
                let delta_gas = current_gas.saturating_sub(self.last_gas_total);
                let delta_time_s = (now_ms - self.last_gas_time_ms) / 1000.0;
                let gas_per_second = if delta_time_s > 0.5 {
                    (delta_gas as f64 / delta_time_s) as u64
                } else {
                    0
                };
                self.last_gas_total = current_gas;
                self.last_gas_time_ms = now_ms;

                // Match main fuzzer format exactly
                let status_line = format!(
                    "[status] tests: {}/{}, fuzzing: {}/{}, values: {:?}, cov: {}, corpus: {}{}, gas/s: {}",
                    tests_failed, total_tests, total_calls, self.inner.config.test_limit,
                    opt_values, cov, corpus_size, shrinking_part, gas_per_second,
                );

                let mut events = vec![status_line];

                // "New coverage" event (coordinator reports, matches main fuzzer's worker 0 pattern)
                if cov > self.last_reported_coverage {
                    let (_, codehashes) = shared.coverage_stats();
                    events.push(format!(
                        "New coverage: {} instr, {} contracts, {} seqs in corpus",
                        cov, codehashes, corpus_size
                    ));
                    self.last_reported_coverage = cov;
                }

                let status = crate::campaign::CampaignStatus {
                    call_count: total_calls,
                    corpus_size,
                    coverage_points: cov,
                    tests: test_statuses,
                    events,
                    running: shared.is_running(),
                };
                serde_json::to_string(&status).unwrap_or_else(|e| err_json(&format!("serialize: {e}")))
            }
            Err(e) => err_json(&e),
        }
    }

    /// Stop all workers.
    pub fn stop(&self) {
        if let Ok(shared) = get_shared_state() {
            shared.set_running(false);
        }
    }

    /// Check if campaign is still running.
    pub fn is_running(&self) -> bool {
        get_shared_state().map(|s| s.is_running()).unwrap_or(false)
    }

    /// Format final results with traces (coordinator runs this after stopping).
    pub fn get_final_results(&mut self) -> String {
        // Sync all shared state back into inner CampaignState for trace replay + stats
        if let Ok(shared) = get_shared_state() {
            self.inner.tests = shared.tests.iter()
                .map(|t| t.lock_sync_read().clone())
                .collect();
            // Sync coverage so final stats are correct
            self.inner.evm.coverage = shared.runtime_coverage.lock_sync_read().clone();
            self.inner.evm.init_coverage = shared.init_coverage.lock_sync_read().clone();
        }
        self.inner.format_final_results()
    }
}

/// Worker-side API — each web worker creates one of these.
/// Holds a WorkerEnv with Arc<SharedState> reference + worker-local EVM.
///
/// SAFETY: We use UnsafeCell to avoid wasm-bindgen's RefCell-like borrow tracking,
/// which races across threads when SharedArrayBuffer is used (borrow flags live in
/// shared WASM linear memory). Each WasmFuzzWorker is exclusively owned by one
/// web worker thread, so &self -> &mut inner is safe.
#[wasm_bindgen]
pub struct WasmFuzzWorker {
    inner: std::cell::UnsafeCell<WorkerEnv>,
}

// SAFETY: Each WasmFuzzWorker is created and used by exactly one web worker thread.
// The UnsafeCell is never shared across threads — only the underlying SharedState
// (behind proper RwLock) is shared.
unsafe impl Send for WasmFuzzWorker {}
unsafe impl Sync for WasmFuzzWorker {}

#[wasm_bindgen]
impl WasmFuzzWorker {
    /// Create a new worker from exported state.
    /// Each worker gets its own EVM instance but shares state through SharedState.
    #[wasm_bindgen(constructor)]
    pub fn new(state_json: &str, worker_id: u32, seed: f64) -> Result<WasmFuzzWorker, JsValue> {
        use rand::SeedableRng;

        let shared = get_shared_state()
            .map_err(|e| JsValue::from_str(&e))?;

        let state: ExportedState = serde_json::from_str(state_json)
            .map_err(|e| JsValue::from_str(&format!("parse state: {e}")))?;

        let worker_seed = (seed as u64).wrapping_add(worker_id as u64);

        // Create worker-local EVM from exported state
        let mut evm = EvmState::new();

        // Restore accounts
        for account in &state.accounts {
            let addr: Address = account.address.parse()
                .map_err(|e| JsValue::from_str(&format!("parse addr: {e}")))?;
            let balance = U256::from_str_radix(
                account.balance.strip_prefix("0x").unwrap_or(&account.balance), 16
            ).unwrap_or(U256::ZERO);
            let code_bytes = hex::decode(&account.code).unwrap_or_default();

            let info = if code_bytes.is_empty() {
                revm::state::AccountInfo {
                    balance,
                    nonce: account.nonce,
                    ..Default::default()
                }
            } else {
                let bytecode = revm::bytecode::Bytecode::new_raw(Bytes::from(code_bytes));
                let code_hash = bytecode.hash_slow();
                revm::state::AccountInfo {
                    balance,
                    nonce: account.nonce,
                    code_hash,
                    code: Some(bytecode),
                    ..Default::default()
                }
            };
            evm.db_mut().insert_account_info(addr, info);

            for (slot_hex, val_hex) in &account.storage {
                let slot = U256::from_str_radix(
                    slot_hex.strip_prefix("0x").unwrap_or(slot_hex), 16
                ).unwrap_or(U256::ZERO);
                let val = U256::from_str_radix(
                    val_hex.strip_prefix("0x").unwrap_or(val_hex), 16
                ).unwrap_or(U256::ZERO);
                evm.set_storage(addr, slot, val);
            }
        }

        evm.block_number = state.block_number;
        evm.timestamp = state.timestamp;

        // Restore init coverage into worker-local EVM
        for entry in &state.coverage {
            let codehash: alloy_primitives::B256 = entry.codehash.parse()
                .map_err(|e| JsValue::from_str(&format!("parse codehash: {e}")))?;
            let contract_cov = evm.init_coverage.entry(codehash).or_default();
            let e = contract_cov.entry(entry.pc).or_insert((0, 0));
            e.0 |= entry.depth_bits;
            e.1 |= entry.result_bits;
        }

        // Restore codehash map into worker EVM
        let mut codehash_map: crate::evm::coverage::MetadataToCodehash = std::collections::HashMap::new();
        for entry in &state.codehash_map {
            let metadata_hash: alloy_primitives::B256 = entry.metadata_hash.parse()
                .map_err(|e| JsValue::from_str(&format!("parse metadata_hash: {e}")))?;
            let compile_codehash: alloy_primitives::B256 = entry.compile_codehash.parse()
                .map_err(|e| JsValue::from_str(&format!("parse compile_codehash: {e}")))?;
            codehash_map.entry(metadata_hash)
                .or_insert_with(Vec::new)
                .push((entry.bytecode_len, compile_codehash));
        }
        evm.set_codehash_map(codehash_map);

        let contract_addr: Address = state.contract_addr.parse()
            .map_err(|e| JsValue::from_str(&format!("parse contract_addr: {e}")))?;

        // Restore ABI and build CompiledContract
        let abi: alloy_json_abi::JsonAbi = serde_json::from_str(&state.abi_json)
            .map_err(|e| JsValue::from_str(&format!("parse abi: {e}")))?;

        let fuzzable_funcs: Vec<alloy_json_abi::Function> = abi.functions()
            .filter(|f| {
                !f.name.starts_with("echidna_")
                    && !f.name.starts_with("optimize_")
                    && f.name != "setUp"
            })
            .cloned()
            .collect();

        use alloy_dyn_abi::Specifier;
        let mut functions = std::collections::HashMap::new();
        let mut resolved_param_types = std::collections::HashMap::new();
        for func in abi.functions() {
            let selector = func.selector();
            functions.insert(selector, func.clone());
            let types: Vec<alloy_dyn_abi::DynSolType> = func.inputs.iter()
                .filter_map(|p| p.resolve().ok())
                .collect();
            resolved_param_types.insert(selector, types);
        }

        let contract = crate::evm::foundry::CompiledContract {
            name: state.contract_name.clone(),
            qualified_name: format!("worker:{}", state.contract_name),
            abi: abi.clone(),
            bytecode: Bytes::new(),
            deployed_bytecode: Bytes::new(),
            functions,
            resolved_param_types,
            exclude_from_fuzzing: Vec::new(),
        };

        // Seed dictionary from deployed bytecode
        let mut dictionary = crate::abi::types::GenDict::new(worker_seed);
        if let Some(account) = evm.db().cache.accounts.get(&contract_addr) {
            if let Some(code) = &account.info.code {
                dictionary.seed_from_bytecode(code.bytes_slice());
            }
        }

        let max_value = U256::from_str_radix(
            state.config.max_value.strip_prefix("0x").unwrap_or(&state.config.max_value), 16
        ).unwrap_or(U256::from(u128::MAX));

        let initial_snapshot = Some(evm.snapshot());

        // Build event_map from ABI (matches main fuzzer's Env.event_map)
        let mut event_map = std::collections::HashMap::new();
        for event in abi.events() {
            event_map.insert(event.selector(), event.clone());
        }

        let mut worker = WorkerEnv {
            shared,
            worker_id: worker_id as usize,
            evm,
            rng: rand::rngs::SmallRng::seed_from_u64(worker_seed),
            dictionary,
            contract: Some(contract),
            fuzzable_funcs,
            contract_addr,
            max_value,
            config: state.config.clone(),
            initial_snapshot,
            event_log: Vec::new(),
            call_count: 0,
            total_gas: 0,
            lifetime_calls: 0,
            event_map,
        };

        // Populate return types for type-aware dictionary learning
        worker.populate_return_types();

        // Pull initial shared dictionary values
        worker.pull_dict_from_shared();

        Ok(WasmFuzzWorker { inner: std::cell::UnsafeCell::new(worker) })
    }

    /// SAFETY: Each worker is single-threaded. UnsafeCell avoids wasm-bindgen borrow flag races.
    fn inner_mut(&self) -> &mut WorkerEnv {
        unsafe { &mut *self.inner.get() }
    }

    /// Run N fuzzing iterations. Workers directly read/write shared state.
    pub fn run_batch(&self, n: u32) {
        self.inner_mut().run_batch(n);
    }

    /// Get worker-local status (mainly for debugging).
    pub fn status(&self) -> String {
        let status = self.inner_mut().status();
        serde_json::to_string(&status).unwrap_or_else(|e| err_json(&format!("serialize: {e}")))
    }

    /// Drain event log (coordinator can poll this for worker-specific events).
    pub fn drain_events(&self) -> String {
        let events = std::mem::take(&mut self.inner_mut().event_log);
        serde_json::to_string(&events).unwrap_or("[]".to_string())
    }

    /// Check if the campaign is still running.
    pub fn is_running(&self) -> bool {
        self.inner_mut().shared.is_running()
    }

    /// Get this worker's total call count (lifetime, not the sync counter).
    pub fn call_count(&self) -> u32 {
        self.inner_mut().lifetime_calls as u32
    }
}
