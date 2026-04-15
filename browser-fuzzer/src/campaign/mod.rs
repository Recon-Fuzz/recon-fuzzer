//! Core fuzzing loop for browser-fuzzer
//!
//! Single-threaded port of campaign/src/campaign.rs run_fuzz_worker().
//! Runs N iterations at a time (cooperative yielding for WASM event loop).

pub mod config;
pub mod corpus;
pub mod execution;
pub mod shrink;
pub mod testing;
pub mod transaction;
pub mod types;
pub mod worker_env;

pub use config::EConfig;
pub use types::{
    CampaignStatus, CoverageEntry, CodehashMapEntry, ExportedAccount, ExportedState,
    StateSync, TestStatus, TestSyncEntry, TestUpdate, WorkerDelta,
    test_state_to_status_string, parse_status_string_to_state,
};

use alloy_json_abi::Function;
use alloy_primitives::{Address, B256, Bytes, U256};
use rand::rngs::SmallRng;
use rand::prelude::*;
use rand::SeedableRng;
use serde::Deserialize;

use crate::abi::types::GenDict;
use self::corpus::{
    apply_corpus_mutation, seq_mutators_stateful, seq_mutators_stateless, CorpusEntry,
    DEFAULT_MUTATION_CONSTS,
};
use crate::evm::tracing::decoder::TraceDecoder;
use crate::evm::exec::EvmState;
use crate::evm::foundry::{FoundryProject, CompiledContract};
use self::testing::{
    calculate_value_complexity, check_assertion, check_call_test_predicate, check_etest,
    create_tests, update_open_test, EchidnaTest, ShrinkMode, TestMode, TestState, TestType,
    TestValue,
};
use self::transaction::{rand_seq, shrink_tx, Tx};
use self::shrink::{
    calculate_delay_complexity, can_shrink_tx, generate_call_to_delay_candidates,
    generate_delay_candidates, multi_shorten_seq, remove_useless_no_calls,
    shrink_sender, shorten_seq,
};

// =========================================================================
// CampaignState
// =========================================================================

pub struct CampaignState {
    pub evm: EvmState,
    pub tests: Vec<EchidnaTest>,
    pub corpus: Vec<CorpusEntry>,
    pub dictionary: GenDict,
    pub decoder: TraceDecoder,
    pub config: EConfig,
    pub rng: SmallRng,
    pub call_count: u64,
    pub total_gas: u64,
    pub running: bool,
    // Contract data from CompiledContract (artifact loading)
    pub contract: Option<CompiledContract>,
    // Cached fuzzable functions (from contract.fuzzable_functions())
    fuzzable_funcs: Vec<Function>,
    contract_addr: Address,
    max_value: U256,
    // Foundry project for library linking
    pub project: Option<FoundryProject>,
    // Snapshot of initial state (for reverting between sequences)
    initial_snapshot: Option<u32>,
    // Event log (Echidna-style progress messages, drained each status() call)
    event_log: Vec<String>,
    // Track last reported coverage for "New coverage" events
    last_reported_coverage: usize,
    // Gas/s tracking (delta-based, matches main fuzzer)
    last_gas_total: u64,
    last_gas_time_ms: f64,
    // Event map for ABI-decoded event extraction (matches main fuzzer's WorkerEnv.event_map)
    event_map: std::collections::HashMap<B256, alloy_json_abi::Event>,
}

impl CampaignState {
    pub fn new(config: EConfig) -> Self {
        let seed = if config.seed == 0 {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf).unwrap_or_default();
            u64::from_le_bytes(buf)
        } else {
            config.seed
        };

        let max_value = U256::from_str_radix(
            config.max_value.strip_prefix("0x").unwrap_or(&config.max_value),
            16,
        )
        .unwrap_or(U256::from(u128::MAX));

        Self {
            evm: EvmState::new(),
            tests: Vec::new(),
            corpus: Vec::new(),
            dictionary: GenDict::new(seed),
            decoder: TraceDecoder::new(),
            config,
            rng: SmallRng::seed_from_u64(seed),
            call_count: 0,
            total_gas: 0,
            running: false,
            contract: None,
            fuzzable_funcs: Vec::new(),
            contract_addr: Address::ZERO,
            max_value,
            project: None,
            initial_snapshot: None,
            event_log: Vec::new(),
            last_reported_coverage: 0,
            last_gas_total: 0,
            last_gas_time_ms: 0.0,
            event_map: std::collections::HashMap::new(),
        }
    }

    /// Deploy a contract from a CompiledContract (artifact-based path).
    /// Handles library linking via FoundryProject if needed.
    pub fn deploy_contract(
        &mut self,
        contract_name: &str,
    ) -> Result<Address, String> {
        let deployer = crate::evm::exec::DEFAULT_DEPLOYER;
        let target_addr = crate::evm::exec::DEFAULT_CONTRACT_ADDR;

        // Register ABI with decoder BEFORE deploying so constructor failure traces are decoded
        // Use target_addr as placeholder — will be correct for CREATE2-style deploys
        if let Some(ref project) = self.project {
            if let Some(contract) = project.get_contract(contract_name) {
                self.decoder
                    .add_abi(target_addr, &contract.name, &contract.abi);
            }
            // Also register all other loaded contract ABIs (for cross-contract calls in constructor)
            for c in &project.contracts {
                if c.name != contract_name {
                    self.decoder.add_abi(Address::ZERO, &c.name, &c.abi);
                }
            }

            // Build metadata-to-codehash map BEFORE deployment (matches main fuzzer: config.rs:123)
            // This ensures library + constructor coverage uses proper metadata-based codehash
            let codehash_map = crate::evm::coverage::build_codehash_map(&project.contracts);
            self.evm.set_codehash_map(codehash_map);
        }

        // Get linked bytecode (deploy libraries if needed)
        let linked_bytecode = if let Some(ref mut project) = self.project {
            let contract = project
                .get_contract(contract_name)
                .ok_or_else(|| format!("Contract '{}' not found in loaded artifacts", contract_name))?;

            if contract.has_unlinked_libraries() {
                project.deploy_libraries_and_link(
                    &mut self.evm,
                    contract_name,
                    deployer,
                    Some(target_addr),
                )?
            } else {
                contract.bytecode.clone()
            }
        } else {
            return Err("No project loaded. Call load_artifacts first.".to_string());
        };

        // Deploy the main contract at the target address (matches main fuzzer's deploy_contract_at)
        let mut trace = self.evm.deploy_contract_at(deployer, target_addr, linked_bytecode, U256::ZERO);
        if !trace.success {
            // Use decoder for Foundry-style formatted trace output
            let decoded_trace = crate::evm::tracing::decoder::format_traces_decoded_with_state(
                &mut trace.arena, &mut self.decoder, self.evm.db_mut(), true,
            );
            return Err(format!(
                "Deploy failed: {}\n\n=== Constructor Trace ===\n{}",
                trace.error.as_deref().unwrap_or("unknown error"),
                decoded_trace,
            ));
        }

        let addr = target_addr;
        self.contract_addr = addr;

        // Set up contract data from CompiledContract
        let contract = self
            .project
            .as_ref()
            .and_then(|p| p.get_contract(contract_name))
            .cloned()
            .ok_or("Contract not found after deploy")?;

        // Re-register with actual deployed address (overrides placeholder)
        self.decoder.add_abi(addr, &contract.name, &contract.abi);
        self.fuzzable_funcs = contract.fuzzable_functions(false).into_iter().cloned().collect();
        self.contract = Some(contract);

        // Seed dictionary from deployed bytecode
        if let Some(account) = self.evm.db().cache.accounts.get(&addr) {
            if let Some(code) = &account.info.code {
                self.dictionary.seed_from_bytecode(code.bytes_slice());
            }
        }

        // Also seed from library bytecodes
        if let Some(ref project) = self.project {
            for (lib_addr, _lib_name) in project.get_deployed_library_addresses() {
                if let Some(account) = self.evm.db().cache.accounts.get(&lib_addr) {
                    if let Some(code) = &account.info.code {
                        self.dictionary.seed_from_bytecode(code.bytes_slice());
                    }
                }
            }
        }

        Ok(addr)
    }

    /// Deploy a contract from raw ABI JSON + bytecode hex.
    /// Creates a CompiledContract inline (same pipeline as artifact loading).
    pub fn deploy_raw(
        &mut self,
        name: &str,
        abi_json: &str,
        bytecode_hex: &str,
    ) -> Result<Address, String> {
        use alloy_dyn_abi::Specifier;
        use std::collections::HashMap;

        let abi: alloy_json_abi::JsonAbi =
            serde_json::from_str(abi_json).map_err(|e| format!("ABI parse error: {e}"))?;

        let bytecode_hex_clean = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);
        let bytecode_bytes =
            hex::decode(bytecode_hex_clean).map_err(|e| format!("bytecode hex error: {e}"))?;
        let bytecode = Bytes::from(bytecode_bytes);

        // Build function selector map and resolved param types
        let mut functions = HashMap::new();
        let mut resolved_param_types = HashMap::new();
        for func in abi.functions() {
            let selector = func.selector();
            functions.insert(selector, func.clone());
            let types: Vec<alloy_dyn_abi::DynSolType> = func
                .inputs
                .iter()
                .filter_map(|p| p.resolve().ok())
                .collect();
            resolved_param_types.insert(selector, types);
        }

        let contract = CompiledContract {
            name: name.to_string(),
            qualified_name: format!("manual:{}", name),
            abi: abi.clone(),
            bytecode: bytecode.clone(),
            deployed_bytecode: Bytes::new(), // not available for raw deploy
            functions,
            resolved_param_types,
            exclude_from_fuzzing: Vec::new(),
        };

        // Register ABI with decoder BEFORE deploying so constructor failure traces are decoded
        let deployer = crate::evm::exec::DEFAULT_DEPLOYER;
        let target_addr = crate::evm::exec::DEFAULT_CONTRACT_ADDR;
        self.decoder.add_abi(target_addr, &contract.name, &contract.abi);

        // Build metadata-to-codehash map BEFORE deployment (matches main fuzzer: config.rs:123)
        let codehash_map = crate::evm::coverage::build_codehash_map(&[contract.clone()]);
        self.evm.set_codehash_map(codehash_map);

        // Deploy at the target address (matches main fuzzer's deploy_contract_at)
        let mut trace = self.evm.deploy_contract_at(deployer, target_addr, bytecode, U256::ZERO);
        if !trace.success {
            let decoded_trace = crate::evm::tracing::decoder::format_traces_decoded_with_state(
                &mut trace.arena, &mut self.decoder, self.evm.db_mut(), true,
            );
            return Err(format!(
                "Deploy failed: {}\n\n=== Constructor Trace ===\n{}",
                trace.error.as_deref().unwrap_or("unknown error"),
                decoded_trace,
            ));
        }

        let addr = target_addr;
        self.contract_addr = addr;

        // Re-register with actual deployed address
        self.decoder.add_abi(addr, &contract.name, &contract.abi);
        self.fuzzable_funcs = contract.fuzzable_functions(false).into_iter().cloned().collect();
        self.contract = Some(contract);

        // Seed dictionary from deployed bytecode
        if let Some(account) = self.evm.db().cache.accounts.get(&addr) {
            if let Some(code) = &account.info.code {
                self.dictionary.seed_from_bytecode(code.bytes_slice());
            }
        }

        Ok(addr)
    }

    /// Set up tests from the loaded CompiledContract.
    /// Uses contract.echidna_tests() and contract.fuzzable_functions() — matches main fuzzer.
    pub fn setup_tests(&mut self, mode: TestMode) {
        let contract = match &self.contract {
            Some(c) => c,
            None => return,
        };

        let echidna_fns = contract.echidna_tests();
        let fuzzable = contract.fuzzable_functions(false);
        let fuzzable_sigs: Vec<(String, Vec<String>)> = fuzzable
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    f.inputs.iter().map(|p| p.ty.clone()).collect(),
                )
            })
            .collect();

        self.tests = create_tests(mode, self.contract_addr, &echidna_fns, &fuzzable_sigs);
        self.fuzzable_funcs = fuzzable.into_iter().cloned().collect();

        // Populate return_types for type-aware dictionary learning (rTypes)
        self.populate_return_types();

        // Build event_map for ABI-decoded event extraction (matches main fuzzer's Env.event_map)
        self.event_map.clear();
        if let Some(ref c) = self.contract {
            for event in c.abi.events() {
                self.event_map.insert(event.selector(), event.clone());
            }
        }

        // Take initial snapshot
        self.initial_snapshot = Some(self.evm.snapshot());
        self.running = true;
    }

    /// Populate return_types in dictionary for type-aware return value extraction.
    /// Matches main fuzzer's campaign.rs return_types population.
    fn populate_return_types(&mut self) {
        use alloy_dyn_abi::{DynSolType, Specifier};
        if let Some(ref contract) = self.contract {
            for func in contract.abi.functions() {
                if func.outputs.is_empty() {
                    continue;
                }
                // Build return type: single output -> that type, multiple -> tuple
                let output_types: Vec<DynSolType> = func.outputs.iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();
                if output_types.is_empty() {
                    continue;
                }
                let ty = if output_types.len() == 1 {
                    output_types.into_iter().next().unwrap()
                } else {
                    DynSolType::Tuple(output_types)
                };
                self.dictionary.return_types.insert(func.name.clone(), ty);
            }
        }
    }

    /// Run N fuzzing iterations. Returns JSON status.
    pub fn run_steps(&mut self, n: u32) -> CampaignStatus {
        if !self.running {
            return self.status();
        }

        for _ in 0..n {
            if !self.running {
                break;
            }

            // Check test limit
            if self.call_count >= self.config.test_limit {
                self.running = false;
                // Close optimization tests and run final shrinking
                self.close_and_shrink_optimization_tests();
                break;
            }

            self.fuzz_one_iteration();
        }

        // Shrink any failed tests
        self.shrink_pending_tests_worker();

        self.status()
    }

    /// Single fuzzing iteration
    fn fuzz_one_iteration(&mut self) {
        // Revert to initial state
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            // Re-take snapshot (revm consumes snapshots)
            self.initial_snapshot = Some(self.evm.snapshot());
        }

        // Use pre-cached param types from CompiledContract if available (matches main fuzzer)
        let param_types_lookup = self.contract.as_ref().map(|c| &c.resolved_param_types);

        // Generate sequence
        let seq = if self.corpus.is_empty() {
            // Fresh random sequence
            rand_seq(
                &mut self.rng,
                &self.dictionary,
                &self.fuzzable_funcs,
                self.contract_addr,
                self.config.seq_len,
                self.max_value,
                self.config.max_time_delay,
                self.config.max_block_delay,
                param_types_lookup,
            )
        } else {
            // Corpus-based mutation
            let generated = rand_seq(
                &mut self.rng,
                &self.dictionary,
                &self.fuzzable_funcs,
                self.contract_addr,
                self.config.seq_len,
                self.max_value,
                self.config.max_time_delay,
                self.config.max_block_delay,
                param_types_lookup,
            );

            let mutation = if self.config.seq_len > 1 {
                seq_mutators_stateful(&mut self.rng, DEFAULT_MUTATION_CONSTS)
            } else {
                seq_mutators_stateless(&mut self.rng, DEFAULT_MUTATION_CONSTS)
            };

            apply_corpus_mutation(
                &mut self.rng,
                mutation,
                self.config.seq_len,
                &self.corpus,
                &generated,
            )
        };

        if seq.is_empty() {
            return;
        }

        // Execute sequence and check tests after EVERY transaction
        let mut executed_seq = Vec::new();
        let mut any_new_coverage = false;

        for tx in &seq {
            // Apply delay
            self.evm.apply_delay(tx.delay);

            // Execute transaction with coverage tracking
            let (trace, has_new_cov) = self.evm.exec_tx_check_new_cov(
                tx.sender,
                tx.target,
                tx.calldata.clone(),
                tx.value,
            );

            self.call_count += 1;
            self.total_gas += trace.gas_used;
            executed_seq.push(tx.clone());

            if has_new_cov {
                any_new_coverage = true;
                // Add successful coverage-finding calls to wholeCalls dictionary
                if !tx.function_name.is_empty() && !tx.args.is_empty() {
                    self.dictionary.add_call((tx.function_name.clone(), tx.args.clone()));
                }
            }

            // Dictionary learning: extract values from return data, events, state diffs,
            // and created addresses (matches main fuzzer's execution.rs per-tx extraction)
            if trace.success {
                execution::extract_dict_from_tx(&self.evm, &mut self.dictionary, tx, &self.event_map);
            }

            // Check ALL tests after EVERY transaction (critical invariant)
            // Matches main fuzzer's testing/worker.rs pattern:
            // - PropertyTest/OptimizationTest: check via check_etest with VM CLONE (snapshot/revert)
            // - CallTest/AssertionTest: check directly on current VM state (no clone needed)
            let mut new_events: Vec<String> = Vec::new();

            for test in &mut self.tests {
                if !test.is_open() {
                    continue;
                }

                let test_name = test.test_type.name().to_string();
                let is_optimization = matches!(test.test_type, TestType::OptimizationTest { .. });
                let old_value = test.value.clone();

                let (test_value, passed) = match &test.test_type {
                    // PropertyTest and OptimizationTest: use snapshot/revert to isolate
                    // check_etest calls (it executes a tx that modifies VM state)
                    // Matches main fuzzer: `let mut check_vm = vm.clone();`
                    TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                        let check_snap = self.evm.snapshot();
                        let result = check_etest(&mut self.evm, test);
                        self.evm.revert_to(check_snap);
                        result
                    }
                    // CallTest and AssertionTest: check directly, no VM modification
                    TestType::CallTest { predicate, .. } => {
                        check_call_test_predicate(&self.evm, predicate)
                    }
                    TestType::AssertionTest { signature, addr } => {
                        check_assertion(&self.evm, signature, *addr)
                    }
                    _ => continue,
                };

                // For property tests and optimization tests, use update_open_test
                // Matches main fuzzer's testing/worker.rs pattern
                if matches!(test.test_type, TestType::PropertyTest { .. } | TestType::OptimizationTest { .. }) {
                    let test_updated = update_open_test(test, executed_seq.clone(), test_value.clone());

                    if test_updated {
                        if is_optimization {
                            new_events.push(format!(
                                "New maximum value of {}: {:?}",
                                test_name, test.value
                            ));
                            // Record functions that improved optimization as "hot"
                            // These will be weighted higher in future transaction generation
                            for etx in &executed_seq {
                                if !etx.function_name.is_empty() && !etx.args.is_empty() {
                                    self.dictionary.record_optimization_improving_function(&etx.function_name);
                                    self.dictionary.record_optimization_improving_values(&etx.args);
                                }
                            }
                        } else {
                            new_events.push(format!("Test {} falsified!", test_name));
                        }
                    }
                } else if !passed {
                    // CallTest/AssertionTest failure
                    if update_open_test(test, executed_seq.clone(), test_value) {
                        new_events.push(format!("Test {} falsified!", test_name));
                    }
                }
            }

            // Log collected events
            for event in new_events {
                self.event_log.push(event);
            }
        }

        // Add to corpus if new coverage found (matches main fuzzer's add_to_corpus_worker)
        if any_new_coverage && !executed_seq.is_empty() {
            self.corpus.push((10, executed_seq));
        }
    }

    /// Shrink pending (failed) tests — single-threaded port of campaign/src/shrink/core.rs
    ///
    /// Matches main fuzzer's shrink_test() → shrink_seq() exactly:
    /// 1. remove_reverts to eliminate reverting txs
    /// 2. Check if can_shrink_tx for single-tx sequences
    /// 3. Generate multiple candidates based on ShrinkMode (Sequence vs ValueOnly)
    ///    including generate_call_to_delay_candidates
    /// 4. Validate candidates and pick the best (shortest, then smallest complexity,
    ///    then smallest delay complexity)
    /// 5. Track mode switching via ShrinkContext
    fn shrink_pending_tests_worker(&mut self) {
        let shrink_limit = self.config.shrink_limit;

        for test_idx in 0..self.tests.len() {
            let shrink_count = match &self.tests[test_idx].state {
                TestState::Large(n) => *n,
                _ => continue,
            };

            let is_optimization = matches!(
                self.tests[test_idx].test_type,
                TestType::OptimizationTest { .. }
            );

            // Check shrink limit (optimization tests keep going)
            if shrink_count >= shrink_limit && !is_optimization {
                self.tests[test_idx].state = TestState::Solved;
                continue;
            }

            let current_reproducer = self.tests[test_idx].reproducer.clone();
            if current_reproducer.is_empty() {
                self.tests[test_idx].state = TestState::Solved;
                continue;
            }

            // Step 1: remove_reverts (removeReverts vm test.reproducer)
            let simplified = self.remove_reverts(&current_reproducer);
            let simplified = remove_useless_no_calls(simplified);

            // Stop shrinking when single tx — can't reduce further
            if simplified.len() <= 1 {
                self.tests[test_idx].state = TestState::Solved;
                self.tests[test_idx].reproducer = simplified;
                continue;
            }

            // Check if we can shrink further (length rr > 1 || any canShrinkTx rr)
            if simplified.len() > 1 || simplified.iter().any(can_shrink_tx) {
                // Try shrinking — matches shrink_seq()
                if let Some((new_repro, new_val)) =
                    self.shrink_seq(&simplified, test_idx)
                {
                    let new_complexity = calculate_value_complexity(&new_repro);
                    self.tests[test_idx].shrink_context.update(new_repro.len(), new_complexity);
                    self.tests[test_idx].reproducer = new_repro;
                    self.tests[test_idx].value = new_val;
                    self.tests[test_idx].state = TestState::Large(shrink_count + 1);
                } else {
                    // Shrink attempt failed — keep simplified, bump counter 
                    let complexity = calculate_value_complexity(&simplified);
                    self.tests[test_idx].shrink_context.update(simplified.len(), complexity);
                    self.tests[test_idx].reproducer = simplified;
                    self.tests[test_idx].state = TestState::Large(shrink_count + 1);
                }
            } else {
                // Can't shrink further (single non-shrinkable tx) — mark as Solved
                self.tests[test_idx].state = TestState::Solved;
                self.tests[test_idx].reproducer = simplified;
            }
        }
    }

    /// Shrink a transaction sequence.
    /// Matches main fuzzer's shrink_seq() exactly (serial, no Rayon).
    fn shrink_seq(
        &mut self,
        txs: &[Tx],
        test_idx: usize,
    ) -> Option<(Vec<Tx>, TestValue)> {
        if txs.is_empty() {
            return None;
        }

        let test_value = self.tests[test_idx].value.clone();
        let mode = self.tests[test_idx].shrink_context.mode;

        // Get sorted senders for shrinkSender 
        let mut sorted_senders: Vec<Address> = crate::evm::exec::DEFAULT_SENDERS.to_vec();
        sorted_senders.sort();

        let mut candidates: Vec<Vec<Tx>> = Vec::new();

        match mode {
            ShrinkMode::Sequence => {
                if txs.len() > 10 {
                    for _ in 0..3 {
                        candidates.push(multi_shorten_seq(&mut self.rng, txs));
                    }
                }
                let num_shorten = if txs.len() > 5 { 4 } else { 2 };
                for _ in 0..num_shorten {
                    candidates.push(shorten_seq(&mut self.rng, txs));
                }
                for _ in 0..2 {
                    let shrunk: Vec<Tx> = txs.iter().map(|tx| {
                        let t = shrink_tx(&mut self.rng, tx);
                        shrink_sender(&mut self.rng, &t, &sorted_senders)
                    }).collect();
                    candidates.push(shrunk);
                }
                generate_delay_candidates(&mut self.rng, txs, &mut candidates);
            }
            ShrinkMode::ValueOnly => {
                for _ in 0..2 {
                    candidates.push(shorten_seq(&mut self.rng, txs));
                }
                for _ in 0..8 {
                    let shrunk: Vec<Tx> = txs.iter().map(|tx| {
                        let t = shrink_tx(&mut self.rng, tx);
                        shrink_sender(&mut self.rng, &t, &sorted_senders)
                    }).collect();
                    candidates.push(shrunk);
                }
                generate_delay_candidates(&mut self.rng, txs, &mut candidates);
            }
        }

        // Call-to-delay conversion
        if txs.len() > 2 {
            generate_call_to_delay_candidates(
                &mut self.rng, txs,
                |candidate| {
                    if let Some(snap) = self.initial_snapshot {
                        self.evm.revert_to(snap);
                        self.initial_snapshot = Some(self.evm.snapshot());
                    }
                    for tx in candidate {
                        self.evm.apply_delay(tx.delay);
                        self.evm.exec_tx(tx.sender, tx.target, tx.calldata.clone(), tx.value);
                    }
                    let test = &self.tests[test_idx];
                    match &test.test_type {
                        TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                            let check_snap = self.evm.snapshot();
                            let (val, _passed) = check_etest(&mut self.evm, test);
                            self.evm.revert_to(check_snap);
                            matches!(val, TestValue::BoolValue(false))
                        }
                        _ => false,
                    }
                },
                &mut candidates,
            );
        }

        // Clean up candidates
        let candidates: Vec<Vec<Tx>> = candidates
            .into_iter()
            .map(remove_useless_no_calls)
            .collect();

        // Validate candidates serially and collect valid ones
        let valid_results: Vec<(Vec<Tx>, TestValue)> = candidates
            .into_iter()
            .filter_map(|candidate| {
                let (val, still_fails) = self.execute_and_check(&candidate, test_idx)?;
                if !still_fails {
                    return None;
                }
                match (&val, &test_value) {
                    (TestValue::BoolValue(false), _) => Some((candidate, val)),
                    (TestValue::IntValue(new), TestValue::IntValue(old)) if *new >= *old => {
                        Some((candidate, val))
                    }
                    _ => None,
                }
            })
            .collect();

        // Return best: shortest, then smallest value complexity, then smallest delay complexity
        valid_results.into_iter().min_by(|(txs_a, _), (txs_b, _)| {
            let len_cmp = txs_a.len().cmp(&txs_b.len());
            if len_cmp != std::cmp::Ordering::Equal {
                return len_cmp;
            }
            let val_cmp = calculate_value_complexity(txs_a).cmp(&calculate_value_complexity(txs_b));
            if val_cmp != std::cmp::Ordering::Equal {
                return val_cmp;
            }
            calculate_delay_complexity(txs_a).cmp(&calculate_delay_complexity(txs_b))
        })
    }

    /// Remove reverting transactions from the sequence.
    /// Matches main fuzzer's remove_reverts(): execute txs, replace reverts with NoCalls.
    /// Also removes view/pure calls (they don't modify state).
    fn remove_reverts(&mut self, txs: &[Tx]) -> Vec<Tx> {
        if txs.is_empty() {
            return Vec::new();
        }

        // Revert to initial state for execution
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            self.initial_snapshot = Some(self.evm.snapshot());
        }

        let (init, last) = txs.split_at(txs.len() - 1);
        let mut result = Vec::with_capacity(txs.len());

        for tx in init {
            // Check if this is a view/pure function (check contract ABI)
            let is_view_pure = self.contract.as_ref().map_or(false, |c| {
                if tx.selector == [0; 4] {
                    return false;
                }
                let sel = alloy_primitives::FixedBytes::<4>::from(tx.selector);
                c.functions.get(&sel).map_or(false, |f| {
                    matches!(
                        f.state_mutability,
                        alloy_json_abi::StateMutability::View
                            | alloy_json_abi::StateMutability::Pure
                    )
                })
            });

            if is_view_pure || tx.is_no_call() {
                // Pure/view calls or NoCalls: keep delay, remove call
                result.push(Tx::no_call(tx.sender, tx.target, tx.delay));
            } else {
                // Execute and check for revert
                self.evm.apply_delay(tx.delay);
                let trace = self.evm.exec_tx(
                    tx.sender,
                    tx.target,
                    tx.calldata.clone(),
                    tx.value,
                );
                if !trace.success {
                    // Replace with NoCall but keep delay (replaceByNoCall)
                    result.push(Tx::no_call(tx.sender, tx.target, tx.delay));
                } else {
                    result.push(tx.clone());
                }
            }
        }

        // Keep the last transaction as-is (it's the one that triggers the failure)
        result.extend(last.iter().cloned());
        result
    }

    /// Execute sequence and check test result.
    /// Returns (TestValue, is_valid) — matches main fuzzer's execute_and_check().
    fn execute_and_check(
        &mut self,
        seq: &[Tx],
        test_idx: usize,
    ) -> Option<(TestValue, bool)> {
        // Revert to initial state
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            self.initial_snapshot = Some(self.evm.snapshot());
        }

        // Execute all transactions in order
        for tx in seq {
            self.evm.apply_delay(tx.delay);
            self.evm.exec_tx(tx.sender, tx.target, tx.calldata.clone(), tx.value);
        }

        // Check the test — use snapshot/revert for PropertyTest/OptimizationTest
        let test = &self.tests[test_idx];
        let (test_value, passed) = match &test.test_type {
            TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                let check_snap = self.evm.snapshot();
                let result = check_etest(&mut self.evm, test);
                self.evm.revert_to(check_snap);
                result
            }
            TestType::CallTest { predicate, .. } => {
                check_call_test_predicate(&self.evm, predicate)
            }
            TestType::AssertionTest { signature, addr } => {
                check_assertion(&self.evm, signature, *addr)
            }
            _ => {
                return None;
            }
        };

        Some((test_value, !passed))
    }

    /// Close open optimization tests and run final shrinking.
    /// Called when campaign finishes (test_limit reached) or user stops.
    /// Matches main fuzzer's close_and_shrink_optimization_tests().
    pub fn close_and_shrink_optimization_tests(&mut self) {
        // Close any open optimization tests → Large(0) for shrinking
        for test in &mut self.tests {
            if test.is_open() {
                if matches!(test.test_type, TestType::OptimizationTest { .. }) {
                    if !test.reproducer.is_empty() {
                        test.state = TestState::Large(0);
                        test.worker_id = Some(0);
                    } else {
                        test.state = TestState::Passed;
                    }
                } else {
                    test.state = TestState::Passed;
                }
            }
        }

        // Count shrinkable tests and log
        let shrinkable: Vec<String> = self.tests.iter()
            .filter(|t| matches!(t.state, TestState::Large(_)))
            .map(|t| t.test_type.name().to_string())
            .collect();
        if !shrinkable.is_empty() {
            self.event_log.push(format!("Shrinking {} test(s): {}", shrinkable.len(), shrinkable.join(", ")));
        }

        // Run shrinking until all tests are solved or limit reached
        // Matches campaign.rs: loop { shrink_pending_tests_worker_worker } until done
        let shrink_limit = self.config.shrink_limit;
        let mut last_report_step: i32 = 0;
        loop {
            let has_shrinkable = self.tests.iter().any(|t| {
                matches!(t.state, TestState::Large(n) if n < shrink_limit)
            });
            if !has_shrinkable {
                break;
            }
            self.shrink_pending_tests_worker();

            // Report shrink progress periodically (every 200 steps)
            let max_step: i32 = self.tests.iter()
                .filter_map(|t| if let TestState::Large(n) = t.state { Some(n) } else { None })
                .max()
                .unwrap_or(0);
            if max_step - last_report_step >= 200 {
                let progress: Vec<String> = self.tests.iter()
                    .filter_map(|t| {
                        if let TestState::Large(n) = t.state {
                            Some(format!("{}: {}/{} (len {})", t.test_type.name(), n, shrink_limit, t.reproducer.len()))
                        } else {
                            None
                        }
                    })
                    .collect();
                if !progress.is_empty() {
                    self.event_log.push(format!("Shrinking: {}", progress.join(", ")));
                }
                last_report_step = max_step;
            }
        }

        // Log final shrink results
        for test in &self.tests {
            if matches!(test.state, TestState::Solved) && !test.reproducer.is_empty() {
                self.event_log.push(format!(
                    "{}: shrunk to {} tx(s)",
                    test.test_type.name(),
                    test.reproducer.len()
                ));
            }
        }
    }

    /// Get final results with traces for all failed/shrunk tests.
    /// Matches main fuzzer's CLI output (cli/src/main.rs:1438).
    pub fn format_final_results(&mut self) -> String {
        let mut output = String::new();
        let contract_name = self
            .contract
            .as_ref()
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "Contract".to_string());

        let tests_snapshot = self.tests.clone();
        let shrink_limit = self.config.shrink_limit;

        for test in &tests_snapshot {
            let test_name = test.test_type.name();
            let is_optimization = matches!(test.test_type, TestType::OptimizationTest { .. });

            match &test.state {
                TestState::Passed | TestState::Open => {
                    if is_optimization {
                        if let TestValue::IntValue(v) = &test.value {
                            output.push_str(&format!("{}(): max value: {}\n", test_name, v));
                            if !test.reproducer.is_empty() {
                                self.format_call_sequence(&mut output, &test.reproducer, &contract_name);
                            }
                        } else {
                            output.push_str(&format!("{}(): passing\n", test_name));
                        }
                    } else {
                        output.push_str(&format!("{}(): passing\n", test_name));
                    }
                }
                TestState::Solved => {
                    if is_optimization {
                        if let TestValue::IntValue(v) = &test.value {
                            output.push_str(&format!("{}(): max value: {}\n", test_name, v));
                        } else {
                            output.push_str(&format!("{}(): failed!\n", test_name));
                        }
                    } else {
                        output.push_str(&format!("{}(): failed!\n", test_name));
                    }
                    let repro = test.reproducer.clone();
                    self.format_call_sequence(&mut output, &repro, &contract_name);

                    // Print detailed traces for the falsified sequence
                    if !is_optimization && !repro.is_empty() {
                        output.push_str("Traces:\n");
                        self.format_traces_for_seq(&mut output, &repro, &contract_name);
                    }
                }
                TestState::Large(n) => {
                    if is_optimization {
                        if let TestValue::IntValue(v) = &test.value {
                            output.push_str(&format!(
                                "{}(): max value: {} (shrinking {}/{})\n",
                                test_name, v, n, shrink_limit
                            ));
                        } else {
                            output.push_str(&format!("{}(): failed!\n", test_name));
                            output.push_str(&format!(
                                "  Call sequence, shrinking {}/{}:\n",
                                n, shrink_limit
                            ));
                        }
                    } else {
                        output.push_str(&format!("{}(): failed!\n", test_name));
                        output.push_str(&format!(
                            "  Call sequence, shrinking {}/{}:\n",
                            n, shrink_limit
                        ));
                    }
                    let repro = test.reproducer.clone();
                    self.format_call_sequence(&mut output, &repro, &contract_name);

                    // Print detailed traces even while shrinking
                    if !is_optimization && !repro.is_empty() {
                        output.push_str("Traces:\n");
                        self.format_traces_for_seq(&mut output, &repro, &contract_name);
                    }
                }
                TestState::Failed(e) => {
                    output.push_str(&format!("{}(): could not evaluate\n  {}\n", test_name, e));
                }
            }
        }

        // Coverage stats (matches main fuzzer: cli/src/main.rs:1530-1538)
        let (cov_points, num_codehashes) = crate::evm::coverage::coverage_stats(&self.evm.init_coverage, &self.evm.coverage);
        output.push_str(&format!(
            "\nUnique instructions: {}\nUnique codehashes: {}\n",
            cov_points, num_codehashes
        ));

        output
    }

    /// Format call sequence (Echidna-compatible format)
    fn format_call_sequence(
        &self,
        output: &mut String,
        txs: &[Tx],
        contract_name: &str,
    ) {
        if txs.is_empty() {
            output.push_str("  (no transactions)\n");
            return;
        }
        output.push_str("  Call sequence:\n");
        for tx in txs {
            if tx.is_no_call() {
                output.push_str(&format!(
                    "    *wait* {} seconds, {} blocks\n",
                    tx.delay.0, tx.delay.1
                ));
            } else {
                let decoded_call = self.decoder.decode_calldata(&hex::encode(&tx.calldata));
                let sender_label = self.decoder.resolve_address(&tx.sender);
                let mut line = format!("    {}.{}", contract_name, decoded_call);
                if !tx.value.is_zero() {
                    line.push_str(&format!(" Value: 0x{:x}", tx.value));
                }
                line.push_str(&format!(" from: {}", sender_label));
                if tx.delay.0 > 0 {
                    line.push_str(&format!(" Time delay: {} seconds", tx.delay.0));
                }
                if tx.delay.1 > 0 {
                    line.push_str(&format!(" Block delay: {}", tx.delay.1));
                }
                line.push('\n');
                output.push_str(&line);
            }
        }
    }

    /// Replay and format traces for a sequence (matches main fuzzer's print_traces)
    fn format_traces_for_seq(
        &mut self,
        output: &mut String,
        txs: &[Tx],
        contract_name: &str,
    ) {
        // Revert to initial state
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            self.initial_snapshot = Some(self.evm.snapshot());
        }

        for (i, tx) in txs.iter().enumerate() {
            // Format header
            if tx.is_no_call() {
                output.push_str(&format!(
                    "  [{}] *wait* {} seconds, {} blocks\n",
                    i, tx.delay.0, tx.delay.1
                ));
                self.evm.apply_delay(tx.delay);
                continue;
            }

            let decoded_call = self.decoder.decode_calldata(&hex::encode(&tx.calldata));
            let sender_label = self.decoder.resolve_address(&tx.sender);
            output.push_str(&format!(
                "  [{}] {}.{} from: {}\n",
                i, contract_name, decoded_call, sender_label
            ));

            // Execute with tracing
            self.evm.apply_delay(tx.delay);
            let mut trace = self.evm.exec_tx(
                tx.sender,
                tx.target,
                tx.calldata.clone(),
                tx.value,
            );

            // Show decoded trace tree (Foundry-style via TraceWriter)
            let decoded_trace = crate::evm::tracing::decoder::format_traces_decoded_with_state(
                &mut trace.arena, &mut self.decoder, self.evm.db_mut(), true,
            );
            if !decoded_trace.is_empty() {
                for line in decoded_trace.lines() {
                    output.push_str(&format!("    {}\n", line));
                }
            }
        }
    }

    /// Update test states from coordinator's merged results and format final output.
    /// Called by coordinator after all workers finish, to get proper traces.
    pub fn set_merged_results_and_format(&mut self, merged_json: &str) -> Result<String, String> {
        #[derive(Deserialize)]
        struct MergedTest {
            name: String,
            state: String,
            value: Option<String>,
            reproducer: Option<Vec<Tx>>,
        }

        let merged: Vec<MergedTest> = serde_json::from_str(merged_json)
            .map_err(|e| format!("parse merged: {e}"))?;

        // Update tests with merged results
        for m in &merged {
            if let Some(test) = self.tests.iter_mut().find(|t| t.test_type.name() == m.name) {
                test.state = parse_status_string_to_state(&m.state);
                if let Some(ref v) = m.value {
                    if let Ok(int_val) = v.parse::<alloy_primitives::I256>() {
                        test.value = TestValue::IntValue(int_val);
                    }
                }
                if let Some(ref repro) = m.reproducer {
                    test.reproducer = repro.clone();
                }
            }
        }

        Ok(self.format_final_results())
    }

    /// Log an event message (Echidna-style progress reporting)
    fn log_event(&mut self, msg: String) {
        self.event_log.push(msg);
    }

    /// Get current fuzzer status (drains events)
    pub fn status(&mut self) -> CampaignStatus {
        // Build status line event (Echidna format)
        let tests_failed = self
            .tests
            .iter()
            .filter(|t| t.state.did_fail())
            .count();
        let total_tests = self.tests.len();
        let (cov, num_codehashes) = crate::evm::coverage::coverage_stats(&self.evm.init_coverage, &self.evm.coverage);

        // Collect optimization values (matches main fuzzer: i128 conversion)
        let opt_values: Vec<i128> = self
            .tests
            .iter()
            .filter_map(|t| {
                if matches!(t.test_type, TestType::OptimizationTest { .. }) {
                    if let TestValue::IntValue(v) = &t.value {
                        let val: i128 = (*v).try_into().unwrap_or_else(|_| {
                            if v.is_negative() { i128::MIN } else { i128::MAX }
                        });
                        Some(val)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Collect shrinking info
        let shrinking_info: Vec<String> = self
            .tests
            .iter()
            .filter_map(|t| {
                if let TestState::Large(n) = &t.state {
                    Some(format!(
                        "{}/{}({})",
                        n,
                        self.config.shrink_limit,
                        t.reproducer.len()
                    ))
                } else {
                    None
                }
            })
            .collect();

        // Build status line (matches main fuzzer's output::print_status format)
        let shrinking_part = if shrinking_info.is_empty() {
            String::new()
        } else {
            format!(", shrinking: {}", shrinking_info.join(" "))
        };

        // Calculate gas/s (delta-based, matches main fuzzer's campaign.rs:683-692)
        let now_ms = js_sys::Date::now();
        let delta_gas = self.total_gas.saturating_sub(self.last_gas_total);
        let delta_time_s = (now_ms - self.last_gas_time_ms) / 1000.0;
        let gas_per_second = if delta_time_s > 0.5 {
            (delta_gas as f64 / delta_time_s) as u64
        } else {
            0
        };
        self.last_gas_total = self.total_gas;
        self.last_gas_time_ms = now_ms;

        let status_line = format!(
            "[status] tests: {}/{}, fuzzing: {}/{}, values: {:?}, cov: {}, corpus: {}{}, gas/s: {}",
            tests_failed,
            total_tests,
            self.call_count,
            self.config.test_limit,
            opt_values,
            cov,
            self.corpus.len(),
            shrinking_part,
            gas_per_second,
        );

        // Report new coverage if changed
        if cov > self.last_reported_coverage {
            self.log_event(format!(
                "New coverage: {} instr, {} contracts, {} seqs in corpus",
                cov, num_codehashes, self.corpus.len()
            ));
            self.last_reported_coverage = cov;
        }

        // Drain events
        let mut events = std::mem::take(&mut self.event_log);
        events.insert(0, status_line);

        CampaignStatus {
            call_count: self.call_count,
            corpus_size: self.corpus.len(),
            coverage_points: cov,
            tests: self.tests.iter().map(TestStatus::from).collect(),
            events,
            running: self.running,
        }
    }

    /// Stop the fuzzer — close optimization tests and run final shrinking
    pub fn stop(&mut self) {
        self.running = false;
        self.close_and_shrink_optimization_tests();
    }

    /// Get formatted traces for a test's reproducer.
    /// Re-executes each tx with full tracing (matches main fuzzer's print_traces).
    pub fn format_reproducer(&mut self, test_idx: usize) -> String {
        if test_idx >= self.tests.len() {
            return String::new();
        }
        let test = &self.tests[test_idx];
        let mut output = format!(
            "Test: {} ({})\n",
            test.test_type.name(),
            if test.state.is_solved() {
                "FAILED"
            } else if test.state.is_shrinking() {
                "shrinking"
            } else {
                "open"
            }
        );
        output.push_str(&format!("Reproducer ({} txs):\n", test.reproducer.len()));

        let reproducer = test.reproducer.clone();

        // Revert to initial state to replay
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            self.initial_snapshot = Some(self.evm.snapshot());
        }

        let contract_name = self
            .contract
            .as_ref()
            .map(|c| c.name.as_str())
            .unwrap_or("Contract");

        for (i, tx) in reproducer.iter().enumerate() {
            // Format header: [i] ContractName::function(args) from sender
            let decoded_call = self.decoder.decode_calldata(&hex::encode(&tx.calldata));
            let sender_label = self.decoder.resolve_address(&tx.sender);
            output.push_str(&format!(
                "\n  [{}] {contract_name}::{decoded_call} from: {sender_label}",
                i,
            ));
            if tx.delay.0 > 0 || tx.delay.1 > 0 {
                output.push_str(&format!(
                    " [delay: {} secs, {} blocks]",
                    tx.delay.0, tx.delay.1
                ));
            }
            if !tx.value.is_zero() {
                output.push_str(&format!(" {{value: {}}}", tx.value));
            }
            output.push('\n');

            // Apply delay and re-execute with tracing
            self.evm.apply_delay(tx.delay);
            let mut trace = self.evm.exec_tx(
                tx.sender,
                tx.target,
                tx.calldata.clone(),
                tx.value,
            );

            // Show decoded trace tree (Foundry-style via TraceWriter)
            let decoded_trace = crate::evm::tracing::decoder::format_traces_decoded_with_state(
                &mut trace.arena, &mut self.decoder, self.evm.db_mut(), true,
            );
            if !decoded_trace.is_empty() {
                for line in decoded_trace.lines() {
                    output.push_str(&format!("    {}\n", line));
                }
            }
        }

        output
    }

    // =====================================================================
    // Multi-worker support — export/import/batch/sync
    // Matches main fuzzer's WorkerEnv pattern (campaign/src/worker_env.rs)
    // =====================================================================

    /// Export the current EVM state + contract info for cloning to workers.
    /// Called by coordinator after deploy + setUp to create worker snapshots.
    /// Matches main fuzzer's pattern of cloning EvmState to each worker thread.
    pub fn export_state(&self) -> Result<ExportedState, String> {
        let contract = self.contract.as_ref()
            .ok_or("No contract deployed")?;

        // Serialize all accounts from CacheDB
        let mut accounts = Vec::new();
        for (addr, account) in &self.evm.db().cache.accounts {
            let code_hex = account.info.code.as_ref()
                .map(|c| hex::encode(c.bytes_slice()))
                .unwrap_or_default();
            let storage: Vec<(String, String)> = account.storage.iter()
                .map(|(k, v)| (format!("{k:#066x}"), format!("{v:#066x}")))
                .collect();
            accounts.push(ExportedAccount {
                address: format!("{addr:?}"),
                balance: format!("{:#066x}", account.info.balance),
                nonce: account.info.nonce,
                code: code_hex,
                storage,
            });
        }

        // Serialize coverage (both init + runtime, so workers start with deployment coverage)
        let coverage: Vec<CoverageEntry> = self.evm.init_coverage.iter()
            .chain(self.evm.coverage.iter())
            .flat_map(|(codehash, pcs)| {
                pcs.iter().map(move |(pc, (depth, result))| CoverageEntry {
                    codehash: format!("{codehash:?}"),
                    pc: *pc,
                    depth_bits: *depth,
                    result_bits: *result,
                })
            })
            .collect();

        // Serialize fuzzable functions
        let fuzzable_funcs_json = serde_json::to_string(&contract.fuzzable_functions(false)
            .iter()
            .map(|f| serde_json::to_value(f).unwrap_or_default())
            .collect::<Vec<_>>())
            .unwrap_or_default();

        let tests_json = serde_json::to_string(&self.tests)
            .map_err(|e| format!("serialize tests: {e}"))?;

        let abi_json = serde_json::to_string(&contract.abi)
            .unwrap_or_default();

        // Serialize codehash map for workers
        let mut codehash_map_entries = Vec::new();
        if let Some(ref project) = self.project {
            let map = crate::evm::coverage::build_codehash_map(&project.contracts);
            for (metadata_hash, entries) in &map {
                for &(bytecode_len, compile_codehash) in entries {
                    codehash_map_entries.push(CodehashMapEntry {
                        metadata_hash: format!("{metadata_hash:?}"),
                        bytecode_len,
                        compile_codehash: format!("{compile_codehash:?}"),
                    });
                }
            }
        }

        Ok(ExportedState {
            accounts,
            block_number: self.evm.block_number,
            timestamp: self.evm.timestamp,
            coverage,
            contract_name: contract.name.clone(),
            contract_addr: format!("{:?}", self.contract_addr),
            fuzzable_funcs_json,
            config: self.config.clone(),
            tests_json,
            abi_json,
            codehash_map: codehash_map_entries,
        })
    }

    /// Import state from coordinator. Restores EVM state, contract info, tests.
    /// Called by each fuzzer worker on init.
    /// Matches main fuzzer's WorkerEnv construction pattern.
    pub fn import_state(&mut self, state: &ExportedState, worker_id: usize, seed: u64) -> Result<(), String> {
        // Reset EVM
        self.evm = crate::evm::exec::EvmState::new();

        // Restore accounts
        for account in &state.accounts {
            let addr: Address = account.address.parse()
                .map_err(|e| format!("parse addr: {e}"))?;
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
            self.evm.db_mut().insert_account_info(addr, info);

            // Restore storage
            for (slot_hex, val_hex) in &account.storage {
                let slot = U256::from_str_radix(
                    slot_hex.strip_prefix("0x").unwrap_or(slot_hex), 16
                ).unwrap_or(U256::ZERO);
                let val = U256::from_str_radix(
                    val_hex.strip_prefix("0x").unwrap_or(val_hex), 16
                ).unwrap_or(U256::ZERO);
                self.evm.set_storage(addr, slot, val);
            }
        }

        // Restore block state
        self.evm.block_number = state.block_number;
        self.evm.timestamp = state.timestamp;

        // Restore coverage into init_coverage (matches main fuzzer: workers get deployment PCs
        // in coverage_ref_init, and start with empty coverage_ref_runtime).
        // During fuzzing, deployment PCs will be "rediscovered" and added to runtime coverage too.
        // coverage_stats(init, runtime) then matches the main fuzzer's counting.
        for entry in &state.coverage {
            let codehash: B256 = entry.codehash.parse()
                .map_err(|e| format!("parse codehash: {e}"))?;
            let contract_cov = self.evm.init_coverage.entry(codehash).or_default();
            let e = contract_cov.entry(entry.pc).or_insert((0, 0));
            e.0 |= entry.depth_bits;
            e.1 |= entry.result_bits;
        }

        // Restore contract addr
        self.contract_addr = state.contract_addr.parse()
            .map_err(|e| format!("parse contract_addr: {e}"))?;

        // Restore tests
        self.tests = serde_json::from_str(&state.tests_json)
            .map_err(|e| format!("parse tests: {e}"))?;

        // Restore config
        self.config = state.config.clone();

        // Set up RNG with worker-specific seed (matches main fuzzer: seed + worker_id)
        self.rng = SmallRng::seed_from_u64(seed.wrapping_add(worker_id as u64));
        self.dictionary = GenDict::new(seed.wrapping_add(worker_id as u64));

        // Restore fuzzable functions from ABI
        let abi: alloy_json_abi::JsonAbi = serde_json::from_str(&state.abi_json)
            .map_err(|e| format!("parse abi: {e}"))?;
        self.fuzzable_funcs = abi.functions()
            .filter(|f| {
                let name = &f.name;
                !name.starts_with("echidna_")
                    && !name.starts_with("optimize_")
                    && name != "setUp"
            })
            .cloned()
            .collect();

        // Set up decoder
        self.decoder.add_abi(self.contract_addr, &state.contract_name, &abi);

        // Build resolved_param_types for fuzzable_funcs
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

        // Create CompiledContract (lightweight, for param type lookup)
        self.contract = Some(CompiledContract {
            name: state.contract_name.clone(),
            qualified_name: format!("worker:{}", state.contract_name),
            abi,
            bytecode: Bytes::new(),
            deployed_bytecode: Bytes::new(),
            functions,
            resolved_param_types,
            exclude_from_fuzzing: Vec::new(),
        });

        // Restore codehash map from exported state
        let mut codehash_map: crate::evm::coverage::MetadataToCodehash = std::collections::HashMap::new();
        for entry in &state.codehash_map {
            let metadata_hash: B256 = entry.metadata_hash.parse()
                .map_err(|e| format!("parse metadata_hash: {e}"))?;
            let compile_codehash: B256 = entry.compile_codehash.parse()
                .map_err(|e| format!("parse compile_codehash: {e}"))?;
            codehash_map.entry(metadata_hash)
                .or_insert_with(Vec::new)
                .push((entry.bytecode_len, compile_codehash));
        }
        self.evm.set_codehash_map(codehash_map);

        // Seed dictionary from deployed bytecode
        if let Some(account) = self.evm.db().cache.accounts.get(&self.contract_addr) {
            if let Some(code) = &account.info.code {
                self.dictionary.seed_from_bytecode(code.bytes_slice());
            }
        }

        // Populate return_types for type-aware dictionary learning
        self.populate_return_types();

        let max_value = U256::from_str_radix(
            self.config.max_value.strip_prefix("0x").unwrap_or(&self.config.max_value), 16
        ).unwrap_or(U256::from(u128::MAX));
        self.max_value = max_value;

        // Take initial snapshot
        self.initial_snapshot = Some(self.evm.snapshot());
        self.running = true;
        self.call_count = 0;
        self.last_reported_coverage = crate::evm::coverage::coverage_stats(&self.evm.init_coverage, &self.evm.coverage).0;

        Ok(())
    }

    /// Run N iterations and return deltas (not full status).
    /// Called by fuzzer workers in their batch loop.
    /// Matches main fuzzer's run_fuzz_worker() batch pattern.
    pub fn run_batch(&mut self, n: u32, worker_id: usize) -> WorkerDelta {
        let cov_before = self.evm.coverage.clone();
        let corpus_len_before = self.corpus.len();
        let call_count_before = self.call_count;

        // Snapshot test states before batch (to detect changes)
        let tests_before: Vec<(String, usize)> = self.tests.iter()
            .map(|t| (test_state_to_status_string(&t.state), t.reproducer.len()))
            .collect();

        // Run iterations (matches campaign.rs main loop)
        let mut limit_reached = false;
        for _ in 0..n {
            if !self.running {
                break;
            }

            // Prioritize shrinking (matches campaign.rs: any_pending_shrink -> shrink -> continue)
            if self.tests.iter().any(|t| t.is_shrinkable()) {
                self.shrink_pending_tests_worker();
                continue;
            }

            // Check test limit (matches campaign.rs: ncalls >= per_worker_limit)
            if self.call_count >= self.config.test_limit {
                self.running = false;
                limit_reached = true;
                break;
            }

            // Check if all tests complete (matches campaign.rs: all_tests_complete -> stop)
            let all_complete = !self.tests.is_empty() && self.tests.iter().all(|t| {
                matches!(t.state, TestState::Passed | TestState::Solved | TestState::Failed(_))
            });
            if all_complete {
                self.running = false;
                break;
            }

            self.fuzz_one_iteration();
        }

        // If test limit reached, run full finalization + shrinking
        // Matches campaign.rs: close_and_shrink_optimization_tests at test limit
        if limit_reached {
            self.close_and_shrink_optimization_tests();
        }

        // Compute deltas
        let call_count_delta = self.call_count - call_count_before;

        // Coverage delta: new entries not in cov_before
        let mut coverage_delta = Vec::new();
        for (codehash, pcs) in &self.evm.coverage {
            let old_pcs = cov_before.get(codehash);
            for (pc, (depth, result)) in pcs {
                let (old_depth, old_result) = old_pcs
                    .and_then(|m| m.get(pc))
                    .copied()
                    .unwrap_or((0, 0));
                let new_depth = *depth & !old_depth;
                let new_result = *result & !old_result;
                if new_depth != 0 || new_result != 0 {
                    coverage_delta.push(CoverageEntry {
                        codehash: format!("{codehash:?}"),
                        pc: *pc,
                        depth_bits: new_depth,
                        result_bits: new_result,
                    });
                }
            }
        }

        // New corpus entries
        let new_corpus: Vec<Vec<Tx>> = self.corpus[corpus_len_before..]
            .iter()
            .map(|(_, txs)| txs.clone())
            .collect();

        // Test updates: only report tests that CHANGED since batch start
        let mut test_updates = Vec::new();
        for (idx, test) in self.tests.iter().enumerate() {
            let current_state = test_state_to_status_string(&test.state);
            let (before_state, before_repro_len) = &tests_before[idx];
            // Report if state changed OR reproducer length changed (shrink progress)
            if current_state != *before_state || test.reproducer.len() != *before_repro_len {
                test_updates.push(TestUpdate {
                    test_idx: idx,
                    state: current_state,
                    value: test.value.clone(),
                    reproducer: test.reproducer.clone(),
                });
            }
        }

        // New dictionary values
        let dict_values: Vec<String> = self.dictionary.dict_values.iter()
            .take(50) // limit to avoid huge messages
            .map(|v| format!("{v:#066x}"))
            .collect();

        // Drain events
        let events = std::mem::take(&mut self.event_log);

        WorkerDelta {
            worker_id,
            new_corpus,
            coverage_delta,
            test_updates,
            call_count_delta,
            dict_values,
            events,
        }
    }

    /// Apply merged state from coordinator.
    /// Updates corpus, coverage stats, test states, and COVERAGE MAP from other workers.
    /// Matches main fuzzer's pattern of syncing shared state to workers.
    pub fn apply_sync(&mut self, sync: &StateSync) {
        // Add new corpus entries from other workers
        for entry in &sync.new_corpus {
            self.corpus.push((10, entry.clone()));
        }

        // Merge coverage delta from other workers into local coverage map
        // (CRITICAL: without this, workers independently rediscover same coverage → corpus inflation)
        for entry in &sync.coverage_delta {
            if let Ok(codehash) = entry.codehash.parse::<B256>() {
                let contract_cov = self.evm.coverage.entry(codehash).or_default();
                let e = contract_cov.entry(entry.pc).or_insert((0, 0));
                e.0 |= entry.depth_bits;
                e.1 |= entry.result_bits;
            }
        }

        // Apply test updates from coordinator (other workers may have found failures)
        for test_entry in &sync.tests {
            if test_entry.test_idx < self.tests.len() {
                let test = &mut self.tests[test_entry.test_idx];
                let coord_state = parse_status_string_to_state(&test_entry.state);
                // Only update if coordinator has better state
                match (&test.state, &coord_state) {
                    // If we're open and coordinator says failed, accept
                    (TestState::Open, TestState::Large(_) | TestState::Solved) => {
                        test.state = coord_state;
                        test.value = test_entry.value.clone();
                        test.reproducer = test_entry.reproducer.clone();
                    }
                    // If coordinator has shorter reproducer while shrinking, accept
                    (TestState::Large(_), TestState::Large(_) | TestState::Solved) => {
                        if test_entry.reproducer.len() < test.reproducer.len()
                            || matches!(coord_state, TestState::Solved)
                        {
                            test.state = coord_state;
                            test.value = test_entry.value.clone();
                            test.reproducer = test_entry.reproducer.clone();
                        }
                    }
                    // Optimization: accept better values
                    (_, _) => {
                        if let (TestValue::IntValue(new_v), TestValue::IntValue(old_v)) =
                            (&test_entry.value, &test.value)
                        {
                            if *new_v > *old_v {
                                test.value = test_entry.value.clone();
                                test.reproducer = test_entry.reproducer.clone();
                            }
                        }
                    }
                }
            }
        }

        // Add dictionary values from other workers
        for val_hex in &sync.dict_values {
            if let Ok(v) = U256::from_str_radix(
                val_hex.strip_prefix("0x").unwrap_or(val_hex), 16
            ) {
                self.dictionary.dict_values.insert(v);
            }
        }
    }
}