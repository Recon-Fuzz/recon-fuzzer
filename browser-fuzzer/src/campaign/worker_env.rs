//! Worker-local environment for fuzzing threads
//!
//! Browser-fuzzer equivalent of campaign/src/worker_env.rs.
//! Uses wasm_safe_mutex::RwLock instead of parking_lot::RwLock for WASM SharedArrayBuffer support.
//!
//! Architecture (mirrors main fuzzer exactly):
//!   - SharedState: holds all shared data behind wasm_safe_mutex::RwLock
//!   - WorkerEnv: per-worker struct with Arc<SharedState> + worker-local EVM, RNG, dictionary
//!   - Workers read/write shared state through lock_sync_read()/lock_sync_write()

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

use alloy_json_abi::Function;
use alloy_primitives::{Address, B256, Bytes, U256};
use rand::prelude::*;
use rand::rngs::SmallRng;
use rand::SeedableRng;
use wasm_safe_mutex::rwlock::RwLock;

use crate::abi::types::GenDict;
use crate::evm::coverage::{CoverageMap, MetadataToCodehash};
use crate::evm::exec::EvmState;
use crate::evm::foundry::CompiledContract;
use crate::evm::tracing::decoder::TraceDecoder;
use super::corpus::{
    apply_corpus_mutation, seq_mutators_stateful, seq_mutators_stateless, CorpusEntry,
    DEFAULT_MUTATION_CONSTS,
};
use super::testing::{
    calculate_value_complexity, check_assertion, check_call_test_predicate, check_etest,
    create_tests, update_open_test, EchidnaTest, ShrinkMode, TestMode, TestState, TestType,
    TestValue,
};
use super::transaction::{rand_seq, shrink_tx, Tx};
use super::shrink::{
    calculate_delay_complexity, can_shrink_tx, generate_call_to_delay_candidates,
    generate_delay_candidates, multi_shorten_seq, remove_useless_no_calls,
    shrink_sender, shorten_seq,
};
use super::config::EConfig;
use super::types::{
    CampaignStatus, TestStatus, test_state_to_status_string,
};

/// Shared state between all workers — equivalent to Arc<RwLock<>> fields in main fuzzer's Env/WorkerEnv.
/// Protected by wasm_safe_mutex::RwLock for WASM SharedArrayBuffer support.
pub struct SharedState {
    /// Shared corpus (matches corpus_ref: Arc<RwLock<Vec<CorpusEntry>>>)
    pub corpus: RwLock<Vec<CorpusEntry>>,
    /// Dedup hashes for corpus (matches corpus_seen: Arc<RwLock<HashSet<u64>>>)
    pub corpus_seen: RwLock<HashSet<u64>>,
    /// Init coverage from deployment (matches coverage_ref_init: Arc<RwLock<CoverageMap>>)
    pub init_coverage: RwLock<CoverageMap>,
    /// Runtime coverage from fuzzing (matches coverage_ref_runtime: Arc<RwLock<CoverageMap>>)
    pub runtime_coverage: RwLock<CoverageMap>,
    /// Tests with per-test locking (matches test_refs: Vec<Arc<RwLock<EchidnaTest>>>)
    pub tests: Vec<RwLock<EchidnaTest>>,
    /// Total calls across all workers (matches total_calls: Arc<AtomicUsize>)
    pub total_calls: AtomicU64,
    /// Total gas consumed across all workers (matches total_gas: Arc<AtomicUsize>)
    pub total_gas: AtomicU64,
    /// Global running flag
    pub running: AtomicBool,
    /// Shared dictionary values (matches main fuzzer's dict sharing)
    pub dict_values: RwLock<std::collections::BTreeSet<U256>>,
    /// Metadata-to-codehash map (matches codehash_map: Arc<RwLock<MetadataToCodehash>>)
    pub codehash_map: RwLock<MetadataToCodehash>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            corpus: RwLock::new(Vec::new()),
            corpus_seen: RwLock::new(HashSet::new()),
            init_coverage: RwLock::new(HashMap::new()),
            runtime_coverage: RwLock::new(HashMap::new()),
            tests: Vec::new(),
            total_calls: AtomicU64::new(0),
            total_gas: AtomicU64::new(0),
            running: AtomicBool::new(false),
            dict_values: RwLock::new(std::collections::BTreeSet::new()),
            codehash_map: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize tests (must be called before spawning workers).
    /// Takes ownership of tests and wraps each in RwLock.
    pub fn init_tests(&mut self, tests: Vec<EchidnaTest>) {
        self.tests = tests.into_iter().map(|t| RwLock::new(t)).collect();
    }

    /// Set init coverage from deployment (before workers start).
    pub fn set_init_coverage(&self, coverage: CoverageMap) {
        let mut init = self.init_coverage.lock_sync_write();
        *init = coverage;
    }

    /// Set codehash map (before workers start).
    pub fn set_codehash_map(&self, map: MetadataToCodehash) {
        let mut m = self.codehash_map.lock_sync_write();
        *m = map;
    }

    /// Get total coverage points (init + runtime, matching coverage_stats)
    pub fn coverage_points(&self) -> usize {
        let (points, _) = self.coverage_stats();
        points
    }

    /// Get coverage stats: (total_points, unique_codehashes/contracts)
    pub fn coverage_stats(&self) -> (usize, usize) {
        let init = self.init_coverage.lock_sync_read();
        let runtime = self.runtime_coverage.lock_sync_read();
        let mut all_pcs: HashSet<(B256, usize)> = HashSet::new();
        let mut codehashes: HashSet<B256> = HashSet::new();
        for (codehash, pcs) in init.iter() {
            codehashes.insert(*codehash);
            for (pc, _) in pcs {
                all_pcs.insert((*codehash, *pc));
            }
        }
        for (codehash, pcs) in runtime.iter() {
            codehashes.insert(*codehash);
            for (pc, _) in pcs {
                all_pcs.insert((*codehash, *pc));
            }
        }
        (all_pcs.len(), codehashes.len())
    }

    /// Add total calls atomically
    pub fn add_calls(&self, n: u64) {
        self.total_calls.fetch_add(n, Ordering::Relaxed);
    }

    /// Get total calls
    pub fn get_total_calls(&self) -> u64 {
        self.total_calls.load(Ordering::Relaxed)
    }

    /// Add gas consumed atomically
    pub fn add_gas(&self, n: u64) {
        self.total_gas.fetch_add(n, Ordering::Relaxed);
    }

    /// Get total gas consumed
    pub fn get_total_gas(&self) -> u64 {
        self.total_gas.load(Ordering::Relaxed)
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Set running flag
    pub fn set_running(&self, val: bool) {
        self.running.store(val, Ordering::Relaxed);
    }

    /// Get corpus size
    pub fn corpus_size(&self) -> usize {
        self.corpus.lock_sync_read().len()
    }

    /// Get number of tests
    pub fn num_tests(&self) -> usize {
        self.tests.len()
    }

    /// Count failed tests
    pub fn tests_failed(&self) -> usize {
        self.tests.iter()
            .filter(|t| t.lock_sync_read().state.did_fail())
            .count()
    }

}

/// Worker-local environment — contains cloned refs to shared state plus worker-local state.
/// Matches main fuzzer's WorkerEnv pattern.
///
/// Each worker owns:
///   - Reference to SharedState (via Arc for WASM shared memory)
///   - Worker-local EVM state (each worker has independent EVM)
///   - Worker-local RNG
///   - Worker-local dictionary (GenDict)
///   - Worker-local event log
pub struct WorkerEnv {
    /// Reference to shared state (equivalent to cloned Arc refs in main fuzzer)
    pub shared: Arc<SharedState>,
    /// Worker ID
    pub worker_id: usize,
    /// Worker-local EVM (each worker has its own EVM instance)
    pub evm: EvmState,
    /// Worker-local RNG
    pub rng: SmallRng,
    /// Worker-local dictionary
    pub dictionary: GenDict,
    /// Contract info
    pub contract: Option<CompiledContract>,
    /// Fuzzable functions (cached)
    pub fuzzable_funcs: Vec<Function>,
    /// Contract address
    pub contract_addr: Address,
    /// Max value for tx generation
    pub max_value: U256,
    /// Config
    pub config: EConfig,
    /// Initial EVM snapshot
    pub initial_snapshot: Option<u32>,
    /// Event log (drained periodically)
    pub event_log: Vec<String>,
    /// Worker-local call count pending sync (reset to 0 after sync)
    pub call_count: u64,
    /// Worker-local gas consumed pending sync (reset to 0 after sync)
    pub total_gas: u64,
    /// Total calls this worker has made (never reset, for final reporting)
    pub lifetime_calls: u64,
    /// Event map for ABI-decoded event extraction (matches main fuzzer's WorkerEnv.event_map)
    pub event_map: HashMap<B256, alloy_json_abi::Event>,
}

impl WorkerEnv {
    /// Run N fuzzing iterations.
    /// Matches main fuzzer's run_fuzz_worker() batch loop.
    /// Workers directly read/write shared state through RwLock — no more delta serialization.
    pub fn run_batch(&mut self, n: u32) {
        for i in 0..n {
            // Hot path: only check atomic running flag (free)
            if !self.shared.is_running() {
                break;
            }

            // Check test limit via atomic (free) — only every 10 iterations to reduce contention
            if i % 10 == 0 && self.shared.get_total_calls() >= self.config.test_limit {
                self.shared.set_running(false);
                self.close_and_shrink_optimization_tests();
                break;
            }

            // Prioritize shrinking (| any shrinkable tests)
            // Only this worker shrinks tests it found 
            if self.any_pending_shrink_for_worker() {
                self.shrink_pending_tests_worker();
                continue;
            }

            self.fuzz_one_iteration();
        }

        // Sync local call count and gas to shared
        if self.call_count > 0 {
            self.shared.add_calls(self.call_count);
            self.shared.add_gas(self.total_gas);
            self.call_count = 0;
            self.total_gas = 0;
        }
    }

    /// Single fuzzing iteration — generates and executes a sequence, checks tests.
    /// Matches CampaignState::fuzz_one_iteration but uses shared state.
    fn fuzz_one_iteration(&mut self) {
        // Revert to initial state
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            self.initial_snapshot = Some(self.evm.snapshot());
        }

        let param_types_lookup = self.contract.as_ref().map(|c| &c.resolved_param_types);

        // Generate sequence — read corpus from shared state
        let seq = {
            let corpus = self.shared.corpus.lock_sync_read();
            if corpus.is_empty() {
                drop(corpus);
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

                let result = apply_corpus_mutation(
                    &mut self.rng,
                    mutation,
                    self.config.seq_len,
                    &corpus,
                    &generated,
                );
                drop(corpus);
                result
            }
        };

        if seq.is_empty() {
            return;
        }

        // Execute sequence and check tests after EVERY transaction
        let mut executed_seq = Vec::new();
        let mut any_new_coverage = false;

        for tx in &seq {
            self.evm.apply_delay(tx.delay);

            let (trace, has_new_cov) = self.evm.exec_tx_check_new_cov(
                tx.sender,
                tx.target,
                tx.calldata.clone(),
                tx.value,
            );

            self.call_count += 1;
            self.lifetime_calls += 1;
            self.total_gas += trace.gas_used;
            executed_seq.push(tx.clone());

            if has_new_cov {
                any_new_coverage = true;
                if !tx.function_name.is_empty() && !tx.args.is_empty() {
                    self.dictionary.add_call((tx.function_name.clone(), tx.args.clone()));
                }
            }

            // Dictionary learning from return data and events
            if trace.success {
                self.learn_from_execution(tx);
            }

            // Check ALL tests after EVERY transaction
            self.check_tests_after_tx(&executed_seq);
        }

        // Add to corpus if new coverage found
        // Merge worker's new coverage into shared runtime coverage
        if any_new_coverage && !executed_seq.is_empty() {
            self.merge_coverage_to_shared();
            let mut corpus = self.shared.corpus.lock_sync_write();
            corpus.push((10, executed_seq));
        }

        // Periodically sync call count, gas, and dict values
        if self.call_count >= 100 {
            self.shared.add_calls(self.call_count);
            self.shared.add_gas(self.total_gas);
            self.call_count = 0;
            self.total_gas = 0;
            self.sync_dict_to_shared();
        }
    }

    /// Extract dictionary values from execution results.
    /// Delegates to execution::extract_dict_from_tx (single source of truth).
    fn learn_from_execution(&mut self, tx: &Tx) {
        super::execution::extract_dict_from_tx(&self.evm, &mut self.dictionary, tx, &self.event_map);
    }

    /// Check all tests after executing a transaction.
    /// Uses per-test RwLock from SharedState (matches main fuzzer: test_refs[i].write()).
    fn check_tests_after_tx(&mut self, executed_seq: &[Tx]) {
        for test_lock in &self.shared.tests {
            let should_check = {
                let test = test_lock.lock_sync_read();
                test.is_open()
            };
            if !should_check {
                continue;
            }

            // Read test type for dispatch (avoid holding lock during EVM execution)
            let (test_type, old_value, is_optimization) = {
                let test = test_lock.lock_sync_read();
                (test.test_type.clone(), test.value.clone(), matches!(test.test_type, TestType::OptimizationTest { .. }))
            };

            let (test_value, passed) = match &test_type {
                TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                    // Need to read test for check_etest — use snapshot/revert
                    let check_snap = self.evm.snapshot();
                    let test = test_lock.lock_sync_read();
                    let result = check_etest(&mut self.evm, &test);
                    drop(test);
                    self.evm.revert_to(check_snap);
                    result
                }
                TestType::CallTest { predicate, .. } => {
                    check_call_test_predicate(&self.evm, predicate)
                }
                TestType::AssertionTest { signature, addr } => {
                    check_assertion(&self.evm, signature, *addr)
                }
                _ => continue,
            };

            // Update test with write lock if state changed
            // Matches main fuzzer's testing/worker.rs pattern
            if matches!(test_type, TestType::PropertyTest { .. } | TestType::OptimizationTest { .. }) {
                let mut test = test_lock.lock_sync_write();
                let test_updated = update_open_test(&mut test, executed_seq.to_vec(), test_value.clone());
                if test_updated {
                    if is_optimization {
                        let name = test.test_type.name().to_string();
                        let value = test.value.clone();
                        drop(test);
                        self.event_log.push(format!(
                            "New maximum value of {}: {:?}", name, value
                        ));
                        // Record hot functions/values for targeted evolution
                        for etx in executed_seq {
                            if !etx.function_name.is_empty() && !etx.args.is_empty() {
                                self.dictionary.record_optimization_improving_function(&etx.function_name);
                                self.dictionary.record_optimization_improving_values(&etx.args);
                            }
                        }
                    } else {
                        let name = test.test_type.name().to_string();
                        drop(test);
                        self.event_log.push(format!("Test {} falsified!", name));
                    }
                }
            } else if !passed {
                // CallTest/AssertionTest failure
                let mut test = test_lock.lock_sync_write();
                if update_open_test(&mut test, executed_seq.to_vec(), test_value) {
                    let name = test.test_type.name().to_string();
                    drop(test);
                    self.event_log.push(format!("Test {} falsified!", name));
                }
            }
        }
    }

    /// Merge worker-local EVM coverage into shared runtime coverage.
    /// Called when new coverage is found (matches main fuzzer's add_to_corpus_worker pattern).
    fn merge_coverage_to_shared(&self) {
        let mut shared_cov = self.shared.runtime_coverage.lock_sync_write();
        for (codehash, pcs) in &self.evm.coverage {
            let entry = shared_cov.entry(*codehash).or_default();
            for (pc, (depth, result)) in pcs {
                let e = entry.entry(*pc).or_insert((0, 0));
                e.0 |= depth;
                e.1 |= result;
            }
        }
    }

    /// Sync local dictionary values to shared dict.
    fn sync_dict_to_shared(&self) {
        let mut shared_dict = self.shared.dict_values.lock_sync_write();
        for val in &self.dictionary.dict_values {
            shared_dict.insert(*val);
        }
    }

    /// Pull shared dictionary values into local dictionary.
    pub fn pull_dict_from_shared(&mut self) {
        let shared_dict = self.shared.dict_values.lock_sync_read();
        for val in shared_dict.iter() {
            self.dictionary.dict_values.insert(*val);
        }
    }

    /// Check if any test assigned to this worker needs shrinking.
    /// Matches main fuzzer's any_pending_shrink_for_worker_env().
    fn any_pending_shrink_for_worker(&self) -> bool {
        self.shared.tests.iter().any(|t| {
            let test = t.lock_sync_read();
            matches!(test.state, TestState::Large(_)) && test.worker_id == Some(self.worker_id)
        })
    }

    /// Shrink pending tests that this worker owns.
    /// Matches main fuzzer's shrink_pending_tests_worker() → shrink_test_worker() → shrink_seq_worker().
    /// Uses index-based iteration to avoid borrowing self.shared while calling &mut self methods.
    fn shrink_pending_tests_worker(&mut self) {
        let shrink_limit = self.config.shrink_limit;
        let num_tests = self.shared.tests.len();

        for test_idx in 0..num_tests {
            let (shrink_count, is_optimization, current_reproducer, test_value, shrink_context_mode) = {
                let test = self.shared.tests[test_idx].lock_sync_read();
                if test.worker_id != Some(self.worker_id) {
                    continue;
                }
                let shrink_count = match &test.state {
                    TestState::Large(n) => *n,
                    _ => continue,
                };
                let is_opt = matches!(test.test_type, TestType::OptimizationTest { .. });
                (shrink_count, is_opt, test.reproducer.clone(), test.value.clone(), test.shrink_context.mode)
            };

            // Check shrink limit (optimization tests keep going)
            if shrink_count >= shrink_limit && !is_optimization {
                self.shared.tests[test_idx].lock_sync_write().state = TestState::Solved;
                continue;
            }

            if current_reproducer.is_empty() {
                self.shared.tests[test_idx].lock_sync_write().state = TestState::Solved;
                continue;
            }

            // Step 1: remove_reverts (removeReverts vm test.reproducer)
            let simplified = self.remove_reverts(&current_reproducer);
            let simplified = remove_useless_no_calls(simplified);

            // Stop shrinking when single tx — can't reduce further
            if simplified.len() <= 1 {
                let mut test = self.shared.tests[test_idx].lock_sync_write();
                test.state = TestState::Solved;
                test.reproducer = simplified;
                continue;
            }

            // Check if we can shrink further (length rr > 1 || any canShrinkTx rr)
            if simplified.len() > 1 || simplified.iter().any(can_shrink_tx) {
                // Try shrinking — matches shrink_seq_worker()
                if let Some((new_repro, new_val)) =
                    self.shrink_seq_worker(&simplified, test_idx, &test_value, shrink_context_mode)
                {
                    let new_complexity = calculate_value_complexity(&new_repro);
                    let mut test = self.shared.tests[test_idx].lock_sync_write();
                    test.shrink_context.update(new_repro.len(), new_complexity);
                    test.reproducer = new_repro;
                    test.value = new_val;
                    test.state = TestState::Large(shrink_count + 1);
                } else {
                    // Shrink attempt failed — keep simplified, bump counter 
                    let complexity = calculate_value_complexity(&simplified);
                    let mut test = self.shared.tests[test_idx].lock_sync_write();
                    test.shrink_context.update(simplified.len(), complexity);
                    test.reproducer = simplified;
                    test.state = TestState::Large(shrink_count + 1);
                }
            } else {
                // Can't shrink further (single non-shrinkable tx) — mark as Solved
                let mut test = self.shared.tests[test_idx].lock_sync_write();
                test.state = TestState::Solved;
                test.reproducer = simplified;
            }

            // Only shrink one test per batch call
            return;
        }
    }

    /// Shrink a transaction sequence.
    /// Matches main fuzzer's shrink_seq_worker() exactly.
    /// Serial validation (no Rayon in WASM — each worker is single-threaded).
    fn shrink_seq_worker(
        &mut self,
        txs: &[Tx],
        test_idx: usize,
        test_value: &TestValue,
        mode: ShrinkMode,
    ) -> Option<(Vec<Tx>, TestValue)> {
        if txs.is_empty() {
            return None;
        }

        // Get sorted senders for shrinkSender 
        let mut sorted_senders: Vec<Address> = crate::evm::exec::DEFAULT_SENDERS.to_vec();
        sorted_senders.sort();

        // Generate candidates based on current shrink mode
        let mut candidates: Vec<Vec<Tx>> = Vec::new();

        match mode {
            ShrinkMode::Sequence => {
                // Focus on sequence shortening with some value shrinking
                if txs.len() > 10 {
                    for _ in 0..3 {
                        candidates.push(multi_shorten_seq(&mut self.rng, txs));
                    }
                }
                let num_shorten = if txs.len() > 5 { 4 } else { 2 };
                for _ in 0..num_shorten {
                    candidates.push(shorten_seq(&mut self.rng, txs));
                }
                // Still include some value shrinking
                for _ in 0..2 {
                    let shrunk: Vec<Tx> = txs.iter().map(|tx| {
                        let t = shrink_tx(&mut self.rng, tx);
                        shrink_sender(&mut self.rng, &t, &sorted_senders)
                    }).collect();
                    candidates.push(shrunk);
                }
                // Delay-focused candidates (decoupled from arg shrinking)
                generate_delay_candidates(&mut self.rng, txs, &mut candidates);
            }
            ShrinkMode::ValueOnly => {
                // Focus on value shrinking with minimal sequence shortening
                for _ in 0..2 {
                    candidates.push(shorten_seq(&mut self.rng, txs));
                }
                // Many more value shrinking attempts
                for _ in 0..8 {
                    let shrunk: Vec<Tx> = txs.iter().map(|tx| {
                        let t = shrink_tx(&mut self.rng, tx);
                        shrink_sender(&mut self.rng, &t, &sorted_senders)
                    }).collect();
                    candidates.push(shrunk);
                }
                // Delay-focused candidates (decoupled from arg shrinking)
                generate_delay_candidates(&mut self.rng, txs, &mut candidates);
            }
        }

        // Call-to-delay conversion: convert random txs to NoCalls, merge consecutive
        // (done after rng-dependent generation to avoid borrow conflict with closure)
        if txs.len() > 2 {
            generate_call_to_delay_candidates(
                &mut self.rng, txs,
                |candidate| {
                    // Check if test still fails with this candidate
                    // We use snapshot/revert directly here since self is borrowed by the closure
                    if let Some(snap) = self.initial_snapshot {
                        self.evm.revert_to(snap);
                        self.initial_snapshot = Some(self.evm.snapshot());
                    }
                    for tx in candidate {
                        self.evm.apply_delay(tx.delay);
                        self.evm.exec_tx(tx.sender, tx.target, tx.calldata.clone(), tx.value);
                    }
                    let test = self.shared.tests[test_idx].lock_sync_read();
                    match &test.test_type {
                        TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                            let check_snap = self.evm.snapshot();
                            let (val, _passed) = check_etest(&mut self.evm, &test);
                            self.evm.revert_to(check_snap);
                            matches!(val, TestValue::BoolValue(false))
                        }
                        _ => false,
                    }
                },
                &mut candidates,
            );
        }

        // Clean up candidates: merge consecutive NoCalls, remove zero-delay NoCalls
        let candidates: Vec<Vec<Tx>> = candidates
            .into_iter()
            .map(remove_useless_no_calls)
            .collect();

        // Validate candidates serially and collect valid ones
        // (main fuzzer uses Rayon par_iter here — WASM is single-threaded per worker)
        let valid_results: Vec<(Vec<Tx>, TestValue)> = candidates
            .into_iter()
            .filter_map(|candidate| {
                let (val, still_fails) = self.execute_and_check_shrink_idx(&candidate, test_idx)?;
                if !still_fails {
                    return None;
                }
                match (&val, test_value) {
                    (TestValue::BoolValue(false), _) => Some((candidate, val)),
                    (TestValue::IntValue(new), TestValue::IntValue(old)) if *new >= *old => {
                        Some((candidate, val))
                    }
                    _ => None,
                }
            })
            .collect();

        // Return the best valid candidate using lexicographic ordering:
        // 1. Prefer shorter sequences (fewer transactions)
        // 2. When lengths are equal, prefer smaller value complexity
        // 3. Break ties by delay complexity (prefer smaller total delays)
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
    fn remove_reverts(&mut self, txs: &[Tx]) -> Vec<Tx> {
        if txs.is_empty() {
            return Vec::new();
        }
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            self.initial_snapshot = Some(self.evm.snapshot());
        }
        let (init, last) = txs.split_at(txs.len() - 1);
        let mut result = Vec::with_capacity(txs.len());
        for tx in init {
            let is_view_pure = self.contract.as_ref().map_or(false, |c| {
                if tx.selector == [0; 4] { return false; }
                let sel = alloy_primitives::FixedBytes::<4>::from(tx.selector);
                c.functions.get(&sel).map_or(false, |f| {
                    matches!(f.state_mutability,
                        alloy_json_abi::StateMutability::View | alloy_json_abi::StateMutability::Pure)
                })
            });
            if is_view_pure || tx.is_no_call() {
                result.push(Tx::no_call(tx.sender, tx.target, tx.delay));
            } else {
                self.evm.apply_delay(tx.delay);
                let trace = self.evm.exec_tx(tx.sender, tx.target, tx.calldata.clone(), tx.value);
                if !trace.success {
                    result.push(Tx::no_call(tx.sender, tx.target, tx.delay));
                } else {
                    result.push(tx.clone());
                }
            }
        }
        result.extend(last.iter().cloned());
        result
    }

    /// Execute sequence and check a test for shrink validation (by index).
    fn execute_and_check_shrink_idx(
        &mut self,
        seq: &[Tx],
        test_idx: usize,
    ) -> Option<(TestValue, bool)> {
        if let Some(snap) = self.initial_snapshot {
            self.evm.revert_to(snap);
            self.initial_snapshot = Some(self.evm.snapshot());
        }
        for tx in seq {
            self.evm.apply_delay(tx.delay);
            self.evm.exec_tx(tx.sender, tx.target, tx.calldata.clone(), tx.value);
        }
        let test = self.shared.tests[test_idx].lock_sync_read();
        let (test_value, passed) = match &test.test_type {
            TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                let check_snap = self.evm.snapshot();
                let result = check_etest(&mut self.evm, &test);
                self.evm.revert_to(check_snap);
                result
            }
            TestType::CallTest { predicate, .. } => {
                check_call_test_predicate(&self.evm, predicate)
            }
            TestType::AssertionTest { signature, addr } => {
                check_assertion(&self.evm, signature, *addr)
            }
            _ => return None,
        };
        Some((test_value, !passed))
    }

    /// Close open optimization tests and run final shrinking.
    fn close_and_shrink_optimization_tests(&mut self) {
        let num_tests = self.shared.tests.len();
        for i in 0..num_tests {
            let mut test = self.shared.tests[i].lock_sync_write();
            if test.is_open() {
                if matches!(test.test_type, TestType::OptimizationTest { .. }) {
                    if !test.reproducer.is_empty() {
                        test.state = TestState::Large(0);
                        test.worker_id = Some(self.worker_id);
                    } else {
                        test.state = TestState::Passed;
                    }
                } else {
                    test.state = TestState::Passed;
                }
            }
        }

        // Run shrinking loop until done
        let shrink_limit = self.config.shrink_limit;
        loop {
            let has_shrinkable = {
                let mut found = false;
                for i in 0..num_tests {
                    let test = self.shared.tests[i].lock_sync_read();
                    if matches!(test.state, TestState::Large(n) if n < shrink_limit)
                        && test.worker_id == Some(self.worker_id) {
                        found = true;
                        break;
                    }
                }
                found
            };
            if !has_shrinkable { break; }
            self.shrink_pending_tests_worker();
        }
    }

    /// Populate return_types in dictionary for type-aware return value extraction.
    pub fn populate_return_types(&mut self) {
        use alloy_dyn_abi::{DynSolType, Specifier};
        if let Some(ref contract) = self.contract {
            for func in contract.abi.functions() {
                if func.outputs.is_empty() { continue; }
                let output_types: Vec<DynSolType> = func.outputs.iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();
                if output_types.is_empty() { continue; }
                let ty = if output_types.len() == 1 {
                    output_types.into_iter().next().unwrap()
                } else {
                    DynSolType::Tuple(output_types)
                };
                self.dictionary.return_types.insert(func.name.clone(), ty);
            }
        }
    }

    /// Get campaign status (reads from shared state).
    pub fn status(&mut self) -> CampaignStatus {
        let total_calls = self.shared.get_total_calls();
        let cov = self.shared.coverage_points();
        let corpus_size = self.shared.corpus_size();
        let tests_failed = self.shared.tests_failed();
        let total_tests = self.shared.num_tests();

        // Collect test statuses
        let test_statuses: Vec<TestStatus> = self.shared.tests.iter()
            .map(|t| {
                let test = t.lock_sync_read();
                TestStatus::from(&*test)
            })
            .collect();

        // Collect optimization values (i128, matches main fuzzer)
        let opt_values: Vec<i128> = self.shared.tests.iter()
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
        let mut shrink_parts = Vec::new();
        for t_lock in &self.shared.tests {
            let t = t_lock.lock_sync_read();
            if let TestState::Large(n) = &t.state {
                shrink_parts.push(format!("{}/{} ({})", n, self.config.shrink_limit, t.reproducer.len()));
            }
        }
        let shrinking_part = if shrink_parts.is_empty() {
            String::new()
        } else {
            format!(", shrinking: {}", shrink_parts.join(" "))
        };

        // Build status line (matches main fuzzer format)
        let status_line = format!(
            "[status] tests: {}/{}, fuzzing: {}/{}, values: {:?}, cov: {}, corpus: {}{}",
            tests_failed, total_tests, total_calls, self.config.test_limit,
            opt_values, cov, corpus_size, shrinking_part,
        );

        let mut events = std::mem::take(&mut self.event_log);
        events.insert(0, status_line);

        CampaignStatus {
            call_count: total_calls,
            corpus_size,
            coverage_points: cov,
            tests: test_statuses,
            events,
            running: self.shared.is_running(),
        }
    }
}

