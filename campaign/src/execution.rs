//! Transaction sequence execution
//!
//! Contains functions for executing and replaying transaction sequences.

use std::sync::Arc;

use alloy_dyn_abi::{DynSolType, FunctionExt, JsonAbiExt, Specifier};
use alloy_primitives::{Address, I256, U256};
use evm::exec::EvmState;
use rand::prelude::*;
use tracing::debug;

use abi::types::GenDict;
use evm::types::{Tx, TxCall, TxResult};

use crate::testing::{check_cheap_tests_after_tx_worker, check_tests_after_tx_worker, check_tests_after_tx_worker_with_checkpoint, check_tests_without_optimization_worker};
use crate::types::WorkerState;
use crate::worker_env::{CorpusEntry, WorkerEnv};

/// Add a return value to the dictionary, recursively extracting tuple elements
pub fn add_return_value_to_dict(dict: &mut GenDict, val: alloy_dyn_abi::DynSolValue) {
    use alloy_dyn_abi::DynSolValue;

    // ALWAYS add the whole value first (preserves structs for reuse)
    // This enables passing complete structs to other functions
    dict.add_value(val.clone());

    // ALSO decompose for primitive extraction (enables mixing struct fields)
    match &val {
        // For tuples/structs, also extract each element individually
        DynSolValue::Tuple(elements) => {
            for elem in elements {
                add_return_value_to_dict(dict, elem.clone());
            }
        }
        // For arrays, also extract each element
        DynSolValue::Array(elements) | DynSolValue::FixedArray(elements) => {
            for elem in elements {
                add_return_value_to_dict(dict, elem.clone());
            }
        }
        // Primitive types are already added above
        _ => {}
    }
}

/// Extract dictionary values from call traces at ALL depths
///
/// This function iterates through the CallTraceArena and extracts:
/// 1. Call inputs (arguments passed to external calls)
/// 2. Call outputs (return values from external calls)
/// 3. Event parameters (both indexed and non-indexed)
/// 4. Created contract addresses
///
/// This is essential for setUp extraction and corpus replay to capture
/// values from nested calls (e.g., vault.addMarket(MarketParams{...}))
pub fn extract_dict_from_traces(
    traces: &evm::tracing::CallTraceArena,
    dict: &mut GenDict,
    event_map: &std::collections::HashMap<alloy_primitives::B256, alloy_json_abi::Event>,
    function_map: &std::collections::HashMap<alloy_primitives::FixedBytes<4>, alloy_json_abi::Function>,
) {
    use alloy_dyn_abi::DynSolValue;

    for node in traces.nodes() {
        let trace = &node.trace;

        // Skip calls to HEVM (cheatcodes) and console.log
        if trace.address == evm::cheatcodes::HEVM_ADDRESS {
            continue;
        }
        let console_addr = Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63,
            0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x6c, 0x6f, 0x67,
        ]);
        if trace.address == console_addr {
            continue;
        }

        // Extract call inputs (arguments passed to external calls)
        if trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                // Decode call input arguments
                if let Ok(args) = func.abi_decode_input(&trace.data[4..]) {
                    tracing::trace!(
                        "Extracted {} input args from call to {} at depth {}",
                        args.len(),
                        func.name,
                        trace.depth
                    );
                    for arg in args {
                        add_return_value_to_dict(dict, arg);
                    }
                }
            }
        }

        // Extract call outputs (return values) for successful calls
        if trace.success && !trace.output.is_empty() && trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                if let Ok(outputs) = func.abi_decode_output(&trace.output) {
                    tracing::trace!(
                        "Extracted {} output values from call to {} at depth {}",
                        outputs.len(),
                        func.name,
                        trace.depth
                    );
                    for output in outputs {
                        add_return_value_to_dict(dict, output);
                    }
                }
            } else {
                // Fallback: try to extract raw U256 values from output
                if trace.output.len() == 32 {
                    let val = U256::from_be_slice(&trace.output);
                    dict.dict_values.insert(val);
                } else if trace.output.len() % 32 == 0 && trace.output.len() <= 256 {
                    for chunk in trace.output.chunks(32) {
                        dict.dict_values.insert(U256::from_be_slice(chunk));
                    }
                }
            }
        }

        // Extract addresses from CREATE/CREATE2 operations
        if trace.kind.is_any_create() && trace.success {
            dict.add_value(DynSolValue::Address(trace.address));
        }

        // Extract event parameters from this node's logs
        for log_entry in &node.logs {
            let log = &log_entry.raw_log;

            if let Some(topic0) = log.topics().first() {
                if let Some(event) = event_map.get(topic0) {
                    // Extract NON-INDEXED parameters from log.data
                    let mut non_indexed_types = Vec::new();
                    for input in &event.inputs {
                        if !input.indexed {
                            if let Ok(ty) = input.resolve() {
                                non_indexed_types.push(ty);
                            }
                        }
                    }

                    if !non_indexed_types.is_empty() {
                        let tuple_ty = DynSolType::Tuple(non_indexed_types);
                        if let Ok(val) = tuple_ty.abi_decode(log.data.as_ref()) {
                            if let DynSolValue::Tuple(vals) = val {
                                tracing::trace!(
                                    "Extracted {} non-indexed values from event {} at depth {}",
                                    vals.len(),
                                    event.name,
                                    trace.depth
                                );
                                for v in vals {
                                    add_return_value_to_dict(dict, v);
                                }
                            }
                        }
                    }

                    // Extract INDEXED parameters from topics[1..]
                    let indexed_inputs: Vec<_> = event.inputs.iter()
                        .filter(|input| input.indexed)
                        .collect();

                    for (topic, input) in log.topics().iter().skip(1).zip(indexed_inputs.iter()) {
                        if let Ok(ty) = input.resolve() {
                            match &ty {
                                DynSolType::Address => {
                                    let addr = Address::from_slice(&topic.0[12..32]);
                                    dict.add_value(DynSolValue::Address(addr));
                                }
                                DynSolType::Uint(_) => {
                                    let val = U256::from_be_bytes(topic.0);
                                    dict.dict_values.insert(val);
                                }
                                DynSolType::Int(_) => {
                                    let val = I256::from_be_bytes(topic.0);
                                    dict.signed_dict_values.insert(val);
                                }
                                DynSolType::Bool => {
                                    let val = topic.0[31] != 0;
                                    dict.add_value(DynSolValue::Bool(val));
                                }
                                DynSolType::FixedBytes(n) => {
                                    // Fixed bytes stored left-aligned in the 32-byte topic
                                    dict.add_value(DynSolValue::FixedBytes(
                                        alloy_primitives::FixedBytes::from_slice(&topic.0), *n
                                    ));
                                }
                                _ => {
                                    // Fallback: add raw topic as U256
                                    let val = U256::from_be_bytes(topic.0);
                                    dict.dict_values.insert(val);
                                }
                            }
                        } else {
                            let val = U256::from_be_bytes(topic.0);
                            dict.dict_values.insert(val);
                        }
                    }
                } else {
                    // Unknown event: extract raw topic values
                    for topic in log.topics().iter().skip(1) {
                        dict.dict_values.insert(U256::from_be_bytes(topic.0));
                    }
                    // Extract raw data as U256 chunks
                    if log.data.len() % 32 == 0 {
                        for chunk in log.data.chunks(32) {
                            dict.dict_values.insert(U256::from_be_slice(chunk));
                        }
                    }
                }
            }
        }
    }
}

/// Extracted dictionary values from traces (for passing to Env)
#[derive(Default, Clone)]
pub struct ExtractedDictValues {
    pub uint_values: Vec<U256>,
    pub int_values: Vec<I256>,
    pub addresses: Vec<Address>,
    /// Tuples/structs extracted from traces (e.g., MarketParams)
    pub tuples: Vec<alloy_dyn_abi::DynSolValue>,
}

/// Extract dictionary values from call traces at ALL depths (simple return version)
///
/// This is a simpler version that returns raw values instead of populating a GenDict.
/// Used by cli/main.rs to populate Env.setup_dict_* fields before workers are created.
pub fn extract_values_from_traces(
    traces: &evm::tracing::CallTraceArena,
    event_map: &std::collections::HashMap<alloy_primitives::B256, alloy_json_abi::Event>,
    function_map: &std::collections::HashMap<alloy_primitives::FixedBytes<4>, alloy_json_abi::Function>,
) -> ExtractedDictValues {
    use std::collections::BTreeSet;
    use alloy_dyn_abi::DynSolValue;

    let mut uint_values: BTreeSet<U256> = BTreeSet::new();
    let mut int_values: BTreeSet<I256> = BTreeSet::new();
    let mut addresses: BTreeSet<Address> = BTreeSet::new();
    let mut tuples: Vec<DynSolValue> = Vec::new();

    for node in traces.nodes() {
        let trace = &node.trace;

        // Skip calls to HEVM (cheatcodes) and console.log
        if trace.address == evm::cheatcodes::HEVM_ADDRESS {
            continue;
        }
        let console_addr = Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63,
            0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x6c, 0x6f, 0x67,
        ]);
        if trace.address == console_addr {
            continue;
        }

        // Extract call inputs
        if trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                if let Ok(args) = func.abi_decode_input(&trace.data[4..]) {
                    for arg in &args {
                        extract_raw_values(arg, &mut uint_values, &mut int_values, &mut addresses);
                        // Also capture tuples/structs (e.g., MarketParams)
                        extract_tuples_recursive(arg, &mut tuples);
                    }
                }
            }
        }

        // Extract call outputs for successful calls
        if trace.success && !trace.output.is_empty() && trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                if let Ok(outputs) = func.abi_decode_output(&trace.output) {
                    for output in &outputs {
                        extract_raw_values(output, &mut uint_values, &mut int_values, &mut addresses);
                        // Also capture tuples/structs from outputs
                        extract_tuples_recursive(output, &mut tuples);
                    }
                }
            } else {
                // Fallback: extract raw U256 from output
                if trace.output.len() == 32 {
                    uint_values.insert(U256::from_be_slice(&trace.output));
                } else if trace.output.len() % 32 == 0 && trace.output.len() <= 256 {
                    for chunk in trace.output.chunks(32) {
                        uint_values.insert(U256::from_be_slice(chunk));
                    }
                }
            }
        }

        // Extract addresses from CREATE/CREATE2
        if trace.kind.is_any_create() && trace.success {
            addresses.insert(trace.address);
        }

        // Extract event parameters
        for log_entry in &node.logs {
            let log = &log_entry.raw_log;

            if let Some(topic0) = log.topics().first() {
                if let Some(event) = event_map.get(topic0) {
                    // Non-indexed parameters
                    let mut non_indexed_types = Vec::new();
                    for input in &event.inputs {
                        if !input.indexed {
                            if let Ok(ty) = input.resolve() {
                                non_indexed_types.push(ty);
                            }
                        }
                    }

                    if !non_indexed_types.is_empty() {
                        let tuple_ty = DynSolType::Tuple(non_indexed_types);
                        if let Ok(val) = tuple_ty.abi_decode(log.data.as_ref()) {
                            extract_raw_values(&val, &mut uint_values, &mut int_values, &mut addresses);
                            // Also capture tuples from events
                            extract_tuples_recursive(&val, &mut tuples);
                        }
                    }

                    // Indexed parameters
                    let indexed_inputs: Vec<_> = event.inputs.iter()
                        .filter(|input| input.indexed)
                        .collect();

                    for (topic, input) in log.topics().iter().skip(1).zip(indexed_inputs.iter()) {
                        if let Ok(ty) = input.resolve() {
                            match &ty {
                                DynSolType::Address => {
                                    addresses.insert(Address::from_slice(&topic.0[12..32]));
                                }
                                DynSolType::Uint(_) => {
                                    uint_values.insert(U256::from_be_bytes(topic.0));
                                }
                                DynSolType::Int(_) => {
                                    int_values.insert(I256::from_be_bytes(topic.0));
                                }
                                _ => {
                                    uint_values.insert(U256::from_be_bytes(topic.0));
                                }
                            }
                        } else {
                            uint_values.insert(U256::from_be_bytes(topic.0));
                        }
                    }
                } else {
                    // Unknown event: extract raw values
                    for topic in log.topics().iter().skip(1) {
                        uint_values.insert(U256::from_be_bytes(topic.0));
                    }
                    if log.data.len() % 32 == 0 {
                        for chunk in log.data.chunks(32) {
                            uint_values.insert(U256::from_be_slice(chunk));
                        }
                    }
                }
            }
        }
    }

    // Log tuples found
    if !tuples.is_empty() {
        tracing::info!("Extracted {} tuples from setUp traces", tuples.len());
        for (i, t) in tuples.iter().enumerate() {
            if let DynSolValue::Tuple(elements) = t {
                let type_name = t.sol_type_name().map(|s| s.to_string()).unwrap_or_else(|| "tuple".to_string());
                tracing::info!("  Tuple {}: {} with {} elements", i + 1, type_name, elements.len());
            }
        }
    }

    ExtractedDictValues {
        uint_values: uint_values.into_iter().collect(),
        int_values: int_values.into_iter().collect(),
        addresses: addresses.into_iter().collect(),
        tuples,
    }
}

/// Recursively extract tuples from a DynSolValue
fn extract_tuples_recursive(val: &alloy_dyn_abi::DynSolValue, tuples: &mut Vec<alloy_dyn_abi::DynSolValue>) {
    use alloy_dyn_abi::DynSolValue;

    match val {
        DynSolValue::Tuple(elements) => {
            // Add this tuple
            tuples.push(val.clone());
            // Also recurse into nested tuples
            for elem in elements {
                extract_tuples_recursive(elem, tuples);
            }
        }
        DynSolValue::Array(elements) | DynSolValue::FixedArray(elements) => {
            for elem in elements {
                extract_tuples_recursive(elem, tuples);
            }
        }
        _ => {}
    }
}

/// Helper to recursively extract raw values from DynSolValue
fn extract_raw_values(
    val: &alloy_dyn_abi::DynSolValue,
    uint_values: &mut std::collections::BTreeSet<U256>,
    int_values: &mut std::collections::BTreeSet<I256>,
    addresses: &mut std::collections::BTreeSet<Address>,
) {
    use alloy_dyn_abi::DynSolValue;

    match val {
        DynSolValue::Uint(v, _) => {
            uint_values.insert(*v);
        }
        DynSolValue::Int(v, _) => {
            int_values.insert(*v);
        }
        DynSolValue::Address(a) => {
            addresses.insert(*a);
        }
        DynSolValue::Bool(_) => {}
        DynSolValue::FixedBytes(b, _) => {
            if b.len() == 32 {
                uint_values.insert(U256::from_be_slice(b.as_slice()));
            }
        }
        DynSolValue::Bytes(b) => {
            if b.len() == 32 {
                uint_values.insert(U256::from_be_slice(b));
            }
        }
        DynSolValue::String(_) => {}
        DynSolValue::Tuple(elements) => {
            for elem in elements {
                extract_raw_values(elem, uint_values, int_values, addresses);
            }
        }
        DynSolValue::Array(elements) | DynSolValue::FixedArray(elements) => {
            for elem in elements {
                extract_raw_values(elem, uint_values, int_values, addresses);
            }
        }
        _ => {}
    }
}

/// PERF OPTIMIZED: Generate a transaction sequence using pre-cached data
/// This avoids recomputing fuzzable functions, assert_functions, and relations on every call
pub fn generate_sequence_worker_cached(
    env: &WorkerEnv,
    rng: &mut impl Rng,
    dict: &GenDict,
    cached_fuzzable: &[alloy_json_abi::Function],
    cached_assert_functions: &std::collections::HashSet<String>,
    cached_resolved_relations: &std::collections::HashMap<String, analysis::slither::ResolvedRelations>,
) -> anyhow::Result<Vec<Tx>> {
    let main_contract = env
        .main_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No main contract"))?;

    // Check for fuzz templates from web UI - use them with 50% probability
    let templates = env.fuzz_templates.read();
    if !templates.is_empty() && rng.gen_bool(0.5) {
        // Weighted selection by priority
        let total_weight: usize = templates.iter().map(|t| t.priority.max(1)).sum();
        let mut choice = rng.gen_range(0..total_weight);
        for template in templates.iter() {
            let weight = template.priority.max(1);
            if choice < weight {
                let sequence = crate::transaction::gen_sequence_from_template(
                    rng,
                    dict,
                    &env.world,
                    &env.cfg.tx_conf,
                    main_contract,
                    env.cfg.sol_conf.contract_addr,
                    template,
                );
                if !sequence.is_empty() {
                    tracing::debug!("Generated sequence from fuzz template ({} txs)", sequence.len());
                    return Ok(sequence);
                }
            }
            choice = choice.saturating_sub(weight);
        }
    }
    drop(templates);

    let mut sequence = Vec::with_capacity(env.cfg.campaign_conf.seq_len);

    if cached_fuzzable.is_empty() {
        tracing::warn!("No fuzzable functions found!");
        return Ok(sequence);
    }

    // Filter fuzzable functions based on target_functions from web UI
    let target_funcs = env.target_functions.read();
    let filtered_fuzzable: Vec<_> = if target_funcs.is_empty() {
        cached_fuzzable.to_vec()
    } else {
        cached_fuzzable.iter()
            .filter(|f| target_funcs.contains(&f.name))
            .cloned()
            .collect()
    };
    drop(target_funcs);

    let effective_fuzzable = if filtered_fuzzable.is_empty() {
        // Fall back to all fuzzable if no matches
        cached_fuzzable
    } else {
        &filtered_fuzzable[..]
    };

    let seq_len = env.cfg.campaign_conf.seq_len;
    let mut prev_call: Option<String> = None;

    for _ in 0..seq_len {
        // Use relation-aware generation if we have relations, otherwise fall back
        let mut tx = if !cached_resolved_relations.is_empty() {
            crate::transaction::gen_tx_with_cached_fuzzable(
                rng,
                dict,
                &env.world,
                &env.cfg.tx_conf,
                main_contract,
                env.cfg.sol_conf.contract_addr,
                effective_fuzzable,
                cached_assert_functions,
                cached_resolved_relations,
                prev_call.as_deref(),
            )
        } else {
            crate::transaction::gen_tx_with_cached_fuzzable_simple(
                rng,
                dict,
                &env.world,
                &env.cfg.tx_conf,
                main_contract,
                env.cfg.sol_conf.contract_addr,
                effective_fuzzable,
            )
        };

        if let Some(ref mut tx) = tx {
            // Apply argument clamps from web UI (if any)
            if let evm::types::TxCall::SolCall { ref name, .. } = &tx.call {
                let func_name = name.clone();
                // Find the function to get param types
                if let Some(func) = effective_fuzzable.iter().find(|f| f.name == func_name) {
                    let selector = func.selector();
                    let param_types = main_contract.get_param_types(&selector);
                    crate::transaction::apply_clamps(tx, &env.arg_clamps, param_types);
                }
                prev_call = Some(func_name);
            }
            sequence.push(tx.clone());
        }
    }

    use crate::corpus::{
        apply_corpus_mutation, seq_mutators_stateful, seq_mutators_stateless,
        DEFAULT_MUTATION_CONSTS,
    };

    let mutation = if seq_len == 1 {
        seq_mutators_stateless(rng, DEFAULT_MUTATION_CONSTS)
    } else {
        seq_mutators_stateful(rng, DEFAULT_MUTATION_CONSTS)
    };

    // Corpus uses Arc<Vec<Tx>> - clone is cheap (just ref count increment)
    let corpus = env.corpus_ref.read();
    let mut corpus_with_priority: Vec<CorpusEntry> = corpus.clone();

    // Find max priority for optimization test reproducers
    let base_priority = corpus.iter().map(|(p, _)| *p).max().unwrap_or(0) + 1;
    drop(corpus);

    for (idx, test_ref) in env.test_refs.iter().enumerate() {
        let test = test_ref.read();
        if matches!(test.test_type, crate::testing::TestType::OptimizationTest { .. })
            && !test.reproducer.is_empty()
        {
            // Wrap reproducer in Arc for consistency with corpus entries
            corpus_with_priority.push((base_priority + idx, Arc::new(test.reproducer.clone())));
        }
    }

    // Sort by priority in DESCENDING order to match Echidna's Set.toDescList
    // This ensures newer/higher-priority sequences come first in weighted selection
    corpus_with_priority.sort_by(|a, b| b.0.cmp(&a.0));

    if corpus_with_priority.is_empty() {
        Ok(sequence)
    } else {
        let mutated_seq =
            apply_corpus_mutation(rng, mutation, seq_len, &corpus_with_priority, &sequence);
        Ok(mutated_seq)
    }
}

/// Replay a transaction sequence (WorkerEnv variant)
pub fn replay_sequence_worker(
    vm: &mut EvmState,
    tx_seq: &[Tx],
    worker: &mut WorkerState,
    env: &WorkerEnv,
) -> anyhow::Result<()> {
    // Clone initial VM state BEFORE execution (needed for shortcut expansion)
    let initial_vm = if env.cfg.campaign_conf.shortcuts_enable {
        Some(vm.clone())
    } else {
        None
    };

    let (results, new_cov) = execute_sequence_worker(vm, tx_seq, env, worker)?;
    worker.ncalls += tx_seq.len();

    if new_cov {
        // Compute corpus hash for naming expanded files (must match save_coverage_sequence_worker)
        let corpus_hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            // Use to_string_pretty to match save_coverage_sequence_worker hash computation
            if let Ok(json) = serde_json::to_string_pretty(&tx_seq) {
                json.hash(&mut hasher);
            }
            hasher.finish()
        };

        // Save original corpus with priority = ncallseqs + 1
        // addToCorpus (ncallseqs + 1) - using +1 ensures first entry has weight > 0
        // Without +1, first sequence has priority 0 = ZERO weight in selection = NEVER replayed!
        crate::corpus::add_to_corpus_worker(env, tx_seq.to_vec(), worker.ncallseqs + 1);

        // ON-DEMAND SHORTCUT EXPANSION: When a sequence with successful shortcut_* calls
        // finds new coverage, expand those shortcuts by tracing their external calls
        // and saving them as separate files. This ensures we only expand shortcuts that truly
        // reached new coverage.
        if let Some(ref initial) = initial_vm {
            let expanded = crate::shortcuts::expand_shortcuts_in_sequence(
                env,
                initial,
                tx_seq,
                &results,
                corpus_hash,
            );
            if expanded > 0 {
                tracing::debug!(
                    "[Shortcuts] Expanded {} shortcuts from coverage-finding sequence",
                    expanded
                );
            }
        }
    }

    Ok(())
}

/// Execute a transaction sequence with checkpoint support and adaptive optimization checking
/// Returns ((results, new_coverage), optimization_improved)
///
/// Key differences from execute_sequence_worker:
/// - Saves checkpoints when optimization improves (for checkpoint-based restart)
/// - Uses configurable check_interval instead of hardcoded OPTIMIZATION_CHECK_INTERVAL
/// - Returns whether optimization improved (for adaptive interval adjustment)
pub fn execute_sequence_worker_with_checkpoints(
    vm: &mut EvmState,
    tx_seq: &[Tx],
    env: &WorkerEnv,
    worker: &mut WorkerState,
    checkpoint_manager: &mut crate::types::CheckpointManager,
    checkpoint_enabled: bool,
    adaptive_check_enabled: bool,
    check_interval: usize,
) -> anyhow::Result<((Vec<TxResult>, bool), bool)> {
    let mut results = Vec::with_capacity(tx_seq.len());
    let mut new_coverage = false;
    let mut executed_so_far: Vec<Tx> = Vec::new();
    let mut optimization_improved = false;

    // Use configured interval (or default to 50 if not adaptive)
    let optimization_check_interval = if adaptive_check_enabled { check_interval } else { 50 };
    let mut tx_since_last_check: usize = 0;
    let has_optimization_test = env.test_refs.iter().any(|t| {
        matches!(t.read().test_type, crate::testing::TestType::OptimizationTest { .. })
    });

    // Track current best optimization value at start for checkpoint comparison
    let initial_best_value: Option<I256> = env.test_refs.iter()
        .filter_map(|t| {
            let test = t.read();
            if matches!(test.test_type, crate::testing::TestType::OptimizationTest { .. }) {
                if let crate::testing::TestValue::IntValue(v) = &test.value {
                    return Some(*v);
                }
            }
            None
        })
        .max();

    for tx in tx_seq {
        let (result, local_cov) =
            vm.exec_tx_check_new_cov(
                tx,
                &env.coverage_ref_runtime,
                &env.codehash_map,
            )?;
        executed_so_far.push(tx.clone());

        if local_cov {
            new_coverage = true;
            if let TxCall::SolCall { name, args } = &tx.call {
                worker.gen_dict.add_call((name.clone(), args.clone()));
            }
        }

        // Optimization test checking - check after EVERY tx when optimization test exists
        tx_since_last_check += 1;
        let is_last_tx = executed_so_far.len() == tx_seq.len();
        let should_check_expensive = has_optimization_test  // Always check if optimization test 
            || is_last_tx
            || local_cov
            || tx_since_last_check >= optimization_check_interval;

        if should_check_expensive {
            // Check tests and detect if optimization improved
            let opt_improved_this_check = check_tests_after_tx_worker_with_checkpoint(
                env, vm, &executed_so_far, worker,
                checkpoint_manager, checkpoint_enabled, initial_best_value
            )?;
            if opt_improved_this_check {
                optimization_improved = true;
            }
            tx_since_last_check = 0;
        } else {
            check_cheap_tests_after_tx_worker(env, vm, &executed_so_far, worker)?;
        }

        // Extract return values to dictionary (rTypes)
        match result {
            TxResult::Stop | TxResult::ReturnTrue | TxResult::ReturnFalse => {
                if let TxCall::SolCall { name, .. } = &tx.call {
                    if let Some(ty) = worker.gen_dict.return_types.get(name) {
                        let output = vm.get_last_output();
                        if !output.is_empty() {
                            if let Ok(val) = ty.abi_decode(&output) {
                                add_return_value_to_dict(&mut worker.gen_dict, val);
                            }
                        }
                    }
                }
            }
            TxResult::ErrorRevert => {
                // Track revert hotspots for web UI visualization
                for (codehash, pc) in vm.get_last_touched_pcs() {
                    crate::worker_env::record_revert_hotspot(env, *codehash, *pc);
                }
            }
            _ => {}
        }

        // Capture addresses from CREATE transactions
        if let Some(revm::context_interface::result::ExecutionResult::Success {
            output: revm::context_interface::result::Output::Create(_, Some(addr)),
            ..
        }) = &vm.last_result
        {
            worker.gen_dict.add_value(alloy_dyn_abi::DynSolValue::Address(*addr));
        }

        for addr in &vm.last_created_addresses {
            worker.gen_dict.add_value(alloy_dyn_abi::DynSolValue::Address(*addr));
        }

        // Extract storage changes to dictionary (state diff extraction)
        // This helps with stateful fuzzing by capturing values like position[id][onBehalf].supplyShares
        // after supply(), making them available for withdraw() to use as valid shares parameter
        for (_addr, _slot, _old_val, new_val) in vm.get_last_state_diff() {
            // Only add non-zero values to avoid polluting dictionary
            if !new_val.is_zero() {
                worker.gen_dict.dict_values.insert(new_val);
            }
        }

        results.push(result);
        if local_cov {
            debug!("New coverage found");
        }
        new_coverage |= local_cov;
        // Use actual gas consumed, not gas limit (vm'.burned - vm.burned)
        let gas_used = vm.get_last_gas_used();
        worker.total_gas += gas_used;

        // Record call stats for web UI
        if let Some(ref web_state) = env.web_state {
            web_state.record_call(worker.worker_id, gas_used);
        }
    }

    // Record sequence completion for web UI
    if let Some(ref web_state) = env.web_state {
        web_state.record_sequence(worker.worker_id);
    }

    Ok(((results, new_coverage), optimization_improved))
}

/// Execute a transaction sequence and check for new coverage (WorkerEnv variant)
/// Uses local coverage tracking to minimize lock contention
pub fn execute_sequence_worker(
    vm: &mut EvmState,
    tx_seq: &[Tx],
    env: &WorkerEnv,
    worker: &mut WorkerState,
) -> anyhow::Result<(Vec<TxResult>, bool)> {
    let mut results = Vec::with_capacity(tx_seq.len());
    let mut new_coverage = false;
    let mut executed_so_far: Vec<Tx> = Vec::new();

    // PERF: Only check OptimizationTest every N transactions to avoid VM clone overhead
    // PropertyTest is ALWAYS checked every tx
    // OptimizationTest can be batched since missing intermediate values is acceptable trade-off
    const OPTIMIZATION_CHECK_INTERVAL: usize = 50;
    let mut tx_since_last_opt_check: usize = 0;
    let has_optimization_test = env.test_refs.iter().any(|t| {
        matches!(t.read().test_type, crate::testing::TestType::OptimizationTest { .. })
    });

    // Set context for vm.generateCalls() cheatcode (on-demand reentrancy testing)
    // The cheatcode will call gen_abi_call_m directly for identical behavior to main fuzzer
    if let Some(ref contract) = env.main_contract {
        let fuzzable = contract.fuzzable_functions(true); // mutable only for reentrancy
        let fuzzable_funcs: Vec<_> = fuzzable
            .iter()
            .map(|f| {
                let selector = f.selector();
                let param_types = contract.get_param_types(&selector).to_vec();
                (selector, f.name.clone(), param_types)
            })
            .collect();

        if !fuzzable_funcs.is_empty() {
            vm.generate_calls_context = Some((
                fuzzable_funcs,
                worker.gen_dict.clone(),
                rand::random::<u64>(), // Random seed for this sequence
            ));
        }
    }

    for tx in tx_seq {
        // Execute with local coverage tracking
        let (result, local_cov) = vm.exec_tx_check_new_cov(
            tx,
            &env.coverage_ref_runtime,
            &env.codehash_map,
        )?;

        executed_so_far.push(tx.clone());

        if local_cov {
            new_coverage = true;
            if let TxCall::SolCall { name, args } = &tx.call {
                worker.gen_dict.add_call((name.clone(), args.clone()));
            }
        }

        // Check ALL tests after EVERY transaction when optimization test exists
        // This is critical for both bug-finding AND optimization mode corpus replay!
        // Optimization values can peak at intermediate states, so we must check every tx.
        tx_since_last_opt_check += 1;
        let is_last_tx = executed_so_far.len() == tx_seq.len();
        let should_check_optimization = has_optimization_test
            || is_last_tx
            || local_cov
            || tx_since_last_opt_check >= OPTIMIZATION_CHECK_INTERVAL;

        if should_check_optimization {
            // Check ALL tests including OptimizationTest
            check_tests_after_tx_worker(env, vm, &executed_so_far, worker)?;
            tx_since_last_opt_check = 0;
        } else {
            // Check PropertyTest, CallTest, AssertionTest every tx (skip only OptimizationTest)
            check_tests_without_optimization_worker(env, vm, &executed_so_far, worker)?;
        }

        match result {
            TxResult::Stop | TxResult::ReturnTrue | TxResult::ReturnFalse => {
                // Extract return values (returnValues)
                if let TxCall::SolCall { name, .. } = &tx.call {
                    if let Some(ty) = worker.gen_dict.return_types.get(name) {
                        let output = vm.get_last_output();
                        if !output.is_empty() {
                            if let Ok(val) = ty.abi_decode(&output) {
                                add_return_value_to_dict(&mut worker.gen_dict, val);
                            }
                        }
                    }
                }

                // Extract event values (extractEventValues)
                let logs = vm.get_last_logs();
                for log in logs {
                    if let Some(topic0) = log.topics().first() {
                        if let Some(event) = env.event_map.get(topic0) {
                            // Extract NON-INDEXED parameters from log.data (original behavior)
                            let mut non_indexed_types = Vec::new();
                            for input in &event.inputs {
                                if !input.indexed {
                                    if let Ok(ty) = input.resolve() {
                                        non_indexed_types.push(ty);
                                    }
                                }
                            }

                            if !non_indexed_types.is_empty() {
                                let tuple_ty = DynSolType::Tuple(non_indexed_types);
                                if let Ok(val) = tuple_ty.abi_decode(&log.data.data) {
                                    add_return_value_to_dict(&mut worker.gen_dict, val);
                                }
                            }

                            // NEW: Extract INDEXED parameters from topics[1..] (Echidna TODO)
                            // Indexed parameters are stored as raw 32-byte values in topics
                            let indexed_inputs: Vec<_> = event.inputs.iter()
                                .filter(|input| input.indexed)
                                .collect();

                            // topics[0] is event signature, topics[1..] are indexed params
                            for (topic, input) in log.topics().iter().skip(1).zip(indexed_inputs.iter()) {
                                // Try to decode based on the type
                                if let Ok(ty) = input.resolve() {
                                    // For value types (uint, int, address, bool, bytesN), decode directly
                                    // For reference types (string, bytes, arrays), topic contains keccak256 hash
                                    match &ty {
                                        DynSolType::Address => {
                                            // Address is stored in lower 20 bytes
                                            let addr = Address::from_slice(&topic.0[12..32]);
                                            worker.gen_dict.add_value(alloy_dyn_abi::DynSolValue::Address(addr));
                                            tracing::trace!("Extracted indexed address from event {}: {:?}", event.name, addr);
                                        }
                                        DynSolType::Uint(_) => {
                                            // Uint is stored as big-endian 256-bit value
                                            let val = U256::from_be_bytes(topic.0);
                                            worker.gen_dict.dict_values.insert(val);
                                            tracing::trace!("Extracted indexed uint from event {}: {}", event.name, val);
                                        }
                                        DynSolType::Int(_) => {
                                            // Int is stored as big-endian 256-bit two's complement
                                            let val = alloy_primitives::I256::from_be_bytes(topic.0);
                                            worker.gen_dict.signed_dict_values.insert(val);
                                            tracing::trace!("Extracted indexed int from event {}: {}", event.name, val);
                                        }
                                        DynSolType::Bool => {
                                            // Bool is stored as 0 or 1 in the last byte
                                            let val = topic.0[31] != 0;
                                            worker.gen_dict.add_value(alloy_dyn_abi::DynSolValue::Bool(val));
                                        }
                                        DynSolType::FixedBytes(n) => {
                                            // Fixed bytes stored left-aligned in the 32-byte topic
                                            // DynSolValue::FixedBytes holds a full Word (FixedBytes<32>) plus the logical size
                                            worker.gen_dict.add_value(alloy_dyn_abi::DynSolValue::FixedBytes(
                                                alloy_primitives::FixedBytes::from_slice(&topic.0), *n
                                            ));
                                        }
                                        // String, Bytes, Arrays: topic contains keccak256 hash, not useful for dict
                                        _ => {
                                            // Still add the raw topic as a U256 - could be useful
                                            let val = U256::from_be_bytes(topic.0);
                                            worker.gen_dict.dict_values.insert(val);
                                        }
                                    }
                                } else {
                                    // Fallback: add raw topic as U256
                                    let val = U256::from_be_bytes(topic.0);
                                    worker.gen_dict.dict_values.insert(val);
                                }
                            }
                        }
                    }
                }
            }
            TxResult::ErrorRevert => {
                // Track revert hotspots for web UI visualization
                // When a transaction reverts, record all touched PCs as potential hotspots
                // The most frequently hit PCs across many reverts will bubble up as true hotspots
                for (codehash, pc) in vm.get_last_touched_pcs() {
                    crate::worker_env::record_revert_hotspot(env, *codehash, *pc);
                }
            }
            _ => {
                // Other errors (OutOfGas, etc.) - could track these separately if needed
            }
        }

        // Capture addresses from top-level CREATE transactions
        if let Some(revm::context_interface::result::ExecutionResult::Success {
            output: revm::context_interface::result::Output::Create(_, Some(addr)),
            ..
        }) = &vm.last_result
        {
            worker
                .gen_dict
                .add_value(alloy_dyn_abi::DynSolValue::Address(*addr));
        }

        // Capture addresses from internal CREATE/CREATE2 (factory patterns)
        // This adds newly deployed contract addresses to the dictionary for future fuzzing
        for addr in &vm.last_created_addresses {
            worker
                .gen_dict
                .add_value(alloy_dyn_abi::DynSolValue::Address(*addr));
        }

        // Extract storage changes to dictionary (state diff extraction)
        // This helps with stateful fuzzing by capturing values like position[id][onBehalf].supplyShares
        // after supply(), making them available for withdraw() to use as valid shares parameter
        for (_addr, _slot, _old_val, new_val) in vm.get_last_state_diff() {
            // Only add non-zero values to avoid polluting dictionary
            if !new_val.is_zero() {
                worker.gen_dict.dict_values.insert(new_val);
            }
        }

        results.push(result);
        if local_cov {
            debug!("New coverage found");
        }
        new_coverage |= local_cov;
        // Use actual gas consumed, not gas limit (vm'.burned - vm.burned)
        let gas_used = vm.get_last_gas_used();
        worker.total_gas += gas_used;

        // Record call stats for web UI
        if let Some(ref web_state) = env.web_state {
            web_state.record_call(worker.worker_id, gas_used);
        }
    }

    // Record sequence completion for web UI
    if let Some(ref web_state) = env.web_state {
        web_state.record_sequence(worker.worker_id);
    }

    Ok((results, new_coverage))
}
