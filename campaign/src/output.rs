//! Output formatting and file generation

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_dyn_abi::JsonAbiExt;
use alloy_primitives::{Address, U256};
use evm::tracing::TraceDecoder;
use evm::{exec::EvmState, foundry::CompiledContract, types::{Tx, TxCall}};

use crate::config::Env;
use crate::worker_env::WorkerEnv;

/// Format a transaction for Echidna-compatible output
/// Format: ContractName.function(args) Value: 0xHEX from: 0x... Time delay: X seconds Block delay: Y
pub fn format_tx(tx: &Tx, contract_name: &str) -> String {
    let call_str = match &tx.call {
        TxCall::SolCall { name, args } => {
            let args_str: Vec<String> = args.iter().map(format_sol_value).collect();
            format!("{}.{}({})", contract_name, name, args_str.join(","))
        }
        TxCall::NoCall => "*wait*".to_string(),
        TxCall::SolCalldata(data) => format!("0x{}", hex::encode(data)),
        TxCall::SolCreate(_) => format!("{}.constructor()", contract_name),
    };

    // Build extras like Echidna (exact format for log-parser compatibility)
    let mut extras = Vec::new();

    // Add Value field for payable transactions (Echidna format: Value: 0xHEX)
    if !tx.value.is_zero() {
        extras.push(format!("Value: 0x{:x}", tx.value));
    }

    extras.push(format!("from: {:?}", tx.src));
    if tx.delay.0 > 0 {
        extras.push(format!("Time delay: {} seconds", tx.delay.0));
    }
    if tx.delay.1 > 0 {
        extras.push(format!("Block delay: {}", tx.delay.1));
    }

    format!("{} {}", call_str, extras.join(" "))
}

/// Format a transaction sequence for display
pub fn format_call_sequence(txs: &[Tx], contract_name: &str) -> Vec<String> {
    txs.iter().map(|tx| format_tx(tx, contract_name)).collect()
}

/// Format the `vm.generateCalls()` invocations recorded during a tx into
/// human-readable annotation lines. Returns lines per invocation; if
/// `decode_with` is `Some((gen_dict, fuzzable_functions, contract_name))`,
/// each kept call is also regenerated and decoded as
/// `ContractName.fn(args)` so the user sees exactly what the harness
/// invoked. Otherwise only the seed and indices are shown.
pub fn format_generate_calls(
    tx: &Tx,
    decode_with: Option<(
        &std::sync::Arc<abi::types::GenDict>,
        &[(
            alloy_primitives::FixedBytes<4>,
            String,
            Vec<alloy_dyn_abi::DynSolType>,
        )],
        &str,
    )>,
) -> Vec<String> {
    if tx.generate_calls.is_empty() {
        return Vec::new();
    }
    let seed = tx.generate_calls_seed.unwrap_or(0);
    let mut lines = Vec::new();
    let mut call_count_so_far: usize = 0;
    for (i, rec) in tx.generate_calls.iter().enumerate() {
        let header = match &rec.keep_mask {
            Some(mask) => {
                let kept: Vec<usize> = mask
                    .iter()
                    .enumerate()
                    .filter_map(|(j, b)| if *b { Some(j) } else { None })
                    .collect();
                format!(
                    "  vm.generateCalls(#{}): kept {} of {} (seed=0x{:016x}, indices={:?})",
                    i,
                    kept.len(),
                    rec.n,
                    seed,
                    kept
                )
            }
            None => format!(
                "  vm.generateCalls(#{}): kept all {} (seed=0x{:016x})",
                i, rec.n, seed
            ),
        };
        lines.push(header);

        if let Some((dict, fuzzable, cname)) = decode_with {
            // Regenerate using the same per-invocation seed the cheatcode would.
            let inv_seed = seed.wrapping_add(call_count_so_far as u64);
            let kept = evm::cheatcodes::CheatcodeInspector::regenerate_kept_calls(
                inv_seed,
                rec.n,
                rec.keep_mask.as_ref(),
                dict,
                fuzzable,
            );
            for (j, name, args) in kept {
                let args_str: Vec<String> = args.iter().map(format_sol_value).collect();
                lines.push(format!(
                    "    [#{}] {}.{}({})",
                    j,
                    cname,
                    name,
                    args_str.join(", ")
                ));
            }
        }
        // Cheatcode advances call_count by full requested count, so seeds
        // for subsequent invocations align even when masks dropped calls.
        call_count_so_far += rec.n;
    }
    lines
}

/// Multi-contract variant of `format_tx`. Resolves the contract name per-tx
/// from `tx.dst → deployed_addresses`, falling back to `fallback_name` if the
/// destination isn't in the deployed list.
pub fn format_tx_multi(
    tx: &Tx,
    deployed_addresses: &[(Address, String)],
    fallback_name: &str,
) -> String {
    let target_name = deployed_addresses
        .iter()
        .find(|(a, _)| *a == tx.dst)
        .map(|(_, l)| l.as_str())
        .unwrap_or(fallback_name);
    format_tx(tx, target_name)
}

/// Multi-contract variant of `format_call_sequence`. Each tx's contract name
/// is resolved from `tx.dst` against `deployed_addresses`, falling back to
/// `fallback_name`. Use this in operator-style multi-target sessions; the
/// existing single-contract CLI flow keeps using `format_call_sequence`.
pub fn format_call_sequence_multi(
    txs: &[Tx],
    deployed_addresses: &[(Address, String)],
    fallback_name: &str,
) -> Vec<String> {
    txs.iter()
        .map(|tx| format_tx_multi(tx, deployed_addresses, fallback_name))
        .collect()
}

/// Format a Solidity value for display (Echidna-compatible)
pub fn format_sol_value(val: &alloy_dyn_abi::DynSolValue) -> String {
    use alloy_dyn_abi::DynSolValue;
    match val {
        DynSolValue::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        DynSolValue::Int(n, _) => format!("{}", n),
        DynSolValue::Uint(n, _) => format!("{}", n),
        DynSolValue::FixedBytes(b, _) => format!("0x{}", hex::encode(b)),
        DynSolValue::Address(a) => format!("{:#x}", a),
        DynSolValue::Function(f) => format!("0x{}", hex::encode(f)),
        DynSolValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        DynSolValue::String(s) => format!("\"{}\"", s),
        DynSolValue::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_sol_value).collect();
            format!("[{}]", items.join(","))
        }
        DynSolValue::FixedArray(arr) => {
            let items: Vec<String> = arr.iter().map(format_sol_value).collect();
            format!("[{}]", items.join(","))
        }
        DynSolValue::Tuple(t) => {
            let items: Vec<String> = t.iter().map(format_sol_value).collect();
            format!("({})", items.join(","))
        }
    }
}

/// Print a timestamp in Echidna format: [YYYY-MM-DD HH:MM:SS.ss]
pub fn format_timestamp() -> String {
    use chrono::Local;
    let now = Local::now();
    format!(
        "[{}.{:02}]",
        now.format("%Y-%m-%d %H:%M:%S"),
        now.timestamp_subsec_millis() / 10
    )
}

/// Print a worker message in Echidna format
pub fn print_worker_msg(worker_id: usize, msg: &str) {
    println!("{} [Worker {}] {}", format_timestamp(), worker_id, msg);
}

/// Shrinking worker info for status display
pub struct ShrinkingWorker {
    pub worker_id: usize,
    pub step: i32,
    pub shrink_limit: usize,
    pub seq_length: usize,
}

/// Print a status message in Echidna format
pub fn print_status(
    tests_failed: usize,
    total_tests: usize,
    ncalls: usize,
    test_limit: usize,
    opt_values: &[i128],
    coverage: usize,
    corpus_size: usize,
    shrinking_workers: &[ShrinkingWorker],
    gas_per_second: u64,
) {
    let shrinking_part = if shrinking_workers.is_empty() {
        String::new()
    } else {
        let workers_str: Vec<String> = shrinking_workers
            .iter()
            .map(|w| {
                format!(
                    "W{}:{}/{}({})",
                    w.worker_id, w.step, w.shrink_limit, w.seq_length
                )
            })
            .collect();
        format!(", shrinking: {}", workers_str.join(" "))
    };

    // Format optimization values like values: [1, 2, 3]
    let values_str = format!("{:?}", opt_values);

    println!(
        "{} [status] tests: {}/{}, fuzzing: {}/{}, values: {}, cov: {}, corpus: {}{}, gas/s: {}",
        format_timestamp(),
        tests_failed,
        total_tests,
        ncalls,
        test_limit,
        values_str,
        coverage,
        corpus_size,
        shrinking_part,
        gas_per_second
    );
}

/// Print new coverage message
pub fn print_new_coverage(
    worker_id: usize,
    coverage: usize,
    codehashes: usize,
    corpus_size: usize,
) {
    print_worker_msg(
        worker_id,
        &format!(
            "New coverage: {} instr, {} contracts, {} seqs in corpus",
            coverage, codehashes, corpus_size
        ),
    );
}

/// Print test failure message with call sequence
pub fn print_test_failure(worker_id: usize, test_name: &str, txs: &[Tx], contract_name: &str) {
    print_worker_msg(worker_id, &format!("Test {} falsified!", test_name));
    println!("  Call sequence:");
    for tx in txs {
        println!("{}", format_tx(tx, contract_name));
        // No dict snapshot or main contract available here — emit the
        // seed/indices header without decoded bodies. Callers that have
        // both can use `format_generate_calls(..., Some((..)))` directly.
        for line in format_generate_calls(tx, None) {
            println!("{}", line);
        }
    }
}

/// Generate a unique filename for a reproducer
fn generate_reproducer_filename() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let mut hasher = DefaultHasher::new();
    now.as_nanos().hash(&mut hasher);
    let hash = hasher.finish();

    format!("{}.txt", hash)
}

/// Serialize a transaction sequence to Echidna reproducer format
pub fn serialize_reproducer(txs: &[Tx]) -> String {
    // Echidna uses a specific JSON format
    serde_json::to_string_pretty(txs).unwrap_or_else(|_| "[]".to_string())
}

/// Save a reproducer to the appropriate directory
pub fn save_reproducer(base_dir: &Path, subdir: &str, txs: &[Tx]) -> anyhow::Result<String> {
    let dir = base_dir.join(subdir);
    fs::create_dir_all(&dir)?;

    let filename = generate_reproducer_filename();
    let filepath = dir.join(&filename);

    let content = serialize_reproducer(txs);
    fs::write(&filepath, content)?;

    Ok(filepath.to_string_lossy().to_string())
}

/// Save a coverage sequence
pub fn save_coverage_sequence(env: &Env, txs: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("echidna"));
    let filepath = save_reproducer(corpus_dir, "coverage", txs)?;
    println!("{} Saved reproducer to {}", format_timestamp(), filepath);
    Ok(())
}

/// Save an unshrunk reproducer
pub fn save_unshrunk_reproducer(env: &Env, txs: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("echidna"));
    let filepath = save_reproducer(corpus_dir, "reproducers-unshrunk", txs)?;
    println!("{} Saved reproducer to {}", format_timestamp(), filepath);
    Ok(())
}

/// Save a shrunk reproducer
pub fn save_shrunk_reproducer(env: &Env, txs: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("echidna"));
    let filepath = save_reproducer(corpus_dir, "reproducers", txs)?;
    println!("{} Saved reproducer to {}", format_timestamp(), filepath);
    Ok(())
}

/// Save an optimization reproducer (reproducers-optimizations/)
pub fn save_optimization_reproducer(env: &Env, txs: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("echidna"));
    let filepath = save_reproducer(corpus_dir, "reproducers-optimizations", txs)?;
    println!("{} Saved reproducer to {}", format_timestamp(), filepath);
    Ok(())
}

// =============================================================================
// WorkerEnv variants - identical to Env functions but take WorkerEnv
// =============================================================================

/// Save an unshrunk reproducer (WorkerEnv variant)
pub fn save_unshrunk_reproducer_worker(env: &WorkerEnv, txs: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("echidna"));
    let filepath = save_reproducer(corpus_dir, "reproducers-unshrunk", txs)?;
    println!("{} Saved reproducer to {}", format_timestamp(), filepath);
    Ok(())
}

/// Save a shrunk reproducer (WorkerEnv variant)
pub fn save_shrunk_reproducer_worker(env: &WorkerEnv, txs: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("echidna"));
    let filepath = save_reproducer(corpus_dir, "reproducers", txs)?;
    println!("{} Saved reproducer to {}", format_timestamp(), filepath);
    Ok(())
}

/// Save an optimization reproducer (WorkerEnv variant)
pub fn save_optimization_reproducer_worker(env: &WorkerEnv, txs: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .as_ref()
        .map(|p| p.as_path())
        .unwrap_or(Path::new("echidna"));
    let filepath = save_reproducer(corpus_dir, "reproducers-optimizations", txs)?;
    println!("{} Saved reproducer to {}", format_timestamp(), filepath);
    Ok(())
}

/// Build a TraceDecoder from contracts and their deployed addresses
pub fn build_trace_decoder(
    contracts: &[CompiledContract],
    deployed_addresses: &[(Address, String)],
) -> TraceDecoder {
    let mut decoder = TraceDecoder::new();

    // Add ALL contracts by codehash first - this allows resolving contracts
    // deployed during setUp or via CREATE/CREATE2 by matching their bytecode
    for contract in contracts {
        decoder.add_contract_by_codehash(contract);
    }

    // Add known deployed contract addresses (explicit labels)
    for (addr, name) in deployed_addresses {
        if let Some(contract) = contracts.iter().find(|c| c.name == *name) {
            decoder.add_contract(*addr, contract);
        } else {
            // Just add as a label even if we don't have the contract
            decoder.add_label(*addr, name.clone());
        }
    }

    decoder
}

/// Print traces for a transaction sequence (Foundry-style output)
/// Uses revm-inspectors TracingInspector for detailed call traces with storage diffs
///
/// If `main_contract` is provided, sets up the generate_calls context for reentrancy
/// trace replay. Note: reentrancy calls during replay may differ from the original
/// execution since the RNG seed is not preserved.
///
/// Thin wrapper around `write_traces` that prints to stdout. Existing CLI call
/// sites use this; the operator crate uses `write_traces` with a String buffer.
pub fn print_traces(
    vm: &mut EvmState,
    txs: &[Tx],
    contract_name: &str,
    contracts: &[CompiledContract],
    deployed_addresses: &[(Address, String)],
    main_contract: Option<&CompiledContract>,
    gen_dict_snapshot: Option<&std::sync::Arc<abi::types::GenDict>>,
) {
    // StdoutWriter forwards `fmt::Write` calls to `println!`/`print!`.
    struct StdoutWriter;
    impl std::fmt::Write for StdoutWriter {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            // Use print! (not println!) since the writer protocol passes
            // explicit \n via writeln! upstream.
            print!("{}", s);
            Ok(())
        }
    }
    let mut sink = StdoutWriter;
    let _ = write_traces(
        &mut sink,
        vm,
        txs,
        contract_name,
        contracts,
        deployed_addresses,
        main_contract,
        gen_dict_snapshot,
    );
}

/// Render the same traces as `print_traces`, but write to any `fmt::Write` sink
/// (string buffer, file, network, etc.) instead of stdout.
///
/// This is the actual implementation of trace rendering. `print_traces` is a
/// thin wrapper that pipes the output to stdout for CLI use. The operator
/// crate's findings writer uses this directly with a `String` buffer so the
/// per-break `report.md` contains the exact same trace format the main CLI
/// prints to stdout — no drift, no duplication.
pub fn write_traces(
    out: &mut dyn std::fmt::Write,
    vm: &mut EvmState,
    txs: &[Tx],
    contract_name: &str,
    contracts: &[CompiledContract],
    deployed_addresses: &[(Address, String)],
    main_contract: Option<&CompiledContract>,
    gen_dict_snapshot: Option<&std::sync::Arc<abi::types::GenDict>>,
) -> std::fmt::Result {
    use alloy_primitives::keccak256;

    // Build the per-tx generateCalls cheatcode context for trace replay.
    // Per-tx wiring (inside the loop below) restores `tx.generate_calls_seed`
    // and `tx.generate_calls[*].keep_mask` so the trace shows exactly the
    // calls the failing run saw — including only the kept subset after
    // inner-batch shrink. Falls back to a fresh dict + dummy seed if no
    // snapshot was provided.
    let trace_gen_calls_ctx: Option<(
        Vec<(
            alloy_primitives::FixedBytes<4>,
            String,
            Vec<alloy_dyn_abi::DynSolType>,
        )>,
        std::sync::Arc<abi::types::GenDict>,
    )> = main_contract.and_then(|contract| {
        let fuzzable = contract.fuzzable_functions(true);
        let fuzzable_funcs: Vec<_> = fuzzable
            .iter()
            .map(|f| {
                let selector = f.selector();
                let param_types = contract.get_param_types(&selector).to_vec();
                (selector, f.name.clone(), param_types)
            })
            .collect();
        if fuzzable_funcs.is_empty() {
            None
        } else {
            let dict = gen_dict_snapshot
                .cloned()
                .unwrap_or_else(|| std::sync::Arc::new(abi::types::GenDict::new(0xDEADBEEF)));
            Some((fuzzable_funcs, dict))
        }
    });

    writeln!(out, "Traces:")?;

    // Build decoder for address/function resolution
    let mut decoder = build_trace_decoder(contracts, deployed_addresses);

    // Add labels from vm state (set during constructor via vm.label)
    for (addr, label) in &vm.labels {
        decoder.labels.insert(*addr, label.clone());
    }

    // Collect Log(string) events for display at the end
    let log_string_selector = keccak256("Log(string)");
    let mut debug_logs: Vec<(usize, String)> = Vec::new(); // (tx_index, message)

    // Build a fast (Address → label) lookup so we can resolve the per-tx contract
    // name from `tx.dst` instead of using the same `contract_name` for every tx.
    // Falls back to `contract_name` if the destination isn't in the deployed list
    // (covers the main fuzzer's single-target case identically since `tx.dst`
    // always equals the main contract's address there).
    let label_by_addr: std::collections::HashMap<Address, &str> = deployed_addresses
        .iter()
        .map(|(a, l)| (*a, l.as_str()))
        .collect();
    let resolve_target = |dst: Address| -> &str {
        label_by_addr.get(&dst).copied().unwrap_or(contract_name)
    };

    for (i, tx) in txs.iter().enumerate() {
        // Format function call header — resolve the contract name from tx.dst
        // so multi-contract sequences show the right contract per call.
        let target_name = resolve_target(tx.dst);
        let func_info = match &tx.call {
            TxCall::SolCall { name, args } => {
                let args_str: Vec<String> = args.iter().map(format_sol_value).collect();
                format!("{}.{}({})", target_name, name, args_str.join(", "))
            }
            TxCall::NoCall => {
                format!("*wait* {} seconds, {} blocks", tx.delay.0, tx.delay.1)
            }
            TxCall::SolCalldata(data) => format!("0x{}", hex::encode(data)),
            TxCall::SolCreate(_) => format!("{}.constructor()", target_name),
        };

        // Format sender - try to resolve to a label
        let sender_label = decoder
            .labels
            .get(&tx.src)
            .map(|s| s.as_str())
            .unwrap_or_else(|| "");
        let sender_str = if sender_label.is_empty() {
            format!("0x{}", hex::encode(&tx.src.0[16..20]))
        } else {
            format!("{} (..{})", sender_label, hex::encode(&tx.src.0[18..20]))
        };

        writeln!(out, "  [{}] {} from: {}", i, func_info, sender_str)?;

        // Per-tx wiring of the generateCalls context: restore the failing
        // run's seed and per-invocation keep-masks so traces reflect the
        // shrunk subset of calls. Clears the context for txs that didn't
        // invoke the cheatcode so a previous tx's wiring doesn't leak.
        if let Some((funcs, dict)) = &trace_gen_calls_ctx {
            if let Some(seed) = tx.generate_calls_seed {
                let masks: Vec<Option<Vec<bool>>> = tx
                    .generate_calls
                    .iter()
                    .map(|r| r.keep_mask.clone())
                    .collect();
                vm.generate_calls_context = Some(evm::exec::GenerateCallsRunCtx {
                    fuzzable_functions: funcs.clone(),
                    gen_dict: dict.clone(),
                    rng_seed: seed,
                    return_masks: masks,
                });
            } else {
                vm.generate_calls_context = None;
            }
        }

        // Execute with revm-inspectors TracingInspector
        match vm.exec_tx_with_revm_tracing(tx) {
            Ok((result, mut traces, storage_changes, _storage_reads, output_bytes, logs, _pcs)) => {
                // Extract vm.label() calls from traces and add to decoder + vm state
                let extracted_labels = evm::tracing::extract_labels_from_traces(&traces);
                for (addr, label) in extracted_labels {
                    decoder.labels.insert(addr, label.clone());
                    vm.labels.insert(addr, label);
                }

                // Collect Log(string) events from direct logs
                for log in &logs {
                    if let Some(topic0) = log.topics().first() {
                        if topic0.0 == log_string_selector.0 {
                            if let Some(msg) = decode_log_string_event(&log.data.data) {
                                debug_logs.push((i, msg));
                            }
                        }
                    }
                }

                // Also collect Log(string) events from trace arena (nested logs)
                for node in traces.nodes() {
                    for log in &node.logs {
                        if let Some(topic0) = log.raw_log.topics().first() {
                            if topic0.0 == log_string_selector.0 {
                                if let Some(msg) =
                                    decode_log_string_event(log.raw_log.data.as_ref())
                                {
                                    // Avoid duplicates
                                    if !debug_logs.iter().any(|(idx, m)| *idx == i && m == &msg) {
                                        debug_logs.push((i, msg));
                                    }
                                }
                            }
                        }
                    }
                }

                // Format traces with decoded addresses and functions,
                // resolving unknown addresses by codehash from VM state
                let trace_output = evm::tracing::format_traces_decoded_with_state(
                    &mut traces,
                    &mut decoder,
                    &mut vm.db,
                    true,
                );
                if !trace_output.is_empty() {
                    // Indent the trace output
                    for line in trace_output.lines() {
                        writeln!(out, "    {}", line)?;
                    }
                }

                // Show emitted events/logs with decoded values
                if !logs.is_empty() {
                    for log in logs.iter().take(10) {
                        let event_str = format_log_event(log, contracts);
                        writeln!(out, "    emit {}", event_str)?;
                    }
                    if logs.len() > 10 {
                        writeln!(out, "    ... {} more events", logs.len() - 10)?;
                    }
                }

                // Show storage changes with resolved addresses (labels now populated from state)
                if !storage_changes.is_empty() {
                    writeln!(out, "    Storage Changes:")?;
                    for (addr, slot, old_val, new_val) in storage_changes.iter().take(10) {
                        // Resolve address - may have been populated from state during trace formatting
                        let addr_label = decoder.resolve_address_with_state(addr, &mut vm.db);
                        let old_str = format_u256(*old_val);
                        let new_str = format_u256(*new_val);
                        // Format slot - show decimal for small slots, hex for large
                        let slot_str = if *slot < U256::from(100u64) {
                            format!("{}", slot)
                        } else {
                            format!("{:#x}", slot)
                        };
                        writeln!(
                            out,
                            "      {} [slot {}]: {} → {}",
                            addr_label, slot_str, old_str, new_str
                        )?;
                    }
                    if storage_changes.len() > 10 {
                        writeln!(out, "      ... {} more changes", storage_changes.len() - 10)?;
                    }
                }

                // Show result with decoded revert reason if applicable
                let result_str = match result {
                    evm::types::TxResult::Stop => "← [Stop]".to_string(),
                    evm::types::TxResult::ReturnTrue => "← [Return: true]".to_string(),
                    evm::types::TxResult::ReturnFalse => "← [Return: false/0] ❌".to_string(),
                    evm::types::TxResult::ErrorRevert => {
                        // Try to decode revert reason - first standard errors, then custom
                        if let Some(reason) =
                            decode_revert_with_abi_public(&output_bytes, contracts)
                        {
                            format!("← [Revert] {}", reason)
                        } else if !output_bytes.is_empty() {
                            format!("← [Revert] 0x{}", hex::encode(&output_bytes))
                        } else {
                            "← [Revert]".to_string()
                        }
                    }
                    evm::types::TxResult::ErrorAssertionFailed => "← [Assertion Failed] 💥".to_string(),
                    evm::types::TxResult::ErrorOutOfGas => "← [Out of Gas]".to_string(),
                    _ => "← [Error]".to_string(),
                };
                writeln!(out, "    {}", result_str)?;
            }
            Err(e) => {
                writeln!(out, "    Error: {}", e)?;
            }
        }
        writeln!(out)?;
    }

    // Print collected Log(string) debug messages at the end
    if !debug_logs.is_empty() {
        writeln!(out, "Debug Logs:")?;
        for (tx_idx, msg) in &debug_logs {
            writeln!(out, "  [{}] emit Log(«{}»)", tx_idx, msg)?;
        }
        writeln!(out)?;
    }

    Ok(())
}

/// Decode revert reason using standard errors and custom errors from ABIs
pub fn decode_revert_with_abi_public(
    data: &[u8],
    contracts: &[CompiledContract],
) -> Option<String> {
    use alloy_primitives::keccak256;

    if data.len() < 4 {
        return None;
    }

    // First try standard errors (Error(string) and Panic(uint256))
    if let Some(reason) = evm::tracing::decode_revert_reason(data) {
        // Check if it's just the raw selector (unknown error)
        if !reason.starts_with("0x") {
            return Some(reason);
        }
    }

    // Extract selector
    let selector: [u8; 4] = data[0..4].try_into().ok()?;

    // Search for matching custom error in contract ABIs
    for contract in contracts {
        for error in contract.abi.errors() {
            // Compute error signature hash
            let sig = format!(
                "{}({})",
                error.name,
                error
                    .inputs
                    .iter()
                    .map(|i| i.ty.clone())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let sig_hash = keccak256(sig.as_bytes());

            if sig_hash[0..4] == selector {
                // Found matching error! Decode parameters
                return Some(decode_custom_error(data, error));
            }
        }
    }

    // Unknown error - show selector
    Some(format!("0x{}", hex::encode(&selector)))
}

/// Decode a custom error using its ABI definition
fn decode_custom_error(data: &[u8], error: &alloy_json_abi::Error) -> String {
    // Always include parentheses to show it's a function-like error call
    if error.inputs.is_empty() {
        return format!("{}()", error.name);
    }

    // Try to use alloy's built-in decoder first (handles dynamic types properly)
    if data.len() > 4 {
        if let Ok(values) = error.abi_decode_input(&data[4..]) {
            let formatted: Vec<String> = error
                .inputs
                .iter()
                .zip(values.iter())
                .map(|(input, v)| {
                    let val_str = format_dyn_sol_value(v);
                    if input.name.is_empty() {
                        val_str
                    } else {
                        format!("{}: {}", input.name, val_str)
                    }
                })
                .collect();
            return format!("{}({})", error.name, formatted.join(", "));
        }
    }

    // Fallback: manual decoding for simple types
    let mut values = Vec::new();
    let mut offset = 4; // Skip selector

    for input in &error.inputs {
        if offset + 32 <= data.len() {
            let chunk: [u8; 32] = data[offset..offset + 32].try_into().unwrap_or([0; 32]);
            let val = match input.ty.as_str() {
                "address" => {
                    let addr = alloy_primitives::Address::from_slice(&chunk[12..32]);
                    if input.name.is_empty() {
                        format!("{:#x}", addr)
                    } else {
                        format!("{}: {:#x}", input.name, addr)
                    }
                }
                "bool" => {
                    let b = chunk[31] != 0;
                    if input.name.is_empty() {
                        format!("{}", b)
                    } else {
                        format!("{}: {}", input.name, b)
                    }
                }
                "string" | "bytes" => {
                    // Dynamic type - for now just show placeholder
                    if input.name.is_empty() {
                        "<dynamic>".to_string()
                    } else {
                        format!("{}: <dynamic>", input.name)
                    }
                }
                t if t.starts_with("uint") || t.starts_with("int") => {
                    let val = alloy_primitives::U256::from_be_bytes(chunk);
                    if val < alloy_primitives::U256::from(1_000_000u64) {
                        if input.name.is_empty() {
                            format!("{}", val)
                        } else {
                            format!("{}: {}", input.name, val)
                        }
                    } else {
                        if input.name.is_empty() {
                            format!("{:#x}", val)
                        } else {
                            format!("{}: {:#x}", input.name, val)
                        }
                    }
                }
                t if t.starts_with("bytes") => {
                    // bytesN - show hex
                    if input.name.is_empty() {
                        format!("0x{}", hex::encode(&chunk))
                    } else {
                        format!("{}: 0x{}", input.name, hex::encode(&chunk))
                    }
                }
                _ => {
                    if input.name.is_empty() {
                        format!("0x{}", hex::encode(&chunk))
                    } else {
                        format!("{}: 0x{}", input.name, hex::encode(&chunk))
                    }
                }
            };
            values.push(val);
            offset += 32;
        }
    }

    // Always include parentheses
    if values.is_empty() {
        format!("{}()", error.name)
    } else {
        format!("{}({})", error.name, values.join(", "))
    }
}

/// Format a DynSolValue for display
fn format_dyn_sol_value(value: &alloy_dyn_abi::DynSolValue) -> String {
    use alloy_dyn_abi::DynSolValue;

    match value {
        DynSolValue::Address(a) => format!("{:#x}", a),
        DynSolValue::Bool(b) => format!("{}", b),
        DynSolValue::Int(i, _) => {
            // Show decimal for small values, hex for large
            if *i >= alloy_primitives::I256::ZERO
                && *i < alloy_primitives::I256::try_from(1_000_000i64).unwrap_or_default()
            {
                format!("{}", i)
            } else {
                format!("{:#x}", i)
            }
        }
        DynSolValue::Uint(u, _) => {
            // Show decimal for small values, hex for large
            if *u < alloy_primitives::U256::from(1_000_000u64) {
                format!("{}", u)
            } else {
                format!("{:#x}", u)
            }
        }
        DynSolValue::FixedBytes(b, _) => format!("0x{}", hex::encode(b)),
        DynSolValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        DynSolValue::String(s) => format!("\"{}\"", s),
        DynSolValue::Array(arr) | DynSolValue::FixedArray(arr) => {
            let items: Vec<String> = arr.iter().map(format_dyn_sol_value).collect();
            format!("[{}]", items.join(", "))
        }
        DynSolValue::Tuple(t) => {
            let items: Vec<String> = t.iter().map(format_dyn_sol_value).collect();
            format!("({})", items.join(", "))
        }
        _ => format!("{:?}", value),
    }
}

/// Format a log/event for display with decoded event name and values
pub fn format_log_event(log: &revm::primitives::Log, contracts: &[CompiledContract]) -> String {
    use alloy_primitives::keccak256;

    // Get topic0 (event signature hash)
    let topic0 = match log.topics().first() {
        Some(t) => t,
        None => return format!("Anonymous(data: 0x{})", hex::encode(&log.data.data)),
    };

    // Try to find event in contract ABIs
    for contract in contracts {
        for event in contract.abi.events() {
            // Compute event signature hash
            let sig = format!(
                "{}({})",
                event.name,
                event
                    .inputs
                    .iter()
                    .map(|i| i.ty.clone())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let sig_hash = keccak256(sig.as_bytes());

            if sig_hash.0 == topic0.0 {
                // Found matching event! Decode it
                return decode_event(log, event);
            }
        }
    }

    // Unknown event - show raw data
    let addr_short = format!("0x{}", hex::encode(&log.address.0[..4]));
    let topic0_short = format!("0x{}", hex::encode(&topic0.0[..4]));
    format!(
        "[{}] {}(data: {} bytes)",
        addr_short,
        topic0_short,
        log.data.data.len()
    )
}

/// Decode a Log(string) event - extracts the string message from ABI-encoded data
fn decode_log_string_event(data: &[u8]) -> Option<String> {
    // ABI encoding for string:
    // - First 32 bytes: offset to string data (usually 0x20 = 32)
    // - Next 32 bytes: string length
    // - Following bytes: string content (padded to 32 bytes)

    if data.len() < 64 {
        return None;
    }

    // Read offset (first 32 bytes) - should be 32 for simple string
    let offset = U256::from_be_bytes::<32>(data[0..32].try_into().ok()?);
    let offset_usize: usize = offset.try_into().ok()?;

    if offset_usize + 32 > data.len() {
        return None;
    }

    // Read string length
    let len_bytes: [u8; 32] = data[offset_usize..offset_usize + 32].try_into().ok()?;
    let len = U256::from_be_bytes(len_bytes);
    let len_usize: usize = len.try_into().ok()?;

    if offset_usize + 32 + len_usize > data.len() {
        return None;
    }

    // Read string content
    let string_data = &data[offset_usize + 32..offset_usize + 32 + len_usize];
    String::from_utf8(string_data.to_vec()).ok()
}

/// Decode an event log using its ABI definition
fn decode_event(log: &revm::primitives::Log, event: &alloy_json_abi::Event) -> String {
    let mut values = Vec::new();

    // Decode indexed parameters from topics (skip topic0 which is the signature)
    let mut topic_idx = 1;
    for input in &event.inputs {
        if input.indexed {
            if topic_idx < log.topics().len() {
                let topic = &log.topics()[topic_idx];
                // Format based on type
                let val = match input.ty.as_str() {
                    "address" => {
                        let addr = alloy_primitives::Address::from_slice(&topic.0[12..32]);
                        format!("{}: {:#x}", input.name, addr)
                    }
                    "bool" => {
                        let b = topic.0[31] != 0;
                        format!("{}: {}", input.name, b)
                    }
                    t if t.starts_with("uint") || t.starts_with("int") => {
                        let val = alloy_primitives::U256::from_be_bytes(topic.0);
                        if val < alloy_primitives::U256::from(1_000_000u64) {
                            format!("{}: {}", input.name, val)
                        } else {
                            format!("{}: {:#x}", input.name, val)
                        }
                    }
                    t if t.starts_with("bytes") => {
                        format!("{}: 0x{}", input.name, hex::encode(&topic.0))
                    }
                    _ => format!("{}: 0x{}", input.name, hex::encode(&topic.0)),
                };
                values.push(val);
                topic_idx += 1;
            }
        }
    }

    // Decode non-indexed parameters from data
    let data = &log.data.data;
    if !data.is_empty() {
        // Build the type tuple for non-indexed params
        let non_indexed: Vec<_> = event.inputs.iter().filter(|i| !i.indexed).collect();

        // Try to decode as a tuple
        let mut offset = 0;
        for input in non_indexed {
            if offset + 32 <= data.len() {
                let chunk: [u8; 32] = data[offset..offset + 32].try_into().unwrap_or([0; 32]);
                let val = match input.ty.as_str() {
                    "address" => {
                        let addr = alloy_primitives::Address::from_slice(&chunk[12..32]);
                        format!("{}: {:#x}", input.name, addr)
                    }
                    "bool" => {
                        let b = chunk[31] != 0;
                        format!("{}: {}", input.name, b)
                    }
                    "string" => {
                        // String is dynamic - skip for now, show as bytes
                        format!("{}: <string>", input.name)
                    }
                    t if t.starts_with("uint") || t.starts_with("int") => {
                        let val = alloy_primitives::U256::from_be_bytes(chunk);
                        if val < alloy_primitives::U256::from(1_000_000u64) {
                            format!("{}: {}", input.name, val)
                        } else {
                            format!("{}: {:#x}", input.name, val)
                        }
                    }
                    _ => format!("{}: 0x{}", input.name, hex::encode(&chunk)),
                };
                values.push(val);
                offset += 32;
            }
        }
    }

    format!("{}({})", event.name, values.join(", "))
}

/// Format U256 for display - show as decimal if small, hex if large
fn format_u256(val: U256) -> String {
    if val == U256::ZERO {
        "0".to_string()
    } else if val < U256::from(1_000_000u64) {
        format!("{}", val)
    } else {
        format!("{:#x}", val)
    }
}

/// Print deployment traces in Foundry-style format
/// This formats existing CallTraceArena without re-executing
pub fn print_deployment_traces(
    vm: &mut EvmState,
    traces: &mut evm::tracing::CallTraceArena,
    contract_name: &str,
    contracts: &[CompiledContract],
    deployed_addresses: &[(Address, String)],
) {
    use std::io::Write;

    eprintln!("\nDeployment Call Trace for {}:", contract_name);
    eprintln!("=======================");

    // Build decoder for address/function resolution
    let mut decoder = build_trace_decoder(contracts, deployed_addresses);

    // Format traces with decoded addresses and functions
    let trace_output =
        evm::tracing::format_traces_decoded_with_state(traces, &mut decoder, &mut vm.db, true);

    if !trace_output.is_empty() {
        for line in trace_output.lines() {
            eprintln!("  {}", line);
        }
    }

    eprintln!("=======================\n");
    let _ = std::io::stderr().flush();
}

/// Print deployment traces with minimal context (just VM state, no contract metadata)
/// Use this when contract metadata is not available
pub fn print_deployment_traces_minimal(
    vm: &mut EvmState,
    traces: &mut evm::tracing::CallTraceArena,
) {
    use std::io::Write;

    eprintln!("\nDeployment Call Trace:");
    eprintln!("=======================");

    // Create an empty decoder - will still resolve addresses from state
    let mut decoder = TraceDecoder::new();

    // Format traces, resolving addresses from VM state
    let trace_output =
        evm::tracing::format_traces_decoded_with_state(traces, &mut decoder, &mut vm.db, true);

    if !trace_output.is_empty() {
        for line in trace_output.lines() {
            eprintln!("  {}", line);
        }
    }

    eprintln!("=======================\n");
    let _ = std::io::stderr().flush();
}
