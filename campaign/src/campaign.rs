//! Fuzzing campaign logic

use evm::exec::EvmState;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info};

use evm::types::Tx;

use crate::config::Env;
use crate::corpus::add_to_corpus_worker;
use crate::execution::{
    execute_sequence_worker_with_checkpoints, generate_sequence_worker_cached,
    replay_sequence_worker,
};
use crate::output;
use crate::shrink::{close_and_shrink_optimization_tests, shrink_pending_tests_worker};
use crate::status::{
    all_tests_complete_worker, any_pending_shrink_for_worker_env, any_test_failed_worker,
    get_corpus_size_worker, get_coverage_stats_worker, print_status_worker, write_lcov_info_worker,
};
use crate::testing::check_tests_worker;
use crate::types::{WorkerState, WorkerStopReason};
use crate::worker_env::{CorpusEntry, WorkerEnv};

/// Run the fuzzing campaign with multiple workers
pub fn run_campaign(
    env: &mut Env,
    vm: EvmState,
    initial_corpus: Vec<CorpusEntry>,
    stop_flag: Arc<AtomicBool>,
    force_stop: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let start = Instant::now();

    // Generate random seed if not provided, and store it back for reporting
    let base_seed = env.cfg.campaign_conf.seed.unwrap_or_else(|| rand::random());
    // Update the config so the seed can be reported at the end
    env.cfg.campaign_conf.seed = Some(base_seed);

    let conf = &env.cfg.campaign_conf;
    let num_workers = conf.workers as usize;

    info!("Starting fuzzing campaign with {} workers", num_workers);
    info!(
        "Test limit: {} (shared across all workers), Sequence length: {}",
        conf.test_limit, conf.seq_len
    );

    // Shared state for status reporting
    let total_calls = Arc::new(AtomicUsize::new(0));
    let total_gas = Arc::new(AtomicUsize::new(0));

    // Clone shared refs for workers
    let test_refs = env.test_refs.clone();
    let coverage_ref_runtime = env.coverage_ref_runtime.clone();
    let coverage_ref_init = env.coverage_ref_init.clone();
    let corpus_ref = env.corpus_ref.clone();
    let corpus_seen = env.corpus_seen.clone();
    let cfg = env.cfg.clone();
    let main_contract = env.main_contract.clone();
    let world = env.world.clone();
    let event_map = env.event_map.clone();
    let codehash_map = env.codehash_map.clone();
    let slither_info = env.slither_info.clone();
    let contracts = Arc::new(env.contracts.clone());
    let project_path = std::env::current_dir().unwrap_or_default();
    let revert_hotspots = env.revert_hotspots.clone();
    let injected_dict_values = env.injected_dict_values.clone();
    let arg_clamps = env.arg_clamps.clone();
    let target_functions = env.target_functions.clone();
    let fuzz_templates = env.fuzz_templates.clone();
    let web_state = env.web_state.clone();
    let repro_writer = env.repro_writer.clone();
    // Setup-extracted dictionary values (from constructor/setUp traces)
    let setup_dict_values = env.setup_dict_values.clone();
    let setup_dict_addresses = env.setup_dict_addresses.clone();
    let setup_dict_signed = env.setup_dict_signed.clone();
    let setup_dict_tuples = env.setup_dict_tuples.clone();

    // Split corpus among workers (extract just sequences, ignoring priorities for replay)
    // Note: We clone from Arc here only for initial replay; runtime corpus uses Arc refs
    let initial_sequences: Vec<Vec<Tx>> = initial_corpus
        .into_iter()
        .map(|(_, txs)| (*txs).clone())
        .collect();
    let corpus_chunks: Vec<Vec<Vec<Tx>>> = {
        let chunk_size = (initial_sequences.len() + num_workers - 1) / num_workers.max(1);
        if chunk_size == 0 {
            vec![vec![]; num_workers]
        } else {
            initial_sequences
                .chunks(chunk_size.max(1))
                .map(|c| c.to_vec())
                .chain(std::iter::repeat(vec![]))
                .take(num_workers)
                .collect()
        }
    };

    // Spawn worker threads using scoped threads
    tracing::debug!("About to spawn {} workers", num_workers);
    thread::scope(|s| {
        let mut handles = Vec::new();

        for worker_id in 0..num_workers {
            tracing::debug!("Creating worker {}", worker_id);
            let stop_flag = stop_flag.clone();
            let force_stop = force_stop.clone();
            let total_calls = total_calls.clone();
            let total_gas = total_gas.clone();
            let test_refs = test_refs.clone();
            let coverage_ref_runtime = coverage_ref_runtime.clone();
            let coverage_ref_init = coverage_ref_init.clone();
            let corpus_ref = corpus_ref.clone();
            let corpus_seen = corpus_seen.clone();
            let cfg = cfg.clone();
            let main_contract = main_contract.clone();
            let world = world.clone();
            let event_map = event_map.clone();
            let codehash_map = codehash_map.clone();
            let slither_info = slither_info.clone();
            let contracts = contracts.clone();
            let project_path = project_path.clone();
            let revert_hotspots = revert_hotspots.clone();
            let injected_dict_values = injected_dict_values.clone();
            let arg_clamps = arg_clamps.clone();
            let target_functions = target_functions.clone();
            let fuzz_templates = fuzz_templates.clone();
            let web_state = web_state.clone();
            let repro_writer = repro_writer.clone();
            let vm = vm.clone();
            let corpus_chunk = corpus_chunks[worker_id].clone();
            let worker_seed = base_seed.wrapping_add(worker_id as u64);
            let setup_dict_values = setup_dict_values.clone();
            let setup_dict_addresses = setup_dict_addresses.clone();
            let setup_dict_signed = setup_dict_signed.clone();
            let setup_dict_tuples = setup_dict_tuples.clone();

            // Capture dict_freq before cfg moves into worker_env
            let dict_freq = cfg.campaign_conf.dict_freq;
            // Capture seed_file path before cfg moves
            let seed_file = cfg.campaign_conf.seed_file.clone();

            let handle = s.spawn(move || {
                tracing::debug!("Worker {} spawned", worker_id);
                // Create worker-local env-like context
                let worker_env = WorkerEnv {
                    cfg,
                    test_refs,
                    coverage_ref_runtime,
                    coverage_ref_init,
                    corpus_ref,
                    corpus_seen,
                    main_contract: main_contract.clone(),
                    world,
                    event_map,
                    codehash_map,
                    slither_info: slither_info.clone(),
                    contracts,
                    project_path,
                    revert_hotspots,
                    injected_dict_values,
                    arg_clamps,
                    target_functions,
                    fuzz_templates,
                    web_state: web_state.clone(),
                    setup_dict_values: setup_dict_values.clone(),
                    setup_dict_addresses: setup_dict_addresses.clone(),
                    setup_dict_signed: setup_dict_signed.clone(),
                    setup_dict_tuples: setup_dict_tuples.clone(),
                    repro_writer: repro_writer.clone(),
                };

                let mut worker = WorkerState::new(worker_id, worker_seed);

                // Apply dict_freq from config (dictFreq)
                worker.gen_dict.dict_freq = dict_freq;

                // Seed dictionary with bytecode constants 
                // This extracts constants from PUSH instructions and generates ±N, ±N±3 variants
                if let Some(ref contract) = main_contract {
                    worker
                        .gen_dict
                        .seed_from_bytecode(&contract.deployed_bytecode);
                }

                // Seed dictionary with slither/recon-generate constants (enhanceConstants)
                // This provides precise constants from source code analysis
                if let Some(ref info) = slither_info {
                    worker.gen_dict.seed_from_slither_info(info);
                }

                // EXTERNAL ORACLE SEEDING: Load values from external seed file
                // Allows users to inject known-good values from external analysis
                if let Some(ref seed_path) = seed_file {
                    match worker.gen_dict.seed_from_file(seed_path) {
                        Ok(count) => {
                            if worker_id == 0 && count > 0 {
                                tracing::info!(
                                    "Seeded {} values from external file: {:?}",
                                    count,
                                    seed_path
                                );
                            }
                        }
                        Err(e) => {
                            if worker_id == 0 {
                                tracing::warn!(
                                    "Failed to load seed file {:?}: {}",
                                    seed_path,
                                    e
                                );
                            }
                        }
                    }
                }

                // SETUP TRACE EXTRACTION: Seed dictionary with values from setUp/constructor
                // This captures struct values passed to external calls and event parameters at ALL depths
                if !setup_dict_values.is_empty() || !setup_dict_addresses.is_empty() || !setup_dict_signed.is_empty() || !setup_dict_tuples.is_empty() {
                    for val in &setup_dict_values {
                        worker.gen_dict.dict_values.insert(*val);
                    }
                    for addr in &setup_dict_addresses {
                        worker.gen_dict.add_value(alloy_dyn_abi::DynSolValue::Address(*addr));
                    }
                    for val in &setup_dict_signed {
                        worker.gen_dict.signed_dict_values.insert(*val);
                    }
                    // Add tuples/structs (e.g., MarketParams) to dictionary
                    for tuple in &setup_dict_tuples {
                        worker.gen_dict.add_value(tuple.clone());
                    }
                    if worker_id == 0 {
                        tracing::info!(
                            "Seeded dictionary from setUp traces: {} uint, {} addresses, {} signed, {} tuples",
                            setup_dict_values.len(),
                            setup_dict_addresses.len(),
                            setup_dict_signed.len(),
                            setup_dict_tuples.len()
                        );
                    }
                }

                // Populate return_types for learning from return values (rTypes)
                // This enables extracting return values and adding them to the dictionary
                // IMPROVED: Capture ALL output types as a tuple, not just the first one
                if let Some(ref contract) = main_contract {
                    use alloy_dyn_abi::{DynSolType, Specifier};
                    let mut return_types_count = 0;
                    for func in contract.abi.functions() {
                        if func.outputs.is_empty() {
                            continue;
                        }
                        // Resolve all output types
                        let output_types: Vec<DynSolType> = func.outputs
                            .iter()
                            .filter_map(|o| o.resolve().ok())
                            .collect();

                        if output_types.is_empty() {
                            continue;
                        }

                        // Create appropriate type: single value or tuple of all outputs
                        let ty = if output_types.len() == 1 {
                            output_types.into_iter().next().unwrap()
                        } else {
                            DynSolType::Tuple(output_types)
                        };

                        worker.gen_dict.return_types.insert(func.name.clone(), ty);
                        return_types_count += 1;
                    }
                    if worker_id == 0 {
                        tracing::info!(
                            "Populated {} return_types from ABI for dictionary learning",
                            return_types_count
                        );
                    }
                } else if worker_id == 0 {
                    tracing::debug!("main_contract is None - cannot populate return_types");
                }

                let result = run_fuzz_worker(
                    &worker_env,
                    vm,
                    &mut worker,
                    corpus_chunk,
                    stop_flag,
                    force_stop,
                    total_calls.clone(),
                    total_gas.clone(),
                );

                (worker_id, worker, result)
            });

            handles.push(handle);
        }

        // Wait for all workers
        for handle in handles {
            match handle.join() {
                Ok((id, _worker, result)) => {
                    debug!("Worker {} finished: {:?}", id, result);
                }
                Err(e) => {
                    tracing::error!("Worker thread panicked: {:?}", e);
                }
            }
        }
    });

    let elapsed = start.elapsed();
    let final_calls = total_calls.load(Ordering::Relaxed);
    info!("Campaign completed in {:.2}s", elapsed.as_secs_f64());
    info!("Total calls: {}", final_calls);

    Ok(())
}

/// Run a shrink-only campaign: no fuzzing, just shrink existing reproducers
/// All workers are dedicated to shrinking tests that have been pre-loaded with reproducers
pub fn run_shrink_campaign(
    env: &Env,
    vm: EvmState,
    force_stop: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let start = Instant::now();

    let base_seed = env.cfg.campaign_conf.seed.unwrap_or_else(|| rand::random());
    let num_workers = env.cfg.campaign_conf.workers as usize;

    info!("Starting shrink-only campaign with {} workers", num_workers);

    // Clone shared refs for workers
    let test_refs = env.test_refs.clone();
    let coverage_ref_runtime = env.coverage_ref_runtime.clone();
    let coverage_ref_init = env.coverage_ref_init.clone();
    let corpus_ref = env.corpus_ref.clone();
    let corpus_seen = env.corpus_seen.clone();
    let cfg = env.cfg.clone();
    let main_contract = env.main_contract.clone();
    let world = env.world.clone();
    let event_map = env.event_map.clone();
    let codehash_map = env.codehash_map.clone();
    let slither_info = env.slither_info.clone();
    let contracts = Arc::new(env.contracts.clone());
    let project_path = std::env::current_dir().unwrap_or_default();
    let revert_hotspots = env.revert_hotspots.clone();
    let injected_dict_values = env.injected_dict_values.clone();
    let arg_clamps = env.arg_clamps.clone();
    let target_functions = env.target_functions.clone();
    let fuzz_templates = env.fuzz_templates.clone();
    let web_state = env.web_state.clone();
    let repro_writer = env.repro_writer.clone();
    let setup_dict_values = env.setup_dict_values.clone();
    let setup_dict_addresses = env.setup_dict_addresses.clone();
    let setup_dict_signed = env.setup_dict_signed.clone();
    let setup_dict_tuples = env.setup_dict_tuples.clone();

    thread::scope(|s| {
        let mut handles = Vec::new();

        for worker_id in 0..num_workers {
            let force_stop = force_stop.clone();
            let test_refs = test_refs.clone();
            let coverage_ref_runtime = coverage_ref_runtime.clone();
            let coverage_ref_init = coverage_ref_init.clone();
            let corpus_ref = corpus_ref.clone();
            let corpus_seen = corpus_seen.clone();
            let cfg = cfg.clone();
            let main_contract = main_contract.clone();
            let world = world.clone();
            let event_map = event_map.clone();
            let codehash_map = codehash_map.clone();
            let slither_info = slither_info.clone();
            let contracts = contracts.clone();
            let project_path = project_path.clone();
            let revert_hotspots = revert_hotspots.clone();
            let injected_dict_values = injected_dict_values.clone();
            let arg_clamps = arg_clamps.clone();
            let target_functions = target_functions.clone();
            let fuzz_templates = fuzz_templates.clone();
            let web_state = web_state.clone();
            let repro_writer = repro_writer.clone();
            let vm = vm.clone();
            let worker_seed = base_seed.wrapping_add(worker_id as u64);
            let setup_dict_values = setup_dict_values.clone();
            let setup_dict_addresses = setup_dict_addresses.clone();
            let setup_dict_signed = setup_dict_signed.clone();
            let setup_dict_tuples = setup_dict_tuples.clone();

            let handle = s.spawn(move || {
                let worker_env = WorkerEnv {
                    cfg,
                    test_refs,
                    coverage_ref_runtime,
                    coverage_ref_init,
                    corpus_ref,
                    corpus_seen,
                    main_contract,
                    world,
                    event_map,
                    codehash_map,
                    slither_info,
                    contracts,
                    project_path,
                    revert_hotspots,
                    injected_dict_values,
                    arg_clamps,
                    target_functions,
                    fuzz_templates,
                    web_state,
                    setup_dict_values,
                    setup_dict_addresses,
                    setup_dict_signed,
                    setup_dict_tuples,
                    repro_writer,
                };

                let worker = WorkerState::new(worker_id, worker_seed);
                let mut rng = ChaCha8Rng::seed_from_u64(worker_seed);

                let result = run_shrink_worker(&worker_env, &vm, &worker, &mut rng, &force_stop);

                (worker_id, result)
            });

            handles.push(handle);
        }

        for handle in handles {
            match handle.join() {
                Ok((id, result)) => {
                    debug!("Shrink worker {} finished: {:?}", id, result);
                }
                Err(e) => {
                    tracing::error!("Shrink worker thread panicked: {:?}", e);
                }
            }
        }
    });

    let elapsed = start.elapsed();
    info!("Shrink campaign completed in {:.2}s", elapsed.as_secs_f64());

    Ok(())
}

/// Run a single shrink worker: loop shrinking until all tests assigned to this worker are done
fn run_shrink_worker(
    env: &WorkerEnv,
    initial_vm: &EvmState,
    worker: &WorkerState,
    rng: &mut impl Rng,
    force_stop: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut last_status = Instant::now();
    let status_interval = Duration::from_secs(3);

    loop {
        // Check force_stop
        if force_stop.load(Ordering::Relaxed) {
            output::print_worker_msg(worker.worker_id, "Force stop - aborting shrink");
            return Ok(());
        }

        // Check if this worker still has pending tests to shrink
        if !any_pending_shrink_for_worker_env(env, worker.worker_id) {
            return Ok(());
        }

        // Print status periodically (worker 0 only)
        if worker.worker_id == 0 && last_status.elapsed() >= status_interval {
            // Gather progress for all tests being shrunk
            let progress: Vec<String> = env
                .test_refs
                .iter()
                .filter_map(|t| {
                    let test = t.read();
                    if let crate::testing::TestState::Large(n) = test.state {
                        Some(format!(
                            "{}: {}/{} (len {})",
                            test.test_type.name(),
                            n,
                            env.cfg.campaign_conf.shrink_limit,
                            test.reproducer.len()
                        ))
                    } else {
                        None
                    }
                })
                .collect();

            if !progress.is_empty() {
                println!(
                    "{} Shrinking: {}",
                    output::format_timestamp(),
                    progress.join(", ")
                );
            }
            last_status = Instant::now();
        }

        shrink_pending_tests_worker(env, initial_vm, worker, rng, force_stop)?;
    }
}

/// Run a single fuzzing worker
fn run_fuzz_worker(
    env: &WorkerEnv,
    vm: EvmState,
    worker: &mut WorkerState,
    initial_corpus: Vec<Vec<Tx>>,
    stop_flag: Arc<AtomicBool>,
    force_stop: Arc<AtomicBool>,
    total_calls: Arc<AtomicUsize>,
    total_gas: Arc<AtomicUsize>,
) -> anyhow::Result<WorkerStopReason> {
    let mut rng = ChaCha8Rng::seed_from_u64(worker.gen_dict.seed);
    let status_interval = Duration::from_secs(3); // Print status every 3 seconds
    let mut last_status = Instant::now();

    // LCOV reporting: write coverage periodically (worker 0 only, if enabled)
    let lcov_enabled = env.cfg.campaign_conf.lcov_enable;
    let lcov_interval = Duration::from_secs(env.cfg.campaign_conf.lcov_interval);
    let mut last_lcov_write = Instant::now();

    // Gas tracking for gas/s calculation 
    let mut last_gas_update = Instant::now();
    let mut last_gas_total: u64 = 0;

    // Per-worker test limit (each worker gets testLimit / nworkers)
    let num_workers = env.cfg.campaign_conf.workers as usize;
    let per_worker_limit = env.cfg.campaign_conf.test_limit / num_workers;

    // PERF: Batch atomic counter updates to reduce cache line bouncing
    // Only sync to shared counters every COUNTER_SYNC_INTERVAL calls
    const COUNTER_SYNC_INTERVAL: usize = 100;
    let mut local_calls_pending: usize = 0;
    let mut local_gas_pending: usize = 0;

    // PERF: Pre-cache fuzzable functions and related data at worker startup
    // This avoids recomputing HashSets and filtering on every sequence generation
    let cached_assert_functions: std::collections::HashSet<String> = env
        .main_contract
        .as_ref()
        .and_then(|contract| {
            env.slither_info
                .as_ref()
                .map(|info| info.assert_functions(&contract.name).into_iter().collect())
        })
        .unwrap_or_default();

    let cached_resolved_relations = env
        .main_contract
        .as_ref()
        .and_then(|contract| {
            env.slither_info
                .as_ref()
                .map(|info| info.resolve_wrapper_relations(&contract.name))
        })
        .unwrap_or_default();

    let cached_fuzzable: Vec<alloy_json_abi::Function> = env
        .main_contract
        .as_ref()
        .map(|contract| {
            if !cached_assert_functions.is_empty() {
                contract
                    .fuzzable_functions_smart(
                        env.cfg.sol_conf.mutable_only,
                        &cached_assert_functions,
                    )
                    .into_iter()
                    .cloned()
                    .collect()
            } else {
                contract
                    .fuzzable_functions(env.cfg.sol_conf.mutable_only)
                    .into_iter()
                    .cloned()
                    .collect()
            }
        })
        .unwrap_or_default();

    // Save initial VM state for shrinking (Echidna passes initial vm to shrinkTest)
    // each sequence is executed from initial state, not accumulated state
    let initial_vm = vm.clone();

    // OPTIMIZATION: Checkpoint manager for intermediate state restarts
    // When enabled, saves promising VM states and occasionally restarts from them
    let checkpoint_enabled = env.cfg.campaign_conf.checkpoint_enable;
    let checkpoint_probability = env.cfg.campaign_conf.checkpoint_probability;
    let mut checkpoint_manager =
        crate::types::CheckpointManager::new(env.cfg.campaign_conf.checkpoint_count);

    // OPTIMIZATION: Adaptive check interval tracking
    // When we find improvements, check more often
    let adaptive_check_enabled = env.cfg.campaign_conf.adaptive_check;
    let mut last_optimization_improvement = Instant::now();
    let mut current_check_interval: usize = 50; // Start with standard interval

    // Replay initial corpus (each sequence from fresh initial state)
    // replayCorpus passes vm to callseq, which doesn't mutate the original
    tracing::debug!(
        "Worker {} replaying {} corpus sequences",
        worker.worker_id,
        initial_corpus.len()
    );
    for tx_seq in &initial_corpus {
        let mut vm_for_replay = initial_vm.clone();
        replay_sequence_worker(&mut vm_for_replay, tx_seq, worker, env)?;
    }
    tracing::debug!("Worker {} finished replaying corpus", worker.worker_id);

    // Main fuzzing loop
    loop {
        tracing::trace!("Worker {} entering main fuzzing loop", worker.worker_id);
        if stop_flag.load(Ordering::Relaxed) {
            // On interrupt, close optimization tests and shrink them before exiting
            // This matches the behavior at test_limit
            close_and_shrink_optimization_tests(env, &initial_vm, worker, &mut rng, &force_stop)?;
            return Ok(WorkerStopReason::Stopped);
        }

        // Print status periodically  - only worker 0 prints
        if worker.worker_id == 0 && last_status.elapsed() >= status_interval {
            // Calculate gas/s (delta-based calculation)
            let delta_time = last_gas_update.elapsed().as_secs();
            let delta_gas = worker.total_gas.saturating_sub(last_gas_total);
            let gas_per_second = if delta_time > 0 {
                delta_gas / delta_time
            } else {
                0
            };
            last_gas_update = Instant::now();
            last_gas_total = worker.total_gas;

            // Use total calls from all workers for status
            let global_calls = total_calls.load(Ordering::Relaxed);
            print_status_worker(
                env,
                global_calls,
                env.cfg.campaign_conf.test_limit,
                gas_per_second,
            );

            // Debug: log dictionary size periodically
            tracing::debug!(
                "Dictionary stats: dict_values={}, signed_dict_values={}, constants={}, whole_calls={}",
                worker.gen_dict.dict_values.len(),
                worker.gen_dict.signed_dict_values.len(),
                worker.gen_dict.constants.values().map(|v| v.len()).sum::<usize>(),
                worker.gen_dict.whole_calls.values().map(|v| v.len()).sum::<usize>(),
            );

            last_status = Instant::now();
        }

        // Write LCOV coverage report periodically (worker 0 only, if enabled)
        if lcov_enabled && worker.worker_id == 0 && last_lcov_write.elapsed() >= lcov_interval {
            write_lcov_info_worker(env);
            last_lcov_write = Instant::now();
        }

        // Poll for injected dictionary values from web UI
        // Workers periodically drain and add values to their dictionaries
        {
            let mut injected = env.injected_dict_values.write();
            if !injected.is_empty() {
                let count = injected.len();
                for val in injected.drain(..) {
                    worker.gen_dict.dict_values.insert(val);
                }
                tracing::debug!(
                    "Worker {} consumed {} injected dictionary values",
                    worker.worker_id,
                    count
                );
            }
        }

        // Check stop on fail (| stopOnFail && any final tests)
        if env.cfg.campaign_conf.stop_on_fail && any_test_failed_worker(env) {
            return Ok(WorkerStopReason::TestFailed);
        }

        // Prioritize shrinking (| any shrinkable tests)
        // Only this worker shrinks tests it found 
        if any_pending_shrink_for_worker_env(env, worker.worker_id) {
            // Use initial VM for shrinking (Echidna passes vm to shrinkTest)
            shrink_pending_tests_worker(env, &initial_vm, worker, &mut rng, &force_stop)?;
            // Check for stop after shrinking
            if stop_flag.load(Ordering::Relaxed) {
                // On interrupt, close optimization tests and shrink them before exiting
                close_and_shrink_optimization_tests(
                    env,
                    &initial_vm,
                    worker,
                    &mut rng,
                    &force_stop,
                )?;
                return Ok(WorkerStopReason::Stopped);
            }
            continue;
        }

        // Check if we should continue fuzzing (| (null tests || any isOpen tests) && ncalls < testLimit)
        // If tests exist and all are complete (none open), we stop.
        let tests_complete = all_tests_complete_worker(env);
        if !env.test_refs.is_empty() && tests_complete {
            tracing::debug!("Early exit: all tests complete! ncalls={}", worker.ncalls);
            return Ok(WorkerStopReason::AllTestsComplete);
        }

        // Check test limit using per-worker limit (ncalls < testLimit)
        if worker.ncalls >= per_worker_limit {
            tracing::debug!(
                "Early exit: test limit reached! ncalls={} >= per_worker_limit={}",
                worker.ncalls,
                per_worker_limit
            );
            // On test limit, close optimization tests and shrink them before exiting
            // This matches the behavior when Ctrl+C is pressed
            close_and_shrink_optimization_tests(env, &initial_vm, worker, &mut rng, &force_stop)?;
            return Ok(WorkerStopReason::TestLimit);
        }

        // Fuzzing step - use cached data for performance
        tracing::trace!("About to call generate_sequence_worker_cached");
        let tx_seq = generate_sequence_worker_cached(
            env,
            &mut rng,
            &mut worker.gen_dict,
            &cached_fuzzable,
            &cached_assert_functions,
            &cached_resolved_relations,
        )?;

        // OPTIMIZATION: Checkpoint-based restart
        // Occasionally start from a saved checkpoint instead of initial state
        // This allows exploring from promising intermediate states
        let mut vm_for_seq = if checkpoint_enabled
            && !checkpoint_manager.is_empty()
            && rng.gen::<f32>() < checkpoint_probability
        {
            // Start from a checkpoint (weighted by optimization value)
            if let Some(checkpoint) = checkpoint_manager.get_random_checkpoint(&mut rng) {
                tracing::trace!(
                    "Worker {} starting from checkpoint with value {:?}",
                    worker.worker_id,
                    checkpoint.optimization_value
                );
                checkpoint.vm_state.clone()
            } else {
                initial_vm.clone()
            }
        } else {
            // Normal: reset VM to initial state 
            initial_vm.clone()
        };

        // OPTIMIZATION: Pass adaptive check interval
        let ((_result, new_cov), opt_improved) = execute_sequence_worker_with_checkpoints(
            &mut vm_for_seq,
            &tx_seq,
            env,
            worker,
            &mut checkpoint_manager,
            checkpoint_enabled,
            adaptive_check_enabled,
            current_check_interval,
        )?;

        // Update adaptive check interval based on whether we found improvements
        if adaptive_check_enabled {
            if opt_improved {
                last_optimization_improvement = Instant::now();
                current_check_interval = 1; // Check every tx when "hot"
            } else if last_optimization_improvement.elapsed() > Duration::from_secs(30) {
                // Relax after 30s without improvement
                current_check_interval = 50;
            } else if last_optimization_improvement.elapsed() > Duration::from_secs(10) {
                // Medium interval after 10s
                current_check_interval = 10;
            }
        }

        worker.ncallseqs += 1;
        worker.ncalls += tx_seq.len();

        // PERF: Batch atomic counter updates to reduce cache line contention
        local_calls_pending += tx_seq.len();
        local_gas_pending += worker.total_gas as usize;
        if local_calls_pending >= COUNTER_SYNC_INTERVAL {
            total_calls.fetch_add(local_calls_pending, Ordering::Relaxed);
            total_gas.fetch_add(local_gas_pending, Ordering::Relaxed);
            local_calls_pending = 0;
            local_gas_pending = 0;
        }

        if new_cov {
            worker.new_coverage = true;

            // Try to add to corpus first - only log if it's actually new
            // priority = ncallseqs + 1 (but ncallseqs already incremented above)
            // Note: execution.rs already added with ncallseqs+1, this will be rejected as duplicate
            let added = add_to_corpus_worker(env, tx_seq.clone(), worker.ncallseqs);

            if added {
                // Print coverage update  - only if we actually added
                let (coverage, codehashes) = get_coverage_stats_worker(env);
                let corpus_size = get_corpus_size_worker(env);
                output::print_new_coverage(worker.worker_id, coverage, codehashes, corpus_size);
                // Note: add_call is now done per-transaction in execute_sequence_worker
                // when each individual tx causes coverage growth (matching Echidna's gaddCalls)
            }
        }

        worker.new_coverage = false;

        // Check test results
        check_tests_worker(env, &vm_for_seq, &tx_seq, worker)?;
    }
}