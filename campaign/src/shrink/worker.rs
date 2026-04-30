//! Worker-specific shrinking functions
//!
//! Contains functions for shrinking failing test cases in worker threads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::prelude::*;

use evm::exec::EvmState;

use crate::output;
use crate::testing::{EchidnaTest, TestState};
use crate::types::WorkerState;
use crate::worker_env::WorkerEnv;

/// Write a Foundry reproducer to the --repro file if configured.
fn try_write_repro(env: &WorkerEnv, test: &EchidnaTest) {
    if let Some(ref writer) = env.repro_writer {
        if let Err(e) = writer.append_test(test) {
            tracing::error!("Failed to write Foundry repro: {}", e);
        }
    }
}

/// Build the `decode_with` tuple for `format_generate_calls` from the
/// worker env and a test that has a frozen dict snapshot. Returns `None`
/// if either piece is missing — the caller falls back to undecoded
/// rendering (just seeds + indices).
fn build_decode_args(
    env: &WorkerEnv,
    test: &EchidnaTest,
) -> Option<(
    Arc<abi::types::GenDict>,
    Vec<(
        alloy_primitives::FixedBytes<4>,
        String,
        Vec<alloy_dyn_abi::DynSolType>,
    )>,
    String,
)> {
    let dict = test.gen_dict_snapshot.clone()?;
    let contract = env.main_contract.as_ref()?;
    let fuzzable = contract.fuzzable_functions(true);
    let funcs: Vec<_> = fuzzable
        .iter()
        .map(|f| {
            let selector = f.selector();
            let param_types = contract.get_param_types(&selector).to_vec();
            (selector, f.name.clone(), param_types)
        })
        .collect();
    if funcs.is_empty() {
        None
    } else {
        Some((dict, funcs, contract.name.clone()))
    }
}

/// Shrink tests that this worker owns (WorkerEnv variant)
/// force_stop: If true, skip shrinking and return immediately (second Ctrl+C)
pub fn shrink_pending_tests_worker(
    env: &WorkerEnv,
    initial_vm: &EvmState,
    worker: &WorkerState,
    rng: &mut impl Rng,
    force_stop: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let shrink_limit = env.cfg.campaign_conf.shrink_limit;

    for test_ref in &env.test_refs {
        // Check force_stop - immediate exit on second Ctrl+C
        if force_stop.load(Ordering::Relaxed) {
            output::print_worker_msg(worker.worker_id, "Force stop - aborting shrink");
            return Ok(());
        }

        let mut test = test_ref.write();

        if test.worker_id != Some(worker.worker_id) {
            continue;
        }

        if let TestState::Large(n) = test.state {
            if n >= shrink_limit as i32 {
                test.shrink_complete();

                // Inner-batch ddmin: prune `vm.generateCalls()` results
                // to the minimal subset that still triggers the bug.
                let mut vm_for_inner = initial_vm.clone();
                if let Err(e) = super::shrink_inner_batches_worker(
                    env,
                    &mut vm_for_inner,
                    &mut test,
                ) {
                    tracing::warn!(
                        "Inner-batch shrink failed for {}: {}",
                        test.test_type.name(),
                        e
                    );
                }

                output::print_worker_msg(
                    worker.worker_id,
                    &format!("Shrinking {} complete.", test.test_type.name()),
                );
                // Pretty-print the shrunk sequence with per-tx
                // generateCalls annotations (decoded when we have the
                // dict snapshot + main contract).
                let cname = env
                    .main_contract
                    .as_ref()
                    .map(|c| c.name.as_str())
                    .unwrap_or("Contract");
                let decode_args = build_decode_args(env, &test);
                let dw = decode_args
                    .as_ref()
                    .map(|(d, f, n)| (d, f.as_slice(), n.as_str()));
                println!("  Shrunk call sequence:");
                for tx in &test.reproducer {
                    println!("    {}", output::format_tx(tx, cname));
                    for line in output::format_generate_calls(tx, dw) {
                        println!("    {}", line);
                    }
                }
                println!();

                if let Err(e) = output::save_shrunk_reproducer_worker(env, &test.reproducer) {
                    tracing::error!("Failed to save shrunk reproducer: {}", e);
                }
                try_write_repro(env, &test);
                // Broadcast shrink completion to web UI
                if let Some(ref web_state) = env.web_state {
                    web_state.broadcast_test_state_change(
                        test.test_type.name(),
                        &test.state,
                        Some(&test.reproducer),
                    );
                }
            } else {
                let mut vm_for_shrink = initial_vm.clone();

                if let Some(mut shrunk_test) =
                    super::shrink_test_worker(env, &mut vm_for_shrink, &test, rng)?
                {
                    if matches!(shrunk_test.state, TestState::Solved) {
                        // Inner-batch ddmin: prune `vm.generateCalls()` results
                        // down to the minimal subset that still triggers the
                        // bug. Only does work when the test invoked the
                        // cheatcode and we have a frozen dict snapshot;
                        // otherwise no-op.
                        let mut vm_for_inner = initial_vm.clone();
                        if let Err(e) = super::shrink_inner_batches_worker(
                            env,
                            &mut vm_for_inner,
                            &mut shrunk_test,
                        ) {
                            tracing::warn!(
                                "Inner-batch shrink failed for {}: {}",
                                shrunk_test.test_type.name(),
                                e
                            );
                        }

                        output::print_worker_msg(
                            worker.worker_id,
                            &format!(
                                "Shrinking {} complete (len {}).",
                                shrunk_test.test_type.name(),
                                shrunk_test.reproducer.len()
                            ),
                        );
                        // Pretty-print the shrunk sequence with per-tx
                        // generateCalls annotations (seeds + kept indices).
                        let cname = env
                            .main_contract
                            .as_ref()
                            .map(|c| c.name.as_str())
                            .unwrap_or("Contract");
                        let decode_args = build_decode_args(env, &shrunk_test);
                        let dw = decode_args
                            .as_ref()
                            .map(|(d, f, n)| (d, f.as_slice(), n.as_str()));
                        println!("  Shrunk call sequence:");
                        for tx in &shrunk_test.reproducer {
                            println!("    {}", output::format_tx(tx, cname));
                            for line in output::format_generate_calls(tx, dw) {
                                println!("    {}", line);
                            }
                        }
                        println!();

                        if let Err(e) =
                            output::save_shrunk_reproducer_worker(env, &shrunk_test.reproducer)
                        {
                            tracing::error!("Failed to save shrunk reproducer: {}", e);
                        }
                        try_write_repro(env, &shrunk_test);
                    }
                    // Broadcast shrink progress to web UI (every attempt, not just completion)
                    if let Some(ref web_state) = env.web_state {
                        web_state.broadcast_test_state_change(
                            shrunk_test.test_type.name(),
                            &shrunk_test.state,
                            Some(&shrunk_test.reproducer),
                        );
                    }
                    *test = shrunk_test;
                } else {
                    test.shrink_attempt();
                    // Broadcast even failed shrink attempts to update progress counter
                    if let Some(ref web_state) = env.web_state {
                        web_state.broadcast_test_state_change(
                            test.test_type.name(),
                            &test.state,
                            Some(&test.reproducer),
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Close open optimization tests and shrink them (for Ctrl+C handling)
/// This ensures optimization tests get shrunk even when interrupted
/// force_stop: If true, skip shrinking entirely (second Ctrl+C)
pub fn close_and_shrink_optimization_tests(
    env: &WorkerEnv,
    initial_vm: &EvmState,
    worker: &WorkerState,
    rng: &mut impl Rng,
    force_stop: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    // Check force_stop immediately - if user pressed Ctrl+C twice, skip shrinking
    if force_stop.load(Ordering::Relaxed) {
        output::print_worker_msg(
            worker.worker_id,
            "Force stop - skipping optimization test shrinking",
        );
        return Ok(());
    }

    // First, close any open optimization tests that belong to this worker or are unowned
    let mut any_closed = false;
    let mut tests_to_shrink = Vec::new();

    for test_ref in &env.test_refs {
        let mut test = test_ref.write();
        if test.is_open()
            && matches!(
                test.test_type,
                crate::testing::TestType::OptimizationTest { .. }
            )
            && (test.worker_id.is_none() || test.worker_id == Some(worker.worker_id))
        {
            // Close optimization test for shrinking
            test.state = TestState::Large(0);
            test.worker_id = Some(worker.worker_id);
            tests_to_shrink.push(test.test_type.name().to_string());
            any_closed = true;
            // Broadcast that we're starting to shrink this test
            if let Some(ref web_state) = env.web_state {
                web_state.broadcast_test_state_change(
                    test.test_type.name(),
                    &test.state,
                    Some(&test.reproducer),
                );
            }
        }
    }

    if !any_closed {
        return Ok(());
    }

    // Show user what's happening - print for whichever worker claimed the tests
    output::print_worker_msg(
        worker.worker_id,
        &format!(
            "Shrinking {} optimization test(s): {}",
            tests_to_shrink.len(),
            tests_to_shrink.join(", ")
        ),
    );

    // Now shrink the closed optimization tests
    // Use the configured shrink_limit (same as normal finish)
    let shrink_limit = env.cfg.campaign_conf.shrink_limit;

    // Progress tracking
    let mut last_progress = Instant::now();
    let progress_interval = Duration::from_secs(3);

    for _i in 0..shrink_limit {
        // Check force_stop - immediate exit on second Ctrl+C
        if force_stop.load(Ordering::Relaxed) {
            output::print_worker_msg(
                worker.worker_id,
                "Force stop - aborting optimization shrink (showing current best results)",
            );
            break;
        }

        // Print progress periodically
        if last_progress.elapsed() >= progress_interval {
            // Gather current progress for all tests being shrunk by this worker
            let progress: Vec<String> = env
                .test_refs
                .iter()
                .filter_map(|t| {
                    let test = t.read();
                    if test.worker_id == Some(worker.worker_id) {
                        if let TestState::Large(n) = test.state {
                            return Some(format!(
                                "{}: {}/{} (len {})",
                                test.test_type.name(),
                                n,
                                shrink_limit,
                                test.reproducer.len()
                            ));
                        }
                    }
                    None
                })
                .collect();

            if !progress.is_empty() {
                output::print_worker_msg(
                    worker.worker_id,
                    &format!("Shrinking: {} (Ctrl+C again to stop)", progress.join(", ")),
                );
                // Broadcast shrinking progress to web UI
                if let Some(ref web_state) = env.web_state {
                    for test_ref in &env.test_refs {
                        let test = test_ref.read();
                        if test.worker_id == Some(worker.worker_id) {
                            if let TestState::Large(_) = test.state {
                                web_state.broadcast_test_state_change(
                                    test.test_type.name(),
                                    &test.state,
                                    Some(&test.reproducer),
                                );
                            }
                        }
                    }
                }
            }
            last_progress = Instant::now();
        }

        // Check if any tests still need shrinking
        let has_pending = env.test_refs.iter().any(|t| {
            let test = t.read();
            test.worker_id == Some(worker.worker_id) && matches!(test.state, TestState::Large(_))
        });

        if !has_pending {
            break;
        }

        for test_ref in &env.test_refs {
            let mut test = test_ref.write();

            if test.worker_id != Some(worker.worker_id) {
                continue;
            }

            if let TestState::Large(n) = test.state {
                // Check if we've reached shrink limit for this test
                if n >= shrink_limit as i32 {
                    test.shrink_complete();

                    // Inner-batch ddmin: prune `vm.generateCalls()` results
                    // to the minimal subset that still triggers the bug.
                    // Same as the converged-Solved path below.
                    let mut vm_for_inner = initial_vm.clone();
                    if let Err(e) = super::shrink_inner_batches_worker(
                        env,
                        &mut vm_for_inner,
                        &mut test,
                    ) {
                        tracing::warn!(
                            "Inner-batch shrink failed for {}: {}",
                            test.test_type.name(),
                            e
                        );
                    }

                    output::print_worker_msg(
                        worker.worker_id,
                        &format!(
                            "Shrinking {} complete ({} attempts, len {}).",
                            test.test_type.name(),
                            n,
                            test.reproducer.len()
                        ),
                    );
                    // Pretty-print the shrunk sequence with per-tx
                    // generateCalls annotations.
                    let cname = env
                        .main_contract
                        .as_ref()
                        .map(|c| c.name.as_str())
                        .unwrap_or("Contract");
                    let decode_args = build_decode_args(env, &test);
                    let dw = decode_args
                        .as_ref()
                        .map(|(d, f, n)| (d, f.as_slice(), n.as_str()));
                    println!("  Shrunk call sequence:");
                    for tx in &test.reproducer {
                        println!("    {}", output::format_tx(tx, cname));
                        for line in output::format_generate_calls(tx, dw) {
                            println!("    {}", line);
                        }
                    }
                    println!();

                    if let Err(e) = output::save_shrunk_reproducer_worker(env, &test.reproducer) {
                        tracing::error!("Failed to save shrunk reproducer: {}", e);
                    }
                    try_write_repro(env, &test);
                    // Broadcast shrink completion to web UI
                    if let Some(ref web_state) = env.web_state {
                        web_state.broadcast_test_state_change(
                            test.test_type.name(),
                            &test.state,
                            Some(&test.reproducer),
                        );
                    }
                    continue;
                }

                let mut vm_for_shrink = initial_vm.clone();

                if let Some(mut shrunk_test) =
                    super::shrink_test_worker(env, &mut vm_for_shrink, &test, rng)?
                {
                    if matches!(shrunk_test.state, TestState::Solved) {
                        // Inner-batch ddmin: prune `vm.generateCalls()` results
                        // down to the minimal subset that still triggers the
                        // bug. No-op when the cheatcode wasn't used.
                        let mut vm_for_inner = initial_vm.clone();
                        if let Err(e) = super::shrink_inner_batches_worker(
                            env,
                            &mut vm_for_inner,
                            &mut shrunk_test,
                        ) {
                            tracing::warn!(
                                "Inner-batch shrink failed for {}: {}",
                                shrunk_test.test_type.name(),
                                e
                            );
                        }

                        output::print_worker_msg(
                            worker.worker_id,
                            &format!(
                                "Shrinking {} complete (len {}).",
                                shrunk_test.test_type.name(),
                                shrunk_test.reproducer.len()
                            ),
                        );
                        // Pretty-print the shrunk sequence with per-tx
                        // generateCalls annotations.
                        let cname = env
                            .main_contract
                            .as_ref()
                            .map(|c| c.name.as_str())
                            .unwrap_or("Contract");
                        let decode_args = build_decode_args(env, &shrunk_test);
                        let dw = decode_args
                            .as_ref()
                            .map(|(d, f, n)| (d, f.as_slice(), n.as_str()));
                        println!("  Shrunk call sequence:");
                        for tx in &shrunk_test.reproducer {
                            println!("    {}", output::format_tx(tx, cname));
                            for line in output::format_generate_calls(tx, dw) {
                                println!("    {}", line);
                            }
                        }
                        println!();

                        if let Err(e) =
                            output::save_shrunk_reproducer_worker(env, &shrunk_test.reproducer)
                        {
                            tracing::error!("Failed to save shrunk reproducer: {}", e);
                        }
                        try_write_repro(env, &shrunk_test);
                    }
                    // Broadcast shrink progress to web UI (every attempt, not just completion)
                    if let Some(ref web_state) = env.web_state {
                        web_state.broadcast_test_state_change(
                            shrunk_test.test_type.name(),
                            &shrunk_test.state,
                            Some(&shrunk_test.reproducer),
                        );
                    }
                    *test = shrunk_test;
                } else {
                    test.shrink_attempt();
                    // Broadcast even failed shrink attempts to update progress counter
                    if let Some(ref web_state) = env.web_state {
                        web_state.broadcast_test_state_change(
                            test.test_type.name(),
                            &test.state,
                            Some(&test.reproducer),
                        );
                    }
                }
            }
        }
    }

    // Final pass: mark any remaining Large tests as Solved
    for test_ref in &env.test_refs {
        let mut test = test_ref.write();
        if test.worker_id == Some(worker.worker_id) {
            if let TestState::Large(n) = test.state {
                test.shrink_complete();
                output::print_worker_msg(
                    worker.worker_id,
                    &format!(
                        "Shrinking {} finalized ({} attempts, len {}).",
                        test.test_type.name(),
                        n,
                        test.reproducer.len()
                    ),
                );
                if let Err(e) = output::save_shrunk_reproducer_worker(env, &test.reproducer) {
                    tracing::error!("Failed to save shrunk reproducer: {}", e);
                }
                try_write_repro(env, &test);
                // Broadcast shrink completion to web UI
                if let Some(ref web_state) = env.web_state {
                    web_state.broadcast_test_state_change(
                        test.test_type.name(),
                        &test.state,
                        Some(&test.reproducer),
                    );
                }
            }
        }
    }

    Ok(())
}
