//! Worker-specific shrinking functions
//!
//! Contains functions for shrinking failing test cases in worker threads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::prelude::*;

use evm::exec::EvmState;

use crate::output;
use crate::testing::TestState;
use crate::types::WorkerState;
use crate::worker_env::WorkerEnv;

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

                output::print_worker_msg(
                    worker.worker_id,
                    &format!("Shrinking {} complete.", test.test_type.name()),
                );

                if let Err(e) = output::save_shrunk_reproducer_worker(env, &test.reproducer) {
                    tracing::error!("Failed to save shrunk reproducer: {}", e);
                }
            } else {
                let mut vm_for_shrink = initial_vm.clone();

                if let Some(shrunk_test) =
                    super::shrink_test_worker(env, &mut vm_for_shrink, &test, rng)?
                {
                    if matches!(shrunk_test.state, TestState::Solved) {
                        output::print_worker_msg(
                            worker.worker_id,
                            &format!("Shrinking {} complete.", shrunk_test.test_type.name()),
                        );

                        if let Err(e) =
                            output::save_shrunk_reproducer_worker(env, &shrunk_test.reproducer)
                        {
                            tracing::error!("Failed to save shrunk reproducer: {}", e);
                        }
                    }
                    *test = shrunk_test;
                } else {
                    test.shrink_attempt();
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
                    output::print_worker_msg(
                        worker.worker_id,
                        &format!(
                            "Shrinking {} complete ({} attempts, len {}).",
                            test.test_type.name(),
                            n,
                            test.reproducer.len()
                        ),
                    );
                    if let Err(e) = output::save_shrunk_reproducer_worker(env, &test.reproducer) {
                        tracing::error!("Failed to save shrunk reproducer: {}", e);
                    }
                    continue;
                }

                let mut vm_for_shrink = initial_vm.clone();

                if let Some(shrunk_test) =
                    super::shrink_test_worker(env, &mut vm_for_shrink, &test, rng)?
                {
                    if matches!(shrunk_test.state, TestState::Solved) {
                        output::print_worker_msg(
                            worker.worker_id,
                            &format!(
                                "Shrinking {} complete (len {}).",
                                shrunk_test.test_type.name(),
                                shrunk_test.reproducer.len()
                            ),
                        );

                        if let Err(e) =
                            output::save_shrunk_reproducer_worker(env, &shrunk_test.reproducer)
                        {
                            tracing::error!("Failed to save shrunk reproducer: {}", e);
                        }
                    }
                    *test = shrunk_test;
                } else {
                    test.shrink_attempt();
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
            }
        }
    }

    Ok(())
}