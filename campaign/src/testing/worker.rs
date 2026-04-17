//! Test checking functions
//!
//! Contains functions for checking test results after transactions.

use alloy_primitives::{Address, I256};

use evm::exec::EvmState;
use evm::types::Tx;

use super::types::{TestState, TestType, TestValue};
use crate::output;
use crate::testing::{check_assertion, check_call_test_predicate, check_etest, update_open_test};
use crate::types::WorkerState;
use crate::worker_env::WorkerEnv;

/// Check CallTest, AssertionTest, PropertyTest, and OptimizationTest after each transaction (WorkerEnv variant)
/// ECHIDNA PARITY: Echidna checks ALL tests (including optimization) after EACH transaction,
/// not just at the end of the sequence. This is critical for finding better optimization
/// values at intermediate states!
pub fn check_tests_after_tx_worker(
    env: &WorkerEnv,
    vm: &EvmState,
    executed_so_far: &[Tx],
    worker: &mut WorkerState,
) -> anyhow::Result<()> {
    let contract_name = env
        .main_contract
        .as_ref()
        .map(|c| c.name.as_str())
        .unwrap_or("Contract");

    // Get sender from last tx for check_etest
    let sender = executed_so_far
        .last()
        .map(|tx| tx.src)
        .unwrap_or(Address::ZERO);

    for test_ref in &env.test_refs {
        let mut test = test_ref.write();

        if !test.is_open() {
            continue;
        }

        // ECHIDNA PARITY: Check PropertyTest and OptimizationTest via check_etest
        // (which calls the test function as a separate transaction)
        // Check CallTest and AssertionTest directly (they examine the current VM state)
        let (val, res) = match &test.test_type {
            TestType::CallTest { predicate, .. } => check_call_test_predicate(vm, predicate)?,
            TestType::AssertionTest {
                signature, addr, ..
            } => check_assertion(vm, signature, *addr)?,

            // CRITICAL FIX: Check PropertyTest and OptimizationTest after each tx!
            // Echidna does this in updateTests(updateOpenTest vm (reverse executedSoFar))
            TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                let mut check_vm = vm.clone();
                check_etest(&mut check_vm, &test, sender)?
            }

            _ => continue,
        };

        let is_optimization = matches!(test.test_type, TestType::OptimizationTest { .. });

        // For property tests and optimization tests, use update_open_test
        if matches!(
            test.test_type,
            TestType::PropertyTest { .. } | TestType::OptimizationTest { .. }
        ) {
            let test_updated = update_open_test(
                &mut test,
                executed_so_far.to_vec(),
                val.clone(),
                res,
                worker.worker_id,
                vm,
            );

            if test_updated {
                if is_optimization {
                    output::print_worker_msg(
                        worker.worker_id,
                        &format!(
                            "New maximum value of {}: {:?}",
                            test.test_type.name(),
                            test.value
                        ),
                    );
                    // ENHANCEMENT: Record functions that improved optimization as "hot"
                    // These will be weighted higher in future transaction generation
                    for tx in executed_so_far {
                        if let evm::types::TxCall::SolCall { ref name, ref args } = tx.call {
                            worker.gen_dict.record_optimization_improving_function(name);
                            // TARGETED ARGUMENT EVOLUTION: Record values that helped improve
                            worker.gen_dict.record_optimization_improving_values(args);
                        }
                    }
                    // Broadcast optimization improvement to web UI (realtime update)
                    // Include the optimization test call itself so replay shows the result
                    if let Some(ref web_state) = env.web_state {
                        if let TestType::OptimizationTest { name, addr } = &test.test_type {
                            // Build sequence with optimization test call appended
                            let sender = test.reproducer.last().map(|tx| tx.src).unwrap_or(*addr);
                            let opt_test_tx = evm::types::Tx {
                                call: evm::types::TxCall::SolCall {
                                    name: name.clone(),
                                    args: vec![],
                                },
                                src: sender,
                                dst: *addr,
                                gasprice: alloy_primitives::U256::ZERO,
                                value: alloy_primitives::U256::ZERO,
                                gas: 12_500_000,
                                delay: (0, 0),
                            };
                            let mut seq_with_test = test.reproducer.clone();
                            seq_with_test.push(opt_test_tx);
                            web_state.broadcast_test_state_change_with_value(
                                test.test_type.name(),
                                &test.state,
                                Some(&seq_with_test),
                                Some(&test.value),
                            );
                        } else {
                            web_state.broadcast_test_state_change_with_value(
                                test.test_type.name(),
                                &test.state,
                                Some(&test.reproducer),
                                Some(&test.value),
                            );
                        }
                    }
                    // NOTE: Don't save reproducer here - save at end of sequence only
                    // to avoid excessive I/O. The test state is updated and will be
                    // saved in check_tests_worker or at campaign end.
                } else if matches!(val, TestValue::BoolValue(false)) {
                    // Property test failed
                    output::print_worker_msg(
                        worker.worker_id,
                        &format!("Test {} falsified!", test.test_type.name()),
                    );
                    println!("  Call sequence:");
                    for tx in executed_so_far {
                        println!("    {}", output::format_tx(tx, contract_name));
                    }
                    println!();
                    if let Err(e) = output::save_unshrunk_reproducer_worker(env, executed_so_far) {
                        tracing::error!("Failed to save reproducer: {}", e);
                    }
                    // Broadcast test failure immediately to web UI
                    if let Some(ref web_state) = env.web_state {
                        web_state.broadcast_test_state_change(
                            test.test_type.name(),
                            &test.state,
                            Some(&test.reproducer),
                        );
                    }
                }
            }
            continue;
        }

        // For CallTest and AssertionTest, handle failure directly
        if let TestValue::BoolValue(false) = val {
            test.state = TestState::Large(0);
            test.reproducer = executed_so_far.to_vec();
            test.result = res;
            test.value = val;
            test.worker_id = Some(worker.worker_id);

            output::print_worker_msg(
                worker.worker_id,
                &format!("Test {} falsified!", test.test_type.name()),
            );
            println!("  Call sequence:");
            for tx in executed_so_far {
                println!("    {}", output::format_tx(tx, contract_name));
            }
            println!();

            if let Err(e) = output::save_unshrunk_reproducer_worker(env, executed_so_far) {
                tracing::error!("Failed to save reproducer: {}", e);
            }
            // Broadcast test failure immediately to web UI
            if let Some(ref web_state) = env.web_state {
                web_state.broadcast_test_state_change(
                    test.test_type.name(),
                    &test.state,
                    Some(&test.reproducer),
                );
            }
        }
    }
    Ok(())
}

/// PERF: Check only cheap tests (CallTest, AssertionTest) that don't require VM clone
/// PropertyTest and OptimizationTest are skipped - they'll be checked periodically
pub fn check_cheap_tests_after_tx_worker(
    env: &WorkerEnv,
    vm: &EvmState,
    executed_so_far: &[Tx],
    worker: &mut WorkerState,
) -> anyhow::Result<()> {
    let contract_name = env
        .main_contract
        .as_ref()
        .map(|c| c.name.as_str())
        .unwrap_or("Contract");

    for test_ref in &env.test_refs {
        let mut test = test_ref.write();

        if !test.is_open() {
            continue;
        }

        // Only check CallTest and AssertionTest - they don't need VM clone
        let (val, res) = match &test.test_type {
            TestType::CallTest { predicate, .. } => check_call_test_predicate(vm, predicate)?,
            TestType::AssertionTest {
                signature, addr, ..
            } => check_assertion(vm, signature, *addr)?,
            // Skip PropertyTest and OptimizationTest - checked periodically in check_tests_after_tx_worker
            _ => continue,
        };

        // Handle failure for CallTest and AssertionTest
        if let TestValue::BoolValue(false) = val {
            test.state = TestState::Large(0);
            test.reproducer = executed_so_far.to_vec();
            test.result = res;
            test.value = val;
            test.worker_id = Some(worker.worker_id);

            output::print_worker_msg(
                worker.worker_id,
                &format!("Test {} falsified!", test.test_type.name()),
            );
            println!("  Call sequence:");
            for tx in executed_so_far {
                println!("    {}", output::format_tx(tx, contract_name));
            }
            println!();

            if let Err(e) = output::save_unshrunk_reproducer_worker(env, executed_so_far) {
                tracing::error!("Failed to save reproducer: {}", e);
            }
            // Broadcast test failure immediately to web UI
            if let Some(ref web_state) = env.web_state {
                web_state.broadcast_test_state_change(
                    test.test_type.name(),
                    &test.state,
                    Some(&test.reproducer),
                );
            }
        }
    }
    Ok(())
}

/// Check PropertyTest, CallTest, AssertionTest after each tx (skip OptimizationTest for performance)
/// ECHIDNA PARITY: PropertyTest MUST be checked after every tx - this is critical for bug-finding!
/// OptimizationTest can be batched since missing intermediate values is acceptable trade-off
pub fn check_tests_without_optimization_worker(
    env: &WorkerEnv,
    vm: &EvmState,
    executed_so_far: &[Tx],
    worker: &mut WorkerState,
) -> anyhow::Result<()> {
    let contract_name = env
        .main_contract
        .as_ref()
        .map(|c| c.name.as_str())
        .unwrap_or("Contract");

    // Get sender from last tx for check_etest
    let sender = executed_so_far
        .last()
        .map(|tx| tx.src)
        .unwrap_or(Address::ZERO);

    for test_ref in &env.test_refs {
        let mut test = test_ref.write();

        if !test.is_open() {
            continue;
        }

        let (val, res) = match &test.test_type {
            TestType::CallTest { predicate, .. } => check_call_test_predicate(vm, predicate)?,
            TestType::AssertionTest {
                signature, addr, ..
            } => check_assertion(vm, signature, *addr)?,

            // CRITICAL: Check PropertyTest every tx! This requires VM clone but is necessary
            TestType::PropertyTest { .. } => {
                let mut check_vm = vm.clone();
                check_etest(&mut check_vm, &test, sender)?
            }

            // Skip OptimizationTest - will be checked at intervals
            TestType::OptimizationTest { .. } => continue,

            _ => continue,
        };

        // For PropertyTest, use update_open_test
        if matches!(test.test_type, TestType::PropertyTest { .. }) {
            let test_updated = update_open_test(
                &mut test,
                executed_so_far.to_vec(),
                val.clone(),
                res,
                worker.worker_id,
                vm,
            );

            if test_updated && matches!(val, TestValue::BoolValue(false)) {
                // Property test failed
                output::print_worker_msg(
                    worker.worker_id,
                    &format!("Test {} falsified!", test.test_type.name()),
                );
                println!("  Call sequence:");
                for tx in executed_so_far {
                    println!("    {}", output::format_tx(tx, contract_name));
                }
                println!();
                if let Err(e) = output::save_unshrunk_reproducer_worker(env, executed_so_far) {
                    tracing::error!("Failed to save reproducer: {}", e);
                }
                // Broadcast test failure immediately to web UI
                if let Some(ref web_state) = env.web_state {
                    web_state.broadcast_test_state_change(
                        test.test_type.name(),
                        &test.state,
                        Some(&test.reproducer),
                    );
                }
            }
            continue;
        }

        // For CallTest and AssertionTest, handle failure directly
        if let TestValue::BoolValue(false) = val {
            test.state = TestState::Large(0);
            test.reproducer = executed_so_far.to_vec();
            test.result = res;
            test.value = val;
            test.worker_id = Some(worker.worker_id);

            output::print_worker_msg(
                worker.worker_id,
                &format!("Test {} falsified!", test.test_type.name()),
            );
            println!("  Call sequence:");
            for tx in executed_so_far {
                println!("    {}", output::format_tx(tx, contract_name));
            }
            println!();

            if let Err(e) = output::save_unshrunk_reproducer_worker(env, executed_so_far) {
                tracing::error!("Failed to save reproducer: {}", e);
            }
            // Broadcast test failure immediately to web UI
            if let Some(ref web_state) = env.web_state {
                web_state.broadcast_test_state_change(
                    test.test_type.name(),
                    &test.state,
                    Some(&test.reproducer),
                );
            }
        }
    }
    Ok(())
}

/// Check tests after tx with checkpoint support
/// Returns true if optimization value improved
pub fn check_tests_after_tx_worker_with_checkpoint(
    env: &WorkerEnv,
    vm: &EvmState,
    executed_so_far: &[Tx],
    worker: &mut WorkerState,
    checkpoint_manager: &mut crate::types::CheckpointManager,
    checkpoint_enabled: bool,
    initial_best_value: Option<I256>,
) -> anyhow::Result<bool> {
    let contract_name = env
        .main_contract
        .as_ref()
        .map(|c| c.name.as_str())
        .unwrap_or("Contract");

    let sender = executed_so_far
        .last()
        .map(|tx| tx.src)
        .unwrap_or(Address::ZERO);
    let mut optimization_improved = false;

    for test_ref in &env.test_refs {
        let mut test = test_ref.write();

        if !test.is_open() {
            continue;
        }

        let (val, res) = match &test.test_type {
            TestType::CallTest { predicate, .. } => check_call_test_predicate(vm, predicate)?,
            TestType::AssertionTest {
                signature, addr, ..
            } => check_assertion(vm, signature, *addr)?,
            TestType::PropertyTest { .. } | TestType::OptimizationTest { .. } => {
                let mut check_vm = vm.clone();
                check_etest(&mut check_vm, &test, sender)?
            }
            _ => continue,
        };

        let is_optimization = matches!(test.test_type, TestType::OptimizationTest { .. });

        if matches!(
            test.test_type,
            TestType::PropertyTest { .. } | TestType::OptimizationTest { .. }
        ) {
            let test_updated = update_open_test(
                &mut test,
                executed_so_far.to_vec(),
                val.clone(),
                res,
                worker.worker_id,
                vm,
            );

            if test_updated {
                if is_optimization {
                    optimization_improved = true;
                    output::print_worker_msg(
                        worker.worker_id,
                        &format!(
                            "New maximum value of {}: {:?}",
                            test.test_type.name(),
                            test.value
                        ),
                    );

                    // SAVE REPRODUCER IMMEDIATELY when optimization improves (Echidna parity)
                    // Don't defer to check_tests_worker - that uses faulty length-based heuristic
                    if let Err(e) =
                        output::save_optimization_reproducer_worker(env, &test.reproducer)
                    {
                        tracing::error!("Failed to save optimization reproducer: {}", e);
                    }

                    // Record hot functions and hot argument values
                    for tx in executed_so_far {
                        if let evm::types::TxCall::SolCall { ref name, ref args } = tx.call {
                            worker.gen_dict.record_optimization_improving_function(name);
                            // TARGETED ARGUMENT EVOLUTION: Record values that helped improve
                            worker.gen_dict.record_optimization_improving_values(args);
                        }
                    }

                    // CHECKPOINT: Save this state for future exploration
                    // Only checkpoint if we beat the initial value (not just equal)
                    if checkpoint_enabled {
                        if let TestValue::IntValue(new_val) = &test.value {
                            let should_save = initial_best_value
                                .map(|init| *new_val > init)
                                .unwrap_or(true);

                            if should_save {
                                // MULTI-OBJECTIVE: Calculate secondary objectives
                                let gas_used: u64 = executed_so_far.iter().map(|tx| tx.gas).sum();
                                let coverage_count = env.coverage_ref_runtime.read().len();

                                let checkpoint =
                                    crate::types::OptimizationCheckpoint::with_secondary_objectives(
                                        vm.clone(),
                                        *new_val,
                                        executed_so_far.to_vec(),
                                        gas_used,
                                        coverage_count,
                                    );
                                checkpoint_manager.add_checkpoint(checkpoint);
                                tracing::debug!(
                                    "Worker {} saved checkpoint: value={}, gas={}, seq_len={}, cov={}",
                                    worker.worker_id,
                                    new_val,
                                    gas_used,
                                    executed_so_far.len(),
                                    coverage_count
                                );
                            }
                        }
                    }

                    // Broadcast optimization improvement to web UI (realtime update)
                    // Include the optimization test call itself so replay shows the result
                    if let Some(ref web_state) = env.web_state {
                        if let TestType::OptimizationTest { name, addr } = &test.test_type {
                            // Build sequence with optimization test call appended
                            let sender = test.reproducer.last().map(|tx| tx.src).unwrap_or(*addr);
                            let opt_test_tx = evm::types::Tx {
                                call: evm::types::TxCall::SolCall {
                                    name: name.clone(),
                                    args: vec![],
                                },
                                src: sender,
                                dst: *addr,
                                gasprice: alloy_primitives::U256::ZERO,
                                value: alloy_primitives::U256::ZERO,
                                gas: 12_500_000,
                                delay: (0, 0),
                            };
                            let mut seq_with_test = test.reproducer.clone();
                            seq_with_test.push(opt_test_tx);
                            web_state.broadcast_test_state_change_with_value(
                                test.test_type.name(),
                                &test.state,
                                Some(&seq_with_test),
                                Some(&test.value),
                            );
                        } else {
                            web_state.broadcast_test_state_change_with_value(
                                test.test_type.name(),
                                &test.state,
                                Some(&test.reproducer),
                                Some(&test.value),
                            );
                        }
                    }
                } else if matches!(val, TestValue::BoolValue(false)) {
                    output::print_worker_msg(
                        worker.worker_id,
                        &format!("Test {} falsified!", test.test_type.name()),
                    );
                    println!("  Call sequence:");
                    for tx in executed_so_far {
                        println!("    {}", output::format_tx(tx, contract_name));
                    }
                    println!();
                    if let Err(e) = output::save_unshrunk_reproducer_worker(env, executed_so_far) {
                        tracing::error!("Failed to save reproducer: {}", e);
                    }
                    // Broadcast test failure immediately to web UI
                    if let Some(ref web_state) = env.web_state {
                        web_state.broadcast_test_state_change(
                            test.test_type.name(),
                            &test.state,
                            Some(&test.reproducer),
                        );
                    }
                }
            }
            continue;
        }

        // Handle CallTest and AssertionTest failure
        if let TestValue::BoolValue(false) = val {
            test.state = TestState::Large(0);
            test.reproducer = executed_so_far.to_vec();
            test.result = res;
            test.value = val;
            test.worker_id = Some(worker.worker_id);

            output::print_worker_msg(
                worker.worker_id,
                &format!("Test {} falsified!", test.test_type.name()),
            );
            println!("  Call sequence:");
            for tx in executed_so_far {
                println!("    {}", output::format_tx(tx, contract_name));
            }
            println!();

            if let Err(e) = output::save_unshrunk_reproducer_worker(env, executed_so_far) {
                tracing::error!("Failed to save reproducer: {}", e);
            }
            // Broadcast test failure immediately to web UI
            if let Some(ref web_state) = env.web_state {
                web_state.broadcast_test_state_change(
                    test.test_type.name(),
                    &test.state,
                    Some(&test.reproducer),
                );
            }
        }
    }
    Ok(optimization_improved)
}

/// Check test results after a sequence (WorkerEnv variant)
/// NOTE: PropertyTest and OptimizationTest are checked per-tx in check_tests_after_tx_worker.
/// Optimization reproducers are saved immediately when the value improves (in check_tests_after_tx_worker).
/// This function is kept for CallTest/AssertionTest handling if needed in the future.
pub fn check_tests_worker(
    _env: &WorkerEnv,
    _vm: &EvmState,
    _tx_seq: &[Tx],
    _worker: &mut WorkerState,
) -> anyhow::Result<()> {
    // PropertyTest and OptimizationTest are checked per-tx in check_tests_after_tx_worker
    // (matching Echidna's evalSeq behavior).
    // Optimization reproducers are now saved immediately when the value improves,
    // not deferred here with a faulty length-based heuristic.
    Ok(())
}
