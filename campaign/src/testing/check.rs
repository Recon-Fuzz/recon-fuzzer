//! Test execution and checking

use alloy_primitives::{Address, I256};

use super::types::{CallTestPredicate, EchidnaTest, TestState, TestType, TestValue};
use evm::exec::EvmState;
use evm::types::{Tx, TxResult};

/// Response from calling an echidna test function
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallRes {
    /// Returned true
    ResTrue,
    /// Returned false
    ResFalse,
    /// Reverted
    ResRevert,
    /// Other result
    ResOther,
}

/// Classify VM result into CallRes
pub fn classify_result(result: &TxResult, return_data: &[u8]) -> CallRes {
    match result {
        TxResult::Stop | TxResult::ReturnTrue => {
            // Check if return data encodes true or false
            if return_data.len() >= 32 {
                let last_byte = return_data[31];
                if last_byte == 1 {
                    CallRes::ResTrue
                } else if last_byte == 0 {
                    CallRes::ResFalse
                } else {
                    CallRes::ResOther
                }
            } else {
                CallRes::ResOther
            }
        }
        TxResult::ReturnFalse => CallRes::ResFalse,
        TxResult::ErrorRevert => CallRes::ResRevert,
        _ => CallRes::ResOther,
    }
}

/// Check an echidna test after executing a transaction sequence
pub fn check_etest(
    vm: &mut EvmState,
    test: &EchidnaTest,
    sender: Address,
) -> anyhow::Result<(TestValue, TxResult)> {
    match &test.test_type {
        TestType::Exploration => {
            // Exploration tests always pass
            Ok((TestValue::BoolValue(true), TxResult::Stop))
        }

        TestType::PropertyTest { name, addr } => check_property(vm, name, *addr, sender),

        TestType::OptimizationTest { name, addr } => check_optimization(vm, name, *addr, sender),

        TestType::AssertionTest {
            signature, addr, ..
        } => check_assertion(vm, signature, *addr),

        TestType::CallTest { predicate, .. } => check_call_test_predicate(vm, predicate),
    }
}

/// Check a call test predicate (public for use in campaign)
pub fn check_call_test_predicate(
    vm: &EvmState,
    predicate: &CallTestPredicate,
) -> anyhow::Result<(TestValue, TxResult)> {
    match predicate {
        CallTestPredicate::AssertionFailed => {
            // Echidna's checkAssertionTest ONLY checks for AssertionFailed(string) events
            // It does NOT check for Panic(1) or InvalidFEOpcode - those are caught by
            // specific AssertionTests for each function.
            // This ensures that if counter_setNumber(22) triggers Panic(1), only the
            // counter_setNumber AssertionTest fails, while AssertionFailed(..) passes.
            let logs = vm.get_last_logs();
            let has_assertion_event = logs.iter().any(|log| {
                if let Some(topic) = log.topics().first() {
                    // AssertionFailed(string) selector: keccak256("AssertionFailed(string)")
                    *topic
                        == alloy_primitives::B256::from(hex_literal::hex!(
                            "b42604cb1052b6c312aa2193cb523f39d846b04f7988352656360c441c888806"
                        ))
                } else {
                    false
                }
            });

            if has_assertion_event {
                Ok((TestValue::BoolValue(false), TxResult::ErrorAssertionFailed))
            } else {
                Ok((TestValue::BoolValue(true), TxResult::Stop))
            }
        }

        CallTestPredicate::SelfDestructTarget(addr) => {
            // Check if target contract was self-destructed
            let is_destroyed = vm.has_selfdestructed(*addr);
            Ok((TestValue::BoolValue(!is_destroyed), TxResult::Stop))
        }

        CallTestPredicate::AnySelfDestruct => {
            // Check if any contract was self-destructed
            // For now, we don't track this - would need VM changes
            Ok((TestValue::BoolValue(true), TxResult::Stop))
        }
    }
}

/// Check a property test
/// Calls the echidna_ function and checks if it returns true
fn check_property(
    vm: &mut EvmState,
    name: &str,
    addr: Address,
    sender: Address,
) -> anyhow::Result<(TestValue, TxResult)> {
    // Create a transaction to call the property function
    let tx = Tx::call(name, vec![], sender, addr, (0, 0));

    tracing::debug!(
        "check_property: calling {}() at {:?} from {:?}",
        name,
        addr,
        sender
    );

    // Execute the test call
    let result = vm.exec_tx(&tx)?;

    // Check result
    let output = vm.get_last_output();
    tracing::debug!(
        "check_property({}) result={:?}, output_len={}, output=0x{}, last_result={:?}",
        name,
        result,
        output.len(),
        if output.len() <= 64 {
            alloy_primitives::hex::encode(&output)
        } else {
            format!("{}...", alloy_primitives::hex::encode(&output[..32]))
        },
        vm.last_result
    );
    let call_res = classify_result(&result, &output);
    tracing::debug!("check_property({}) call_res={:?}", name, call_res);

    // Pass if returns true (and didn't revert)
    let passed = matches!(call_res, CallRes::ResTrue);

    Ok((TestValue::BoolValue(passed), result))
}

/// Check an optimization test
/// Calls the function and extracts the int256 return value
fn check_optimization(
    vm: &mut EvmState,
    name: &str,
    addr: Address,
    sender: Address,
) -> anyhow::Result<(TestValue, TxResult)> {
    let tx = Tx::call(name, vec![], sender, addr, (0, 0));
    let result = vm.exec_tx(&tx)?;

    let value = if matches!(
        result,
        TxResult::Stop | TxResult::ReturnTrue | TxResult::ReturnFalse
    ) {
        let output = vm.get_last_output();
        if output.len() >= 32 {
            // Decode I256 (int256)
            let bytes: [u8; 32] = output[..32].try_into().unwrap();
            let val = I256::from_be_bytes(bytes);
            TestValue::IntValue(val)
        } else {
            TestValue::IntValue(I256::MIN) // Default minBound if succeed but empty (parity with Echidna)
        }
    } else {
        TestValue::IntValue(I256::MIN)
    };

    Ok((value, result))
}

/// Check an assertion test
/// Checks if the last transaction caused an assertion failure
pub fn check_assertion(
    vm: &EvmState,
    signature: &(String, Vec<String>),
    addr: Address,
) -> anyhow::Result<(TestValue, TxResult)> {
    // Echidna checks:
    // 1. isCorrectFn: last call matches function signature
    // 2. isCorrectAddr: last call targets correct contract
    // 3. isAssertionFailure: opcode 0xfe or AssertionFailed event or Panic(1)
    // Test passes if NOT (isCorrectTarget AND isFailure)

    // Check if last call matches the target function 
    let calldata = vm.get_last_calldata();
    let sig_str = format!("{}({})", signature.0, signature.1.join(","));
    let expected_selector = alloy_primitives::keccak256(sig_str.as_bytes());

    let is_correct_fn = if calldata.len() >= 4 {
        &calldata[..4] == &expected_selector[..4]
    } else {
        false
    };

    // Check if last call targets correct contract
    let is_correct_addr = vm.get_last_call_target() == Some(addr);
    let is_correct_target = is_correct_fn && is_correct_addr;

    // Check for invalid opcode (0xfe commonly used for assertions). Also true
    // if any *sub-call* halted with INVALID — flag is set in the inspector's
    // `call_end` so we catch nested cases that the outer `last_result` hides.
    let is_assertion_failure = vm.last_nested_invalid_fe
        || matches!(
            vm.last_result,
            Some(revm::context_interface::result::ExecutionResult::Halt {
                reason: revm::context_interface::result::HaltReason::InvalidFEOpcode
                    | revm::context_interface::result::HaltReason::OpcodeNotFound,
                ..
            })
        );

    // Check for Panic(1) (assert false) in Revert data — outer frame OR any
    // sub-call (nested flag captured per-frame in the inspector).
    let panic_1 = vm.last_nested_panic_1
        || if let Some(revm::context_interface::result::ExecutionResult::Revert { output, .. }) =
            &vm.last_result
        {
            if output.len() >= 4 + 32 {
                let selector = &output[..4];
                if selector == hex_literal::hex!("4e487b71") {
                    let code = &output[4..];
                    code[31] == 1 // Panic code 1 = assertion failure
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

    // Check for AssertionFailed(string) event
    let logs = vm.get_last_logs();
    let has_assertion_event = logs.iter().any(|log| {
        if let Some(topic) = log.topics().first() {
            // keccak256("AssertionFailed(string)")
            *topic
                == alloy_primitives::B256::from(hex_literal::hex!(
                    "b42604cb1052b6c312aa2193cb523f39d846b04f7988352656360c441c888806"
                ))
        } else {
            false
        }
    });

    let is_failure = is_assertion_failure || panic_1 || has_assertion_event;

    tracing::debug!(
        "check_assertion: fn={}, is_correct_fn={}, is_correct_addr={}, is_assertion_failure={}, panic_1={}, has_assertion_event={}, is_failure={}, is_correct_target={}, last_result={:?}",
        signature.0,
        is_correct_fn,
        is_correct_addr,
        is_assertion_failure,
        panic_1,
        has_assertion_event,
        is_failure,
        is_correct_target,
        vm.last_result.as_ref().map(|r| format!("{:?}", r).chars().take(150).collect::<String>())
    );

    // Test fails only if the correct target was called AND an assertion failure occurred
    // This matches Echidna's precise behavior
    if is_correct_target && is_failure {
        Ok((TestValue::BoolValue(false), TxResult::ErrorAssertionFailed))
    } else {
        Ok((TestValue::BoolValue(true), TxResult::Stop))
    }
}

/// Update a test based on the result of checking it
pub fn update_open_test(
    test: &mut EchidnaTest,
    reproducer: Vec<Tx>,
    test_value: TestValue,
    result: TxResult,
    worker_id: usize,
    _vm: &EvmState, // Note: We don't store VM - shrinking uses initial_vm
) -> bool {
    if !test.is_open() {
        return false;
    }

    match (&test_value, &test.value) {
        // Property test failed
        (TestValue::BoolValue(false), _) => {
            test.state = TestState::Large(0);
            test.reproducer = reproducer;
            test.result = result;
            test.value = test_value;
            test.worker_id = Some(worker_id);
            // Note: We don't store test.vm here - shrinking uses initial_vm
            true
        }

        // Optimization test found better value
        // Keep test Open - it will be closed for shrinking after test limit
        // Do NOT set worker_id here! This allows ALL workers
        // to continue competing to find better values. worker_id is only set
        // when closeOptimizationTest is called after test limit.
        (TestValue::IntValue(new), TestValue::IntValue(old)) if *new > *old => {
            test.reproducer = reproducer;
            test.result = result;
            test.value = test_value;
            // Note: We don't store test.vm here - shrinking uses initial_vm
            // State stays Open - closeOptimizationTest will set Large(0) after limit
            // worker_id is NOT set - all workers can continue optimizing!
            true
        }

        _ => false,
    }
}
