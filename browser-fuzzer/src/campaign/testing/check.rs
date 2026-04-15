//! Test checking functions for browser-fuzzer
//!
//! Port of campaign/src/testing/check.rs adapted for EvmState.

use alloy_primitives::{Address, Bytes, U256};

use crate::evm::exec::EvmState;
use crate::evm::exec::DEFAULT_SENDERS;
use crate::campaign::transaction::Tx;
use super::types::{
    CallTestPredicate, EchidnaTest, TestState, TestType, TestValue,
};

// =========================================================================
// Check functions (from campaign/src/testing/check.rs)
// =========================================================================

/// AssertionFailed(string) event topic
const ASSERTION_FAILED_TOPIC: [u8; 32] = hex_literal::hex!(
    "b42604cb1052b6c312aa2193cb523f39d846b04f7988352656360c441c888806"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallRes {
    ResTrue,
    ResFalse,
    ResRevert,
    ResOther,
}

/// Classify return data into CallRes
pub fn classify_result(success: bool, return_data: &[u8]) -> CallRes {
    if !success {
        return CallRes::ResRevert;
    }
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

pub fn check_etest(evm: &mut EvmState, test: &EchidnaTest) -> (TestValue, bool) {
    match &test.test_type {
        TestType::Exploration => (TestValue::BoolValue(true), true),
        TestType::PropertyTest { name, addr } => check_property(evm, name, *addr),
        TestType::OptimizationTest { name, addr } => check_optimization(evm, name, *addr),
        TestType::AssertionTest { signature, addr } => check_assertion(evm, signature, *addr),
        TestType::CallTest { predicate, .. } => check_call_test_predicate(evm, predicate),
    }
}

fn check_property(evm: &mut EvmState, name: &str, addr: Address) -> (TestValue, bool) {
    // Build selector from function name: name()
    let sig = format!("{name}()");
    let selector = alloy_primitives::keccak256(sig.as_bytes());
    let calldata = Bytes::copy_from_slice(&selector[..4]);

    // Use first sender
    let sender = DEFAULT_SENDERS[0];
    let trace = evm.exec_tx(sender, addr, calldata, U256::ZERO);

    let output = evm.get_last_output();
    let call_res = classify_result(trace.success, &output);
    let passed = matches!(call_res, CallRes::ResTrue);
    (TestValue::BoolValue(passed), passed)
}

/// Check an optimization test: call function and extract I256 return value
fn check_optimization(evm: &mut EvmState, name: &str, addr: Address) -> (TestValue, bool) {
    use alloy_primitives::I256;

    let sig = format!("{name}()");
    let selector = alloy_primitives::keccak256(sig.as_bytes());
    let calldata = Bytes::copy_from_slice(&selector[..4]);

    let sender = DEFAULT_SENDERS[0];
    let trace = evm.exec_tx(sender, addr, calldata, U256::ZERO);

    if trace.success {
        let output = evm.get_last_output();
        if output.len() >= 32 {
            let bytes: [u8; 32] = output[..32].try_into().unwrap();
            let val = I256::from_be_bytes(bytes);
            return (TestValue::IntValue(val), true);
        }
    }
    (TestValue::IntValue(I256::MIN), true)
}

/// Check an assertion test after each tx
/// Checks: InvalidFEOpcode, Panic(1), AssertionFailed event
pub fn check_assertion(
    evm: &EvmState,
    signature: &(String, Vec<String>),
    addr: Address,
) -> (TestValue, bool) {
    use revm::context_interface::result::{ExecutionResult, HaltReason};

    // Check if last call matches the target function
    let sig_str = format!("{}({})", signature.0, signature.1.join(","));
    let expected_selector = alloy_primitives::keccak256(sig_str.as_bytes());

    let calldata = evm.get_last_calldata();
    let is_correct_fn = calldata.len() >= 4 && calldata[..4] == expected_selector[..4];
    let is_correct_addr = evm.get_last_call_target() == Some(addr);
    let is_correct_target = is_correct_fn && is_correct_addr;

    // Check for invalid opcode (0xfe)
    let is_assertion_failure = matches!(
        &evm.last_result,
        Some(ExecutionResult::Halt {
            reason: HaltReason::InvalidFEOpcode | HaltReason::OpcodeNotFound,
            ..
        })
    );

    // Check for Panic(1) in revert data
    let panic_1 = if let Some(ExecutionResult::Revert { output, .. }) = &evm.last_result {
        if output.len() >= 4 + 32 {
            let selector = &output[..4];
            selector == hex_literal::hex!("4e487b71") && output[4 + 31] == 1
        } else {
            false
        }
    } else {
        false
    };

    // Check for AssertionFailed(string) event
    let has_assertion_event = evm.get_last_logs().iter().any(|log| {
        log.topics()
            .first()
            .map(|t| t.0 == ASSERTION_FAILED_TOPIC)
            .unwrap_or(false)
    });

    let is_failure = is_assertion_failure || panic_1 || has_assertion_event;

    if is_correct_target && is_failure {
        (TestValue::BoolValue(false), false)
    } else {
        (TestValue::BoolValue(true), true)
    }
}

/// Check for AssertionFailed events (CallTest predicate)
pub fn check_call_test_predicate(
    evm: &EvmState,
    predicate: &CallTestPredicate,
) -> (TestValue, bool) {
    match predicate {
        CallTestPredicate::AssertionFailed => {
            let has_event = evm.get_last_logs().iter().any(|log| {
                log.topics()
                    .first()
                    .map(|t| t.0 == ASSERTION_FAILED_TOPIC)
                    .unwrap_or(false)
            });
            if has_event {
                (TestValue::BoolValue(false), false)
            } else {
                (TestValue::BoolValue(true), true)
            }
        }
    }
}

/// Update an open test based on check result
pub fn update_open_test(
    test: &mut EchidnaTest,
    reproducer: Vec<Tx>,
    test_value: TestValue,
) -> bool {
    if !test.is_open() {
        return false;
    }

    match (&test_value, &test.value) {
        // Property/assertion test failed
        (TestValue::BoolValue(false), _) => {
            test.state = TestState::Large(0);
            test.reproducer = reproducer;
            test.value = test_value;
            test.worker_id = Some(0);
            true
        }
        // Optimization test found better value
        (TestValue::IntValue(new), TestValue::IntValue(old)) if *new > *old => {
            test.reproducer = reproducer;
            test.value = test_value;
            true
        }
        _ => false,
    }
}
