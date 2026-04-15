//! Test types and checking module
//!
//! Rust equivalent of Echidna's Types/Test.hs and Test.hs
//! Contains test types, checking logic, and worker-specific checking functions.

mod check;
mod types;
mod worker;

// Re-export all public items from types
pub use types::{
    calculate_delay_complexity, calculate_value_complexity, create_tests, is_successful,
    CallTestPredicate, EchidnaTest, ShrinkContext, ShrinkMode, TestState, TestType, TestValue,
    SHRINK_MODE_SWITCH_THRESHOLD,
};

// Re-export all public items from check
pub use check::{
    check_assertion, check_call_test_predicate, check_etest, classify_result, update_open_test,
    CallRes,
};

// Re-export all public items from worker
pub use worker::{
    check_cheap_tests_after_tx_worker, check_tests_after_tx_worker,
    check_tests_after_tx_worker_with_checkpoint, check_tests_without_optimization_worker,
    check_tests_worker,
};
