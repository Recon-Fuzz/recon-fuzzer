//! Test shrinking module
//!
//! Rust equivalent of Echidna's Shrink.hs
//! Contains core shrinking logic and worker-specific shrinking functions.

mod core;
mod worker;

// Re-export all public items
pub use core::{shrink_sender, shrink_test, shrink_test_worker};
pub use worker::{close_and_shrink_optimization_tests, shrink_pending_tests_worker};
