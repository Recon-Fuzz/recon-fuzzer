//! Foundational types, traits, and constants for recon-fuzzer
//!
//! This crate provides the absolute foundation that all other crates depend on.
//! It has no internal dependencies and only depends on alloy-primitives.

pub mod constants;
pub mod address;
pub mod traits;

pub use constants::*;
pub use address::*;
pub use traits::*;

// Re-export commonly used alloy types for convenience
pub use alloy_primitives::{Address, Bytes, FixedBytes, B256, I256, U256};
