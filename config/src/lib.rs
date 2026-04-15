//! Configuration types for recon-fuzzer
//!
//! This crate provides pure configuration types that can be loaded from YAML/CLI.
//! Runtime-dependent types (Env, WorkerState, etc.) are in the `campaign` crate.

pub mod campaign;
pub mod solidity;
pub mod transaction;
pub mod global;