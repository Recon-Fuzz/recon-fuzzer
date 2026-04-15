//! Static analysis utilities for smart contract fuzzing
//!
//! This crate provides:
//! - `slither`: Parse recon-generate/Slither JSON output for function relations, constants, etc.
//! - `bytecode`: Extract numeric constants from EVM bytecode PUSH instructions

pub mod bytecode;
pub mod slither;