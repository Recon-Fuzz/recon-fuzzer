//! Foundry reproducer generation (`--repro`).
//!
//! Converts shrunk reproducers into Solidity test functions and appends them to
//! an existing CryticToFoundry-style file in real time — no need to wait for the
//! campaign to finish.
//!
//! # Module structure
//!
//! - **`formatter`** — `DynSolValue` → Solidity literal conversion. Handles
//!   scalars inline and emits variable declarations for arrays/tuples.
//! - **`codegen`** — Askama-based test function rendering. Converts a `Vec<Tx>`
//!   reproducer into a complete `function test_…() public { … }` block.
//! - **`writer`** — Thread-safe file I/O. Appends rendered tests before the
//!   final `}` of the target Solidity file.

pub mod codegen;
pub mod formatter;
pub mod writer;

pub use writer::ReproWriter;
