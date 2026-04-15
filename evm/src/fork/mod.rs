//! Fork database for on-chain fuzzing
//!
//! Provides RPC-backed database for forking from live blockchain state.
//! Implements lazy fetching, caching, and rate limiting.

mod abi_decompiler;
mod cache;
mod error;
mod fork_db;
mod forkable_db;
mod rate_limiter;

#[cfg(test)]
mod tests;

// Re-export all public types
pub use abi_decompiler::{decompile_abi, DecompiledAbi, DecompiledFunction};
pub use cache::{CachedAccount, CachedSlot, RpcCacheData};
pub use error::ForkError;
pub use fork_db::{ForkDb, ForkOptions};
pub use forkable_db::{default_cache_dir, ForkableDb};
pub use rate_limiter::RateLimiter;
