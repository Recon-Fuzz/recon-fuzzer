//! EVM execution using REVM
//!
//! Implements transaction execution with REVM integration

mod helpers;
mod state;
mod transaction;

#[cfg(test)]
mod tests;

use alloy_primitives::{Address, Bytes, B256, U256};
use revm::bytecode::Bytecode;
use revm::context_interface::result::ExecutionResult;
use revm::state::AccountInfo;
use std::collections::HashMap;
use thiserror::Error;

use crate::fork::{ForkError, ForkableDb};
use crate::types::{INITIAL_BLOCK_NUMBER, INITIAL_TIMESTAMP};

// Re-export helpers for external use
pub use helpers::{classify_execution_result, encode_call};

// Re-export CoverageMap from coverage module
pub use crate::coverage::CoverageMap;

/// Coverage info for a single opcode: (opcode index, stack depth bits, tx result bits)
/// Note: In Map, key is PC (serving as opcode index)
pub type CoverageInfo = (i32, u64, u64);

/// Errors during EVM execution
#[derive(Error, Debug)]
pub enum ExecError {
    #[error("EVM execution error: {0}")]
    EvmError(String),

    #[error("Contract not found: {0}")]
    ContractNotFound(Address),

    #[error("ABI encoding error: {0}")]
    AbiError(String),

    #[error("Database error: {0}")]
    DbError(String),
}

/// EVM state wrapper
/// Uses ForkableDb which supports both in-memory and RPC-forked state
#[derive(Debug, Clone)]
pub struct EvmState {
    /// The database (in-memory or forked from RPC)
    pub db: ForkableDb,

    /// Current block number
    pub block_number: u64,

    /// Current timestamp
    pub timestamp: u64,

    /// Gas limit for transactions
    pub gas_limit: u64,

    /// Result of the last transaction execution
    pub last_result: Option<ExecutionResult>,

    /// Calldata of the last transaction (for assertion test precision)
    pub last_calldata: Bytes,

    /// Target address of the last call (for assertion test precision)
    pub last_call_target: Option<Address>,

    /// Newly created addresses from the last transaction (internal CREATE/CREATE2)
    pub last_created_addresses: Vec<Address>,

    /// Storage changes from the last transaction: (address, slot) -> (old_value, new_value)
    /// Only populated for non-reverted transactions
    pub last_state_diff: HashMap<(Address, U256), (U256, U256)>,

    /// Address labels set via vm.label() cheatcode
    /// These persist across transactions for trace decoding
    pub labels: HashMap<Address, String>,

    /// PCs touched during the last transaction: (codehash, pc)
    /// Used by corpus analysis to check if target branches were reached
    pub last_touched_pcs: std::collections::HashSet<(B256, usize)>,

    /// Coverage tracking mode (Full or Branch)
    /// Branch mode only tracks JUMPI/JUMPDEST for faster execution
    pub coverage_mode: crate::coverage::CoverageMode,

    /// Context for vm.generateCalls() cheatcode (on-demand generation)
    /// Set by campaign layer before tx execution to enable reentrancy testing
    /// Contains: (fuzzable_functions, gen_dict, rng_seed)
    pub generate_calls_context: Option<(
        Vec<(alloy_primitives::FixedBytes<4>, String, Vec<alloy_dyn_abi::DynSolType>)>,
        abi::types::GenDict,
        u64,
    )>,
}

impl Default for EvmState {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmState {
    pub fn new() -> Self {
        let mut state = Self {
            db: ForkableDb::new_empty(),
            block_number: INITIAL_BLOCK_NUMBER,
            timestamp: INITIAL_TIMESTAMP,
            gas_limit: 1_000_000_000_000, // High gas limit (1T) but not u64::MAX to avoid overflow
            last_result: None,
            last_calldata: Bytes::new(),
            last_call_target: None,
            last_created_addresses: Vec::new(),
            last_state_diff: HashMap::new(),
            labels: HashMap::new(),
            last_touched_pcs: std::collections::HashSet::new(),
            coverage_mode: crate::coverage::CoverageMode::Full,
            generate_calls_context: None,
        };

        // Deploy a dummy contract at the HEVM cheatcode address
        // This ensures that calls to the cheatcode address go through the inspector
        // Without code, the EVM might not invoke the inspector's call method
        let hevm_addr = crate::cheatcodes::HEVM_ADDRESS;

        // Simple bytecode that just returns (STOP opcode)
        // 0x00 = STOP
        let hevm_code = Bytecode::new_raw(Bytes::from_static(&[0x00]));
        let hevm_info = AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: hevm_code.hash_slow(),
            code: Some(hevm_code),
            account_id: Default::default(),
        };
        state.db.insert_account_info(hevm_addr, hevm_info);

        state
    }

    /// Create a new EvmState that forks from an RPC endpoint
    ///
    /// This is the single entry point for fork mode with all optimizations:
    /// - Automatic disk cache loading/saving (persists RPC responses across runs)
    /// - Optional storage dump mode (requires debug API for faster storage fetching)
    /// - Shared caches across clones (cheap Clone for multi-threaded fuzzing)
    /// - Rate limiting with exponential backoff
    ///
    /// # Arguments
    /// * `rpc_url` - The RPC endpoint URL (e.g., "https://eth.llamarpc.com")
    /// * `block` - Optional block number to fork at. If None, uses latest.
    /// * `options` - Fork options (storage dump mode, custom cache dir)
    pub fn new_fork(
        rpc_url: &str,
        block: Option<u64>,
        options: crate::fork::ForkOptions,
    ) -> Result<Self, ForkError> {
        let db = ForkableDb::new_fork(rpc_url, block, options)?;

        // Use the actual fork block number and timestamp if available, otherwise use defaults
        let fork_block = db.fork_block_number().unwrap_or(INITIAL_BLOCK_NUMBER);
        let fork_timestamp = db.fork_block_timestamp().unwrap_or(INITIAL_TIMESTAMP);

        let mut state = Self {
            db,
            block_number: fork_block,
            timestamp: fork_timestamp,
            gas_limit: 1_000_000_000_000,
            last_result: None,
            last_calldata: Bytes::new(),
            last_call_target: None,
            last_created_addresses: Vec::new(),
            last_state_diff: HashMap::new(),
            labels: HashMap::new(),
            last_touched_pcs: std::collections::HashSet::new(),
            coverage_mode: crate::coverage::CoverageMode::Full,
            generate_calls_context: None,
        };

        // Deploy HEVM cheatcode stub
        let hevm_addr = crate::cheatcodes::HEVM_ADDRESS;
        let hevm_code = Bytecode::new_raw(Bytes::from_static(&[0x00]));
        let hevm_info = AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: hevm_code.hash_slow(),
            code: Some(hevm_code),
            account_id: Default::default(),
        };
        state.db.insert_account_info(hevm_addr, hevm_info);

        Ok(state)
    }

    /// Set coverage mode (Full or Branch)
    pub fn set_coverage_mode(&mut self, mode: crate::coverage::CoverageMode) {
        self.coverage_mode = mode;
    }

    /// Save fork cache to default location
    pub fn save_fork_cache(&self) -> Result<(), ForkError> {
        self.db.save_to_default_cache()
    }

    /// Save the fork's RPC cache as `rpc-cache-<block>.json` directly inside
    /// `dir` (echidna-compatible layout). Use this to persist the cache into
    /// the project's corpus dir alongside reproducers.
    pub fn save_fork_cache_to_dir(&self, dir: &std::path::Path) -> Result<(), ForkError> {
        let block = match self.db.fork_block_number() {
            Some(b) => b,
            None => return Ok(()),
        };
        self.db.save_rpc_cache(dir, block)
    }

    /// Load `rpc-cache-<block>.json` from `dir` into this fork (no-op if the
    /// file isn't there or this isn't a fork).
    pub fn load_fork_cache_from_dir(&self, dir: &std::path::Path) -> Result<bool, ForkError> {
        self.db.load_cache_from_dir(dir)
    }

    /// Snapshot the addresses + runtime bytecodes the fork fetched from RPC
    /// during this run (skipping EOAs / empty-code accounts).
    pub fn fork_contracts_with_code(&self) -> Vec<(alloy_primitives::Address, alloy_primitives::Bytes)> {
        self.db.cached_contracts_with_code()
    }

    /// Check if this EVM state is forked from RPC
    pub fn is_fork(&self) -> bool {
        self.db.is_fork()
    }

    /// Get chain ID (only available in fork mode)
    pub fn chain_id(&self) -> Option<u64> {
        self.db.chain_id()
    }

    /// Get the fork block number (only available in fork mode)
    pub fn fork_block_number(&self) -> Option<u64> {
        self.db.fork_block_number()
    }
}
