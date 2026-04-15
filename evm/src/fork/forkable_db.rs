//! ForkableDb - Database enum that supports both empty and fork modes

use alloy_primitives::{Address, B256, U256};
use revm::database::{CacheDB, Database, DatabaseCommit, DatabaseRef, EmptyDB};
use revm::state::{Account, AccountInfo, Bytecode};
use std::path::Path;

use super::error::ForkError;
use super::fork_db::{ForkDb, ForkOptions};

/// Default cache directory for fork data
pub fn default_cache_dir() -> std::path::PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("recon")
        .join("fork_cache")
}

/// Database that can be either in-memory only or forked from RPC
pub enum ForkableDb {
    /// In-memory only (no forking)
    Empty(CacheDB<EmptyDB>),
    /// Forked from RPC - uses CacheDB for local caching on top of ForkDb
    Fork(CacheDB<ForkDb>),
}

impl std::fmt::Debug for ForkableDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForkableDb::Empty(_) => write!(f, "ForkableDb::Empty"),
            ForkableDb::Fork(db) => write!(f, "ForkableDb::Fork({:?})", db.db),
        }
    }
}

impl Clone for ForkableDb {
    fn clone(&self) -> Self {
        match self {
            ForkableDb::Empty(db) => ForkableDb::Empty(db.clone()),
            ForkableDb::Fork(db) => ForkableDb::Fork(db.clone()),
        }
    }
}

impl ForkableDb {
    /// Create new empty database (no forking)
    pub fn new_empty() -> Self {
        ForkableDb::Empty(CacheDB::new(EmptyDB::default()))
    }

    /// Create new forked database with all optimizations
    ///
    /// This is the single, unified entry point for fork mode:
    /// 1. Automatic disk cache loading/saving (persists RPC responses)
    /// 2. Optional storage dump mode (requires debug API, fetches full contract storage at once)
    /// 3. Shared caches across clones (cheap Clone for multi-threaded fuzzing)
    /// 4. Rate limiting with exponential backoff
    ///
    /// # Arguments
    /// * `rpc_url` - The RPC endpoint URL
    /// * `block` - Optional block number to fork at. If None, uses latest.
    /// * `options` - Fork options (storage dump mode, custom cache dir)
    pub fn new_fork(
        rpc_url: &str,
        block: Option<u64>,
        options: ForkOptions,
    ) -> Result<Self, ForkError> {
        let cache_path = options.cache_dir.clone().unwrap_or_else(default_cache_dir);

        // Create the fork with options
        let fork_db = ForkDb::new(rpc_url, block, options)?;
        let chain_id = fork_db.chain_id();

        // Get resolved block number for cache key
        let block_num = fork_db.block_number().unwrap_or(0);

        // Try to load existing cache
        let chain_cache_dir = cache_path.join(format!("chain_{}", chain_id));
        if let Some(cache) = ForkDb::load_cache(&chain_cache_dir, block_num) {
            tracing::info!(
                "Loaded fork cache: {} accounts, {} slots",
                cache.accounts.len(),
                cache.storage.len()
            );
            fork_db.load_cache_data(&cache);
        } else {
            tracing::info!("No existing cache, starting fresh");
        }

        Ok(ForkableDb::Fork(CacheDB::new(fork_db)))
    }

    /// Check if database is in fork mode
    pub fn is_fork(&self) -> bool {
        matches!(self, ForkableDb::Fork(_))
    }

    /// Get chain ID (only available in fork mode)
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            ForkableDb::Empty(_) => None,
            ForkableDb::Fork(db) => Some(db.db.chain_id()),
        }
    }

    /// Get RPC call count (only available in fork mode)
    pub fn rpc_call_count(&self) -> usize {
        match self {
            ForkableDb::Empty(_) => 0,
            ForkableDb::Fork(db) => db.db.rpc_call_count(),
        }
    }

    /// Save RPC cache to disk (fork mode only)
    pub fn save_rpc_cache(&self, cache_dir: &Path, block: u64) -> Result<(), ForkError> {
        match self {
            ForkableDb::Empty(_) => Ok(()), // No-op for empty db
            ForkableDb::Fork(db) => db.db.save_cache(cache_dir, block),
        }
    }

    /// Save cache to default location automatically organized by chain_id and block
    /// Cache is saved to: `{default_cache_dir}/chain_{chain_id}/rpc_cache_{block}.json`
    pub fn save_to_default_cache(&self) -> Result<(), ForkError> {
        match self {
            ForkableDb::Empty(_) => Ok(()), // No-op for empty db
            ForkableDb::Fork(db) => {
                let chain_id = db.db.chain_id();
                let block = db.db.block_number().unwrap_or(0);
                let cache_dir = default_cache_dir().join(format!("chain_{}", chain_id));
                db.db.save_cache(&cache_dir, block)
            }
        }
    }

    /// Get the block number being forked (for cache identification)
    pub fn fork_block_number(&self) -> Option<u64> {
        match self {
            ForkableDb::Empty(_) => None,
            ForkableDb::Fork(db) => db.db.block_number(),
        }
    }

    /// Get the block timestamp of the forked block
    pub fn fork_block_timestamp(&self) -> Option<u64> {
        match self {
            ForkableDb::Empty(_) => None,
            ForkableDb::Fork(db) => Some(db.db.block_timestamp()),
        }
    }

    /// Insert account info (works for both modes)
    pub fn insert_account_info(&mut self, address: Address, info: AccountInfo) {
        match self {
            ForkableDb::Empty(db) => db.insert_account_info(address, info),
            ForkableDb::Fork(db) => db.insert_account_info(address, info),
        }
    }

    /// Get mutable access to cached account (for direct code modification)
    /// Used by deploy_contract_at to replace init code with runtime code
    pub fn get_cached_account_mut(
        &mut self,
        address: &Address,
    ) -> Option<&mut revm::database::in_memory_db::DbAccount> {
        match self {
            ForkableDb::Empty(db) => db.cache.accounts.get_mut(address),
            ForkableDb::Fork(db) => db.cache.accounts.get_mut(address),
        }
    }

    /// Get immutable access to cached account
    pub fn get_cached_account(
        &self,
        address: &Address,
    ) -> Option<&revm::database::in_memory_db::DbAccount> {
        match self {
            ForkableDb::Empty(db) => db.cache.accounts.get(address),
            ForkableDb::Fork(db) => db.cache.accounts.get(address),
        }
    }

    /// Get storage slot value (immutable, uses DatabaseRef)
    pub fn get_storage(&self, address: Address, slot: U256) -> Option<U256> {
        self.storage_ref(address, slot).ok()
    }

    /// Get code for an address (immutable, uses DatabaseRef)
    pub fn get_code(&self, address: Address) -> Option<alloy_primitives::Bytes> {
        match self.basic_ref(address) {
            Ok(Some(account_info)) => {
                // Get code from account info - it may be stored directly or via code_hash
                if let Some(code) = account_info.code {
                    if !code.is_empty() {
                        return Some(code.original_bytes());
                    }
                }
                // If code not directly available, try code_by_hash
                let code_hash = account_info.code_hash;
                if code_hash != B256::ZERO && code_hash != alloy_primitives::keccak256([]) {
                    match self.code_by_hash_ref(code_hash) {
                        Ok(bytecode) if !bytecode.is_empty() => Some(bytecode.original_bytes()),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Database for ForkableDb {
    type Error = ForkError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .basic(address)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.basic(address),
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .code_by_hash(code_hash)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.code_by_hash(code_hash),
        }
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .storage(address, slot)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.storage(address, slot),
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .block_hash(number)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.block_hash(number),
        }
    }
}

impl DatabaseCommit for ForkableDb {
    fn commit(&mut self, changes: alloy_primitives::map::HashMap<Address, Account>) {
        match self {
            ForkableDb::Empty(db) => db.commit(changes),
            ForkableDb::Fork(db) => db.commit(changes),
        }
    }
}

impl DatabaseRef for ForkableDb {
    type Error = ForkError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .basic_ref(address)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.basic_ref(address),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .code_by_hash_ref(code_hash)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.code_by_hash_ref(code_hash),
        }
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .storage_ref(address, slot)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.storage_ref(address, slot),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        match self {
            ForkableDb::Empty(db) => db
                .block_hash_ref(number)
                .map_err(|_| ForkError::Rpc("EmptyDB error (should never happen)".to_string())),
            ForkableDb::Fork(db) => db.block_hash_ref(number),
        }
    }
}
