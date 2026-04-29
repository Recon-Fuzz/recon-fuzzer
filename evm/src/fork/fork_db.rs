//! Fork database that fetches from RPC

use alloy_primitives::{Address, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::BlockId;
use revm::database::{Database, DatabaseCommit, DatabaseRef};
use revm::state::{Account, AccountInfo, Bytecode};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::runtime::Runtime;

use super::cache::{cache_file_name, CachedAccount, CachedSlot, RpcCacheData};
use super::error::ForkError;
use super::rate_limiter::RateLimiter;

/// Type alias for the provider type returned by ProviderBuilder
type HttpProvider = alloy_provider::fillers::FillProvider<
    alloy_provider::fillers::JoinFill<
        alloy_provider::Identity,
        alloy_provider::fillers::JoinFill<
            alloy_provider::fillers::GasFiller,
            alloy_provider::fillers::JoinFill<
                alloy_provider::fillers::BlobGasFiller,
                alloy_provider::fillers::JoinFill<
                    alloy_provider::fillers::NonceFiller<
                        alloy_provider::fillers::CachedNonceManager,
                    >,
                    alloy_provider::fillers::ChainIdFiller,
                >,
            >,
        >,
    >,
    alloy_provider::RootProvider<alloy_provider::network::Ethereum>,
    alloy_provider::network::Ethereum,
>;

/// Options for creating a fork database
#[derive(Debug, Clone, Default)]
pub struct ForkOptions {
    /// Enable storage dump mode (requires debug_storageRangeAt API)
    /// When enabled, fetches entire contract storage in one call instead of slot-by-slot
    pub use_storage_dump: bool,
    /// Custom cache directory (defaults to ~/.cache/recon/fork_cache)
    pub cache_dir: Option<std::path::PathBuf>,
}

/// Fork database that fetches from RPC
pub struct ForkDb {
    /// Tokio runtime for async RPC calls (SHARED across clones for performance)
    rt: Arc<Runtime>,
    /// RPC provider (SHARED across clones for performance)
    provider: Arc<dyn Provider<alloy_provider::network::Ethereum> + Send + Sync>,
    /// RPC URL for reference
    rpc_url: String,
    /// Block to fetch from
    block_id: BlockId,
    /// Chain ID
    chain_id: u64,
    /// Block timestamp (fetched during init for accurate EVM execution)
    block_timestamp: u64,
    /// Cached accounts (in-memory, SHARED)
    accounts: Arc<RwLock<HashMap<Address, AccountInfo>>>,
    /// Cached storage slots (in-memory, SHARED)
    storage: Arc<RwLock<HashMap<(Address, U256), U256>>>,
    /// Contracts whose storage has been fully dumped (don't fetch individual slots)
    storage_dumped: Arc<RwLock<std::collections::HashSet<Address>>>,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// Whether to use storage dump mode (requires debug API)
    use_storage_dump: bool,
}

impl std::fmt::Debug for ForkDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkDb")
            .field("block_id", &self.block_id)
            .field("chain_id", &self.chain_id)
            .field("accounts_cached", &self.accounts.read().unwrap().len())
            .field("slots_cached", &self.storage.read().unwrap().len())
            .field("rpc_calls", &self.rate_limiter.total_calls())
            .finish()
    }
}

impl ForkDb {
    /// Create a new fork database with options
    pub fn new(
        rpc_url: &str,
        block: Option<u64>,
        options: ForkOptions,
    ) -> Result<Self, ForkError> {
        let rt = Arc::new(Runtime::new().map_err(|e| ForkError::Runtime(e.to_string()))?);

        let url: reqwest::Url = rpc_url
            .parse()
            .map_err(|e| ForkError::InvalidUrl(format!("{}: {}", rpc_url, e)))?;

        let provider: HttpProvider = ProviderBuilder::new().connect_http(url);

        let block_id = block.map(BlockId::number).unwrap_or(BlockId::latest());

        // Fetch chain ID and block timestamp with retry logic for rate limiting
        let mut last_err = None;
        for attempt in 0..5 {
            if attempt > 0 {
                // Back off exponentially: 500ms, 1s, 2s, 4s
                let backoff = std::time::Duration::from_millis(500 * (1 << (attempt - 1)));
                tracing::warn!("Rate limited fetching chain_id/block, waiting {:?}...", backoff);
                std::thread::sleep(backoff);
            }

            // Fetch chain_id and block info concurrently
            let result = rt.block_on(async {
                let chain_id_fut = provider.get_chain_id();
                let block_fut = provider.get_block(block_id);
                let (chain_res, block_res) = tokio::join!(chain_id_fut, block_fut);
                Ok::<_, ForkError>((
                    chain_res.map_err(|e| ForkError::Rpc(format!("chain_id: {}", e)))?,
                    block_res.map_err(|e| ForkError::Rpc(format!("block: {}", e)))?,
                ))
            });

            match result {
                Ok((chain_id, block_opt)) => {
                    // Extract timestamp from block header (default to 0 if block not found)
                    let block_timestamp = block_opt
                        .map(|b| b.header.timestamp)
                        .unwrap_or(0);

                    tracing::info!(
                        "Fork initialized: chain_id={}, block={:?}, timestamp={}, storage_dump={}",
                        chain_id,
                        block_id,
                        block_timestamp,
                        options.use_storage_dump
                    );
                    return Ok(Self {
                        rt,
                        provider: Arc::new(provider),
                        rpc_url: rpc_url.to_string(),
                        block_id,
                        chain_id,
                        block_timestamp,
                        accounts: Arc::new(RwLock::new(HashMap::new())),
                        storage: Arc::new(RwLock::new(HashMap::new())),
                        storage_dumped: Arc::new(RwLock::new(std::collections::HashSet::new())),
                        rate_limiter: RateLimiter::default(),
                        use_storage_dump: options.use_storage_dump,
                    });
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("429") || err_str.to_lowercase().contains("rate") {
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(ForkError::Rpc(format!(
            "Failed to fetch chain_id/block after 5 retries: {:?}",
            last_err
        )))
    }

    /// Load cache data into this ForkDb instance (without creating a new RPC connection)
    pub fn load_cache_data(&self, cache: &RpcCacheData) {
        // Load cached contracts
        {
            let mut accounts = self.accounts.write().unwrap();
            for (addr, cached) in &cache.contracts {
                let code_bytes = cached.code.0.clone();
                let (code_hash, code) = if code_bytes.is_empty() {
                    (alloy_primitives::KECCAK256_EMPTY, None)
                } else {
                    let bc = Bytecode::new_raw(code_bytes);
                    (bc.hash_slow(), Some(bc))
                };
                let nonce = u64::try_from(cached.nonce).unwrap_or(u64::MAX);
                let info = AccountInfo {
                    balance: cached.balance,
                    nonce,
                    code_hash,
                    code,
                    account_id: Default::default(),
                };
                accounts.insert(*addr, info);
            }
        }

        // Load cached storage slots
        {
            let mut storage = self.storage.write().unwrap();
            for slot in &cache.slots {
                storage.insert((slot.address, slot.slot), slot.value);
            }
        }

        tracing::info!(
            "Loaded cache: {} accounts, {} storage slots",
            self.accounts.read().unwrap().len(),
            self.storage.read().unwrap().len()
        );
    }

    /// Get chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get block number (None if using latest)
    pub fn block_number(&self) -> Option<u64> {
        match self.block_id {
            BlockId::Number(n) => n.as_number(),
            _ => None,
        }
    }

    /// Get block timestamp (fetched during fork initialization)
    pub fn block_timestamp(&self) -> u64 {
        self.block_timestamp
    }

    /// Get total RPC calls made
    pub fn rpc_call_count(&self) -> usize {
        self.rate_limiter.total_calls()
    }

    /// Snapshot the fork's cached external contracts as `(address, bytecode)`
    /// pairs. Empty-bytecode entries (EOAs and contracts where the RPC
    /// returned no code) are skipped — only contracts with usable bytecode
    /// are returned, since downstream consumers (source fetching, coverage)
    /// need bytecode to do anything useful.
    pub fn cached_contracts_with_code(&self) -> Vec<(Address, alloy_primitives::Bytes)> {
        let accounts = self.accounts.read().unwrap();
        accounts
            .iter()
            .filter_map(|(addr, info)| match &info.code {
                Some(bc) if !bc.is_empty() => Some((*addr, bc.original_bytes())),
                _ => None,
            })
            .collect()
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let accounts = self.accounts.read().unwrap().len();
        let storage = self.storage.read().unwrap().len();
        (accounts, storage)
    }

    /// Fetch account info from RPC (with caching and retry on 429)
    ///
    /// IMPORTANT: Returns empty account on RPC errors instead of propagating errors.
    /// This is the "lenient" approach - missing or unavailable accounts are treated as
    /// non-existent (empty), which matches Foundry's behavior and prevents transactions
    /// from failing due to RPC issues.
    fn fetch_account(&self, address: Address) -> Result<AccountInfo, ForkError> {
        // Check cache first
        if let Some(info) = self.accounts.read().unwrap().get(&address) {
            return Ok(info.clone());
        }

        // Retry loop for rate limiting
        for attempt in 0..3 {
            self.rate_limiter.wait_if_needed();
            if attempt == 0 {
                tracing::debug!("Fetching account: {:?}", address);
            }

            // Use concurrent requests for balance, nonce, and code
            let result = self.rt.block_on(async {
                let balance_fut = self
                    .provider
                    .get_balance(address)
                    .block_id(self.block_id);

                let nonce_fut = self
                    .provider
                    .get_transaction_count(address)
                    .block_id(self.block_id);

                let code_fut = self.provider.get_code_at(address).block_id(self.block_id);

                // Execute all three requests concurrently
                let (balance_res, nonce_res, code_res) =
                    tokio::join!(balance_fut, nonce_fut, code_fut);

                let balance =
                    balance_res.map_err(|e| ForkError::Rpc(format!("balance: {}", e)))?;
                let nonce = nonce_res.map_err(|e| ForkError::Rpc(format!("nonce: {}", e)))?;
                let code = code_res.map_err(|e| ForkError::Rpc(format!("code: {}", e)))?;

                Ok::<_, ForkError>((balance, nonce, code))
            });

            match result {
                Ok((balance, nonce, code)) => {
                    self.rate_limiter.on_success();

                    let (code_hash, code) = if code.is_empty() {
                        (alloy_primitives::KECCAK256_EMPTY, None)
                    } else {
                        let hash = alloy_primitives::keccak256(&code);
                        (hash, Some(Bytecode::new_raw(code)))
                    };

                    let info = AccountInfo {
                        balance,
                        nonce,
                        code_hash,
                        code,
                        account_id: Default::default(),
                    };

                    // Cache the result
                    self.accounts.write().unwrap().insert(address, info.clone());
                    return Ok(info);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("429") || err_str.contains("rate") {
                        self.rate_limiter.on_rate_limited();
                        if attempt < 2 {
                            continue;
                        }
                    }
                    // Non-rate-limit error: return empty account instead of failing
                    // This is the lenient approach - treat unavailable accounts as non-existent
                    tracing::debug!(
                        "Account fetch error for {:?}, returning empty account: {}",
                        address, e
                    );
                    let empty_info = AccountInfo::default();
                    self.accounts.write().unwrap().insert(address, empty_info.clone());
                    return Ok(empty_info);
                }
            }
        }

        // Max retries exceeded (rate limiting): return empty account instead of failing
        tracing::warn!(
            "Max retries exceeded for account {:?}, returning empty account",
            address
        );
        let empty_info = AccountInfo::default();
        self.accounts.write().unwrap().insert(address, empty_info.clone());
        Ok(empty_info)
    }

    /// Dump all storage for a contract using debug_storageRangeAt
    /// This is much faster than fetching slots one-by-one but requires debug API
    fn dump_storage(&self, address: Address) -> Result<(), ForkError> {
        // Check if already dumped
        if self.storage_dumped.read().unwrap().contains(&address) {
            return Ok(());
        }

        self.rate_limiter.wait_if_needed();
        tracing::debug!("Attempting storage dump for {:?} using debug API", address);

        // Use raw RPC call for debug_storageRangeAt
        // Format: debug_storageRangeAt(blockHash, txIndex, address, startKey, limit)
        let block_num = match self.block_id {
            BlockId::Number(n) => n.as_number().unwrap_or(0),
            _ => 0,
        };

        let result: Result<serde_json::Value, _> = self.rt.block_on(async {
            self.provider
                .client()
                .request(
                    "debug_storageRangeAt",
                    (
                        format!("0x{:x}", block_num),
                        0u64,
                        address,
                        "0x0000000000000000000000000000000000000000000000000000000000000000",
                        1000000000000000u64,
                    ),
                )
                .await
                .map_err(|e| ForkError::Rpc(format!("debug_storageRangeAt: {}", e)))
        });

        match result {
            Ok(response) => {
                self.rate_limiter.on_success();

                // Parse response: { "storage": { "key": { "key": "0x...", "value": "0x..." }, ... }, "nextKey": null }
                if let Some(storage_obj) = response.get("storage").and_then(|s| s.as_object()) {
                    let mut storage = self.storage.write().unwrap();
                    let mut count = 0;

                    for (_hash, entry) in storage_obj {
                        if let (Some(key_str), Some(value_str)) = (
                            entry.get("key").and_then(|k| k.as_str()),
                            entry.get("value").and_then(|v| v.as_str()),
                        ) {
                            // Parse hex strings to U256
                            if let (Ok(key), Ok(value)) = (
                                U256::from_str_radix(key_str.trim_start_matches("0x"), 16),
                                U256::from_str_radix(value_str.trim_start_matches("0x"), 16),
                            ) {
                                storage.insert((address, key), value);
                                count += 1;
                            }
                        }
                    }

                    tracing::info!("Dumped {} storage slots for {:?}", count, address);
                }

                // Mark as dumped
                self.storage_dumped.write().unwrap().insert(address);
                Ok(())
            }
            Err(e) => {
                // debug_storageRangeAt not available, fall back to slot-by-slot
                // Still mark as "attempted" so we don't retry for this address
                self.storage_dumped.write().unwrap().insert(address);
                tracing::debug!(
                    "Storage dump not available: {}, using slot-by-slot mode",
                    e
                );
                Err(e)
            }
        }
    }

    /// Fetch storage slot from RPC (with caching and retry on 429)
    fn fetch_storage(&self, address: Address, slot: U256) -> Result<U256, ForkError> {
        // Check cache first
        if let Some(val) = self.storage.read().unwrap().get(&(address, slot)) {
            return Ok(*val);
        }

        // If storage dump mode is enabled and we haven't tried dumping this contract yet
        if self.use_storage_dump && !self.storage_dumped.read().unwrap().contains(&address) {
            // Try to dump storage - if it succeeds, check the cache
            if self.dump_storage(address).is_ok() {
                // Check cache again after dump
                if let Some(val) = self.storage.read().unwrap().get(&(address, slot)) {
                    return Ok(*val);
                }
                // Slot not in dump means it's zero (uninitialized)
                return Ok(U256::ZERO);
            }
            // If dump failed, fall through to slot-by-slot fetching
        }

        // Retry loop for rate limiting
        for attempt in 0..5 {
            self.rate_limiter.wait_if_needed();
            if attempt == 0 {
                tracing::debug!("Fetching storage: {:?} slot={}", address, slot);
            }

            let result = self.rt.block_on(async {
                self.provider
                    .get_storage_at(address, slot)
                    .block_id(self.block_id)
                    .await
                    .map_err(|e| ForkError::Rpc(format!("storage: {}", e)))
            });

            match result {
                Ok(value) => {
                    self.rate_limiter.on_success();

                    // Cache the result
                    self.storage.write().unwrap().insert((address, slot), value);

                    return Ok(value);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("429") || err_str.to_lowercase().contains("rate") {
                        self.rate_limiter.on_rate_limited();
                        tracing::warn!(
                            "Rate limited on storage fetch (attempt {}), backing off...",
                            attempt + 1
                        );
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Err(ForkError::Rpc(
            "Max retries exceeded for storage fetch".to_string(),
        ))
    }

    /// Save cache to disk in the echidna/hevm-compatible
    /// `rpc-cache-<block>.json` format.
    pub fn save_cache(&self, cache_dir: &Path, block: u64) -> Result<(), ForkError> {
        std::fs::create_dir_all(cache_dir)
            .map_err(|e| ForkError::Cache(format!("create dir: {}", e)))?;

        let cache_file = cache_dir.join(cache_file_name(block));

        let mut cache = RpcCacheData::new();

        // Save contracts (skip empty/uninitialized accounts so the file isn't
        // polluted by transient lookups like address(0)).
        {
            let accounts = self.accounts.read().unwrap();
            for (addr, info) in accounts.iter() {
                let code = info
                    .code
                    .as_ref()
                    .map(|c| c.original_bytes())
                    .unwrap_or_default();
                cache.contracts.insert(
                    *addr,
                    CachedAccount {
                        code: code.into(),
                        nonce: U256::from(info.nonce),
                        balance: info.balance,
                    },
                );
            }
        }

        // Save storage slots
        {
            let storage = self.storage.read().unwrap();
            for ((addr, slot), value) in storage.iter() {
                cache.slots.push(CachedSlot {
                    address: *addr,
                    slot: *slot,
                    value: *value,
                });
            }
            // Stable order on disk
            cache.slots.sort_by(|a, b| a.address.cmp(&b.address).then(a.slot.cmp(&b.slot)));
        }

        let json = serde_json::to_string_pretty(&cache)
            .map_err(|e| ForkError::Cache(format!("serialize: {}", e)))?;

        std::fs::write(&cache_file, json)
            .map_err(|e| ForkError::Cache(format!("write: {}", e)))?;

        tracing::info!(
            "Saved RPC cache: {} contracts, {} slots to {:?}",
            cache.contracts.len(),
            cache.slots.len(),
            cache_file
        );

        Ok(())
    }

    /// Load cache from disk. Tries the new `rpc-cache-<block>.json` filename
    /// first (echidna-compatible) and falls back to the legacy
    /// `rpc_cache_<block>.json` written by older recon builds.
    pub fn load_cache(cache_dir: &Path, block: u64) -> Option<RpcCacheData> {
        let primary = cache_dir.join(cache_file_name(block));
        let legacy = cache_dir.join(format!("rpc_cache_{}.json", block));
        let path = if primary.exists() {
            primary
        } else if legacy.exists() {
            legacy
        } else {
            return None;
        };
        let json = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<RpcCacheData>(&json) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!("Failed to parse RPC cache {:?}: {}", path, e);
                None
            }
        }
    }
}

impl DatabaseRef for ForkDb {
    type Error = ForkError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // fetch_account handles caching internally
        self.fetch_account(address).map(Some)
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Code is fetched with account, so this should already be cached
        // Return empty if not found
        Ok(Bytecode::new())
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.fetch_storage(address, slot)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // Retry loop for rate limiting
        for attempt in 0..3 {
            self.rate_limiter.wait_if_needed();

            let result = self.rt.block_on(async {
                self.provider
                    .get_block_by_number(number.into())
                    .await
                    .map_err(|e| ForkError::Rpc(format!("block_hash: {}", e)))
            });

            match result {
                Ok(Some(block)) => {
                    self.rate_limiter.on_success();
                    return Ok(block.header.hash);
                }
                Ok(None) => {
                    // Block not found - return deterministic hash based on number
                    tracing::debug!("Block {} not found, returning deterministic hash", number);
                    return Ok(alloy_primitives::keccak256(number.to_be_bytes()));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("429") || err_str.to_lowercase().contains("rate") {
                        self.rate_limiter.on_rate_limited();
                        tracing::warn!(
                            "Rate limited on block_hash fetch (attempt {}), backing off...",
                            attempt + 1
                        );
                        continue;
                    }
                    // Non-rate-limit error: return deterministic hash instead of failing
                    tracing::debug!(
                        "Block hash fetch error for block {}, returning deterministic hash: {}",
                        number, e
                    );
                    return Ok(alloy_primitives::keccak256(number.to_be_bytes()));
                }
            }
        }

        // Max retries exceeded: return deterministic hash instead of failing
        tracing::warn!(
            "Max retries exceeded for block_hash {}, returning deterministic hash",
            number
        );
        Ok(alloy_primitives::keccak256(number.to_be_bytes()))
    }
}

impl Database for ForkDb {
    type Error = ForkError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.storage_ref(address, slot)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

impl DatabaseCommit for ForkDb {
    fn commit(&mut self, changes: revm::primitives::AddressMap<Account>) {
        let mut accounts = self.accounts.write().unwrap();
        let mut storage = self.storage.write().unwrap();

        for (address, account) in changes {
            // Update account info
            if !account.is_selfdestructed() {
                accounts.insert(address, account.info.clone());
            } else {
                accounts.remove(&address);
            }

            // Update storage
            if account.is_selfdestructed() {
                // If destroyed, strictly we should remove all storage slots for this address.
                // But efficient removal from HashMap<(addr, slot), val> is hard.
                // For now, we rely on REVM semantics: if destroyed, subsequent loads return 0.
                // But since we cache separate slots, we might return stale data if we don't clear!
                // Correctness requires clearing.
                storage.retain(|(k_addr, _), _| *k_addr != address);
            }

            for (slot, value) in account.storage {
                let val = value.present_value; // field access
                storage.insert((address, slot), val);
            }
        }
    }
}

impl Clone for ForkDb {
    /// Clone ForkDb by sharing runtime, provider, and caches.
    /// This is extremely fast - just Arc reference increments.
    ///
    /// Safe because:
    /// - Runtime/provider are thread-safe
    /// - Caches are protected by RwLock
    /// - EVM writes go to CacheDB layer, not ForkDb
    fn clone(&self) -> Self {
        Self {
            rt: Arc::clone(&self.rt),
            provider: Arc::clone(&self.provider),
            rpc_url: self.rpc_url.clone(),
            block_id: self.block_id,
            chain_id: self.chain_id,
            block_timestamp: self.block_timestamp,
            // Share all caches - they're read-only RPC data
            accounts: Arc::clone(&self.accounts),
            storage: Arc::clone(&self.storage),
            storage_dumped: Arc::clone(&self.storage_dumped),
            rate_limiter: self.rate_limiter.clone(), // Share rate limiter too
            use_storage_dump: self.use_storage_dump,
        }
    }
}
