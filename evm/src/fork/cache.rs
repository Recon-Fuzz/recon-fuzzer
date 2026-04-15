//! Cache types for RPC data persistence

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cached contract data for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAccount {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub code: Option<Bytes>,
}

/// Cached storage slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSlot {
    pub address: Address,
    pub slot: U256,
    pub value: U256,
}

/// RPC cache data for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCacheData {
    pub block: u64,
    pub chain_id: u64,
    pub accounts: HashMap<Address, CachedAccount>,
    pub storage: Vec<CachedSlot>,
}

impl RpcCacheData {
    pub fn new(block: u64, chain_id: u64) -> Self {
        Self {
            block,
            chain_id,
            accounts: HashMap::new(),
            storage: Vec::new(),
        }
    }
}
