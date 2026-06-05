//! Account management and state query methods for EvmState
//!
//! Contains nonce management, funding, code setting, and result queries.

use alloy_primitives::{Address, Bytes, B256, U256};
use rustc_hash::FxHashSet;
use revm::bytecode::Bytecode;
use revm::context_interface::result::{ExecutionResult, Output};
use revm::state::AccountInfo;
use revm::Database;
use std::collections::HashMap;
use std::sync::Arc;

use super::EvmState;

impl EvmState {
    /// Get account nonce
    pub fn get_nonce(&mut self, addr: Address) -> u64 {
        match self.db.basic(addr) {
            Ok(Some(info)) => info.nonce,
            _ => 0,
        }
    }

    /// Set account nonce (used to avoid address collisions during library deployment)
    pub fn set_nonce(&mut self, addr: Address, nonce: u64) {
        // Get existing account info or create default
        let mut info = match self.db.basic(addr) {
            Ok(Some(info)) => info,
            _ => AccountInfo::default(),
        };
        info.nonce = nonce;

        // Insert back into database
        self.db.insert_account_info(addr, info);
    }

    /// Ensure an account exists in the database
    /// If the account doesn't exist, create it with a large balance
    /// This prevents REVM panics when replaying corpus transactions with unknown senders
    pub fn ensure_account_exists(&mut self, addr: Address) {
        let exists = match self.db.basic(addr) {
            Ok(Some(info)) => !info.is_empty(),
            _ => false,
        };

        if !exists {
            // Fund with max/2 balance to allow transactions
            let funding = U256::MAX / U256::from(2);
            self.fund_account(addr, funding);
        }
    }

    /// Increment account nonce
    pub fn increment_nonce(&mut self, addr: Address) {
        let current = match self.db.basic(addr) {
            Ok(Some(info)) => info,
            _ => AccountInfo::default(),
        };
        let new_info = AccountInfo {
            nonce: current.nonce + 1,
            ..current
        };
        self.db.insert_account_info(addr, new_info);
    }

    /// Fund an account with ETH
    pub fn fund_account(&mut self, addr: Address, balance: U256) {
        let current = match self.db.basic(addr) {
            Ok(Some(info)) => info,
            _ => AccountInfo::default(),
        };
        let new_info = AccountInfo { balance, ..current };
        self.db.insert_account_info(addr, new_info);
    }

    /// Set contract code at an address
    pub fn set_code(&mut self, addr: Address, code: Bytes) {
        let bytecode = Bytecode::new_raw(code);
        let code_hash = bytecode.hash_slow();

        let current = match self.db.basic(addr) {
            Ok(Some(info)) => info,
            _ => AccountInfo::default(),
        };

        let new_info = AccountInfo {
            code_hash,
            code: Some(bytecode),
            nonce: if current.nonce == 0 { 1 } else { current.nonce },
            balance: current.balance,
            account_id: current.account_id,
        };
        self.db.insert_account_info(addr, new_info);
    }

    /// Check if a contract has been self-destructed
    pub fn has_selfdestructed(&self, _addr: Address) -> bool {
        false
    }

    /// Get the code hash at an address (for mapping to contract names)
    /// Returns KECCAK_EMPTY for accounts without code
    pub fn get_code_hash(&mut self, addr: Address) -> B256 {
        match self.db.basic(addr) {
            Ok(Some(info)) => info.code_hash,
            _ => revm::primitives::KECCAK_EMPTY,
        }
    }

    /// Get the output bytes of the last transaction
    pub fn get_last_output(&self) -> Bytes {
        match &self.last_result {
            Some(ExecutionResult::Success { output, .. }) => match output {
                Output::Call(data) => data.clone(),
                Output::Create(data, _) => data.clone(),
            },
            Some(ExecutionResult::Revert { output, .. }) => output.clone(),
            _ => Bytes::new(),
        }
    }

    /// Get the logs of the last transaction
    pub fn get_last_logs(&self) -> Vec<revm::primitives::Log> {
        match &self.last_result {
            Some(ExecutionResult::Success { logs, .. }) => logs.clone(),
            _ => Vec::new(),
        }
    }

    /// Get the gas used by the last transaction
    /// Returns 0 if no transaction has been executed or if gas info is unavailable
    pub fn get_last_gas_used(&self) -> u64 {
        match &self.last_result {
            Some(ExecutionResult::Success { gas, .. }) => gas.total_gas_spent(),
            Some(ExecutionResult::Revert { gas, .. }) => gas.total_gas_spent(),
            Some(ExecutionResult::Halt { gas, .. }) => gas.total_gas_spent(),
            None => 0,
        }
    }

    /// Get the calldata of the last transaction (for assertion test precision)
    pub fn get_last_calldata(&self) -> Bytes {
        self.last_calldata.clone()
    }

    /// Get the target address of the last call (for assertion test precision)
    pub fn get_last_call_target(&self) -> Option<Address> {
        self.last_call_target
    }

    /// Get the PCs touched during the last transaction execution
    /// Returns (codehash, pc) pairs for all branches hit
    pub fn get_last_touched_pcs(&self) -> &FxHashSet<(B256, usize)> {
        &self.last_touched_pcs
    }

    /// Get state diff from last transaction (storage changes)
    /// Returns: Vec<(address, slot, old_value, new_value)>
    pub fn get_last_state_diff(&self) -> Vec<(Address, U256, U256, U256)> {
        self.last_state_diff
            .iter()
            .map(|((addr, slot), (old, new))| (*addr, *slot, *old, *new))
            .collect()
    }

    /// Get storage value at a specific slot for an address
    /// Returns None if the account doesn't exist or slot hasn't been written
    pub fn get_storage(&mut self, addr: Address, slot: U256) -> Option<U256> {
        // Use Database trait's storage method
        self.db.storage(addr, slot).ok()
    }

    /// Register a storage layout for a specific address.
    /// Merge storage layouts from an inspector back into EvmState.
    /// Called after tx execution to persist layouts registered via
    /// vm.registerStorageLayout / vm.registerNamespace / vm.assignStorageLayout.
    pub fn merge_storage_layouts_from(&mut self, inspector_layouts: &Arc<HashMap<Address, crate::storage_layout::StorageLayout>>) {
        if Arc::ptr_eq(inspector_layouts, &self.storage_layouts) {
            return;
        }
        for (addr, layout) in inspector_layouts.iter() {
            let dominated = match self.storage_layouts.get(addr) {
                None => true,
                Some(existing) => layout.storage.len() > existing.storage.len(),
            };
            if dominated {
                Arc::make_mut(&mut self.storage_layouts).insert(*addr, layout.clone());
            }
        }
    }

    pub fn register_storage_layout(&mut self, addr: Address, layout: crate::storage_layout::StorageLayout) {
        Arc::make_mut(&mut self.storage_layouts).insert(addr, layout);
    }

    /// Auto-register storage layouts for newly created addresses by matching
    /// deployed bytecode metadata hashes against known compiled contracts.
    pub fn auto_register_storage_layouts(&mut self) {
        if self.last_created_addresses.is_empty() || self.layout_by_metadata.is_empty() {
            return;
        }
        for addr in self.last_created_addresses.clone() {
            if self.storage_layouts.contains_key(&addr) { continue; }
            let runtime_bytes = match self.db.get_code(addr) {
                Some(code) if !code.is_empty() => code,
                _ => continue,
            };
            let metadata_hash = crate::coverage::compute_metadata_hash(&runtime_bytes);
            if let Some((name, layout)) = self.layout_by_metadata.get(&metadata_hash) {
                if layout.storage.is_empty() { continue; }
                Arc::make_mut(&mut self.storage_layouts).insert(addr, layout.clone());
                tracing::debug!("Auto-registered storage layout for {:?} ({})", addr, name);
            }
        }
    }

    /// Populate `available_layouts` and `layout_by_metadata` from compiled contracts.
    /// Called once at startup after `load_storage_layouts()`.
    pub fn set_available_layouts(&mut self, contracts: &[crate::foundry::CompiledContract]) {
        let mut name_map = std::collections::HashMap::new();
        let mut meta_map = std::collections::HashMap::new();
        for c in contracts {
            if let Some(layout) = &c.storage_layout {
                name_map.insert(c.name.clone(), layout.clone());
                name_map.insert(c.qualified_name.clone(), layout.clone());
                if !c.deployed_bytecode.is_empty() {
                    let mh = crate::coverage::compute_metadata_hash(&c.deployed_bytecode);
                    meta_map.insert(mh, (c.name.clone(), layout.clone()));
                }
            }
        }
        self.available_layouts = Arc::new(name_map);
        self.layout_by_metadata = Arc::new(meta_map);
    }
}
