//! Browser-based EVM backed by revm's CacheDB (in-memory, no I/O).
//!
//! Mirrors the patterns in evm/src/exec/ (Context::mainnet(), modify_cfg_chained,
//! build_mainnet_with_inspector, inspect_tx) but simplified for WASM.

use alloy_primitives::{Address, Bytes, Log, TxKind, U256};
use revm::bytecode::Bytecode;
use revm::context_interface::result::{ExecutionResult, Output};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, InspectEvm, MainBuilder, MainContext};
use revm_database::{CacheDB, EmptyDB};
use std::collections::HashMap;

use crate::evm::cheatcodes::{CheatcodeInspector, HEVM_ADDRESS};
use crate::evm::coverage::{DeploymentPcCounter, CoverageMap, MetadataToCodehash, TxResult, check_and_merge_coverage};
use crate::evm::tracing::{ExecResult, StateChange, create_tracing_inspector};

// =========================================================================
// Default constants (mirrors primitives/src/constants.rs and config/src/)
// =========================================================================

/// Maximum gas per block (Ethereum mainnet) — config/src/transaction.rs
pub const MAX_GAS_PER_BLOCK: u64 = 1_000_000_000_000;

/// Initial timestamp (Echidna default: Thu Apr 26 23:39:52 UTC 2018)
pub const INITIAL_TIMESTAMP: u64 = 1524785992;

/// Initial block number (Byzantium fork)
pub const INITIAL_BLOCK_NUMBER: u64 = 4370000;

/// Default deployer address — config/src/solidity.rs
/// 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38
pub const DEFAULT_DEPLOYER: Address = Address::new([
    0x18, 0x04, 0xc8, 0xAB, 0x1F, 0x12, 0xE6, 0xbb, 0xf3, 0x89, 0x4d, 0x40, 0x83, 0xf3, 0x3e,
    0x07, 0x30, 0x9d, 0x1f, 0x38,
]);

/// Default contract address — config/src/solidity.rs (Echidna default)
/// 0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496
pub const DEFAULT_CONTRACT_ADDR: Address = Address::new([
    0x7F, 0xA9, 0x38, 0x5b, 0xE1, 0x02, 0xac, 0x3E, 0xAc, 0x29, 0x74, 0x83, 0xDd, 0x62, 0x33,
    0xD6, 0x2b, 0x3e, 0x14, 0x96,
]);

/// Default sender addresses — primitives/src/address.rs
pub const DEFAULT_SENDERS: [Address; 3] = [
    Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    ]),
    Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    ]),
    Address::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    ]),
];

/// Default balance for test accounts (very large, from primitives)
pub const DEFAULT_BALANCE: U256 = U256::from_limbs([
    0xffffffffffffffff,
    0xffffffffffffffff,
    0,
    0,
]);

/// Test mode (matches config/src/solidity.rs TestMode)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TestMode {
    Property,
    Assertion,
    Optimization,
    Exploration,
}

/// Browser-based EVM backed by revm's CacheDB (in-memory, no I/O).
pub struct EvmState {
    db: CacheDB<EmptyDB>,
    cheatcode_inspector: CheatcodeInspector,
    coverage_inspector: DeploymentPcCounter,
    /// Runtime coverage map: codehash -> pc -> (depth_bits, result_bits)
    pub coverage: CoverageMap,
    /// Init/deployment coverage map
    pub init_coverage: CoverageMap,
    pub block_number: u64,
    pub timestamp: u64,
    pub labels: HashMap<Address, String>,
    snapshots: HashMap<u32, (CacheDB<EmptyDB>, u64, u64)>,
    next_snapshot_id: u32,
    pub last_result: Option<ExecutionResult>,
    pub last_logs: Vec<Log>,
    pub last_calldata: Vec<u8>,
    pub last_call_target: Option<Address>,
    pub last_state_diff: HashMap<(Address, U256), (U256, U256)>,
    pub last_created_addresses: Vec<Address>,
}

impl EvmState {
    pub fn new() -> Self {
        let db = CacheDB::new(EmptyDB::default());

        let mut evm = EvmState {
            db,
            cheatcode_inspector: CheatcodeInspector::new(),
            coverage_inspector: DeploymentPcCounter::new(MetadataToCodehash::new()),
            coverage: CoverageMap::new(),
            init_coverage: CoverageMap::new(),
            block_number: INITIAL_BLOCK_NUMBER,
            timestamp: INITIAL_TIMESTAMP,
            labels: HashMap::new(),
            snapshots: HashMap::new(),
            next_snapshot_id: 0,
            last_result: None,
            last_logs: Vec::new(),
            last_calldata: Vec::new(),
            last_call_target: None,
            last_state_diff: HashMap::new(),
            last_created_addresses: Vec::new(),
        };

        // Deploy HEVM cheatcode stub
        let hevm_code = Bytecode::new_raw(Bytes::from_static(&[0x00]));
        let hevm_info = AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: hevm_code.hash_slow(),
            code: Some(hevm_code),
            ..Default::default()
        };
        evm.db.insert_account_info(HEVM_ADDRESS, hevm_info);

        // Fund default deployer and senders
        let funded_info = AccountInfo {
            balance: DEFAULT_BALANCE,
            ..Default::default()
        };
        evm.db.insert_account_info(DEFAULT_DEPLOYER, funded_info.clone());
        for sender in &DEFAULT_SENDERS {
            evm.db.insert_account_info(*sender, funded_info.clone());
        }

        evm
    }

    pub fn set_codehash_map(&mut self, map: MetadataToCodehash) {
        self.coverage_inspector.set_codehash_map(map);
    }

    pub fn db(&self) -> &CacheDB<EmptyDB> {
        &self.db
    }

    pub fn db_mut(&mut self) -> &mut CacheDB<EmptyDB> {
        &mut self.db
    }

    pub fn get_nonce(&self, addr: Address) -> u64 {
        self.db.cache.accounts.get(&addr).map(|a| a.info.nonce).unwrap_or(0)
    }

    pub fn set_nonce(&mut self, addr: Address, nonce: u64) {
        let current = self.db.cache.accounts.get(&addr).map(|a| a.info.clone()).unwrap_or_default();
        let info = AccountInfo { nonce, ..current };
        self.db.insert_account_info(addr, info);
    }

    fn ensure_account_exists(&mut self, addr: Address) {
        let exists = self.db.cache.accounts.get(&addr).map(|a| !a.info.is_empty()).unwrap_or(false);
        if !exists {
            let funding = U256::MAX / U256::from(2);
            let info = AccountInfo { balance: funding, ..Default::default() };
            self.db.insert_account_info(addr, info);
        }
    }

    /// Deploy a contract. Returns ExecResult with deployed_address.
    pub fn deploy_contract(&mut self, deployer: Address, bytecode: Bytes) -> ExecResult {
        self.ensure_account_exists(deployer);
        self.coverage_inspector.reset_for_new_tx();

        let nonce = self.get_nonce(deployer);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);

        let mut tracer = create_tracing_inspector();

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
            })
            .modify_tx_chained(|tx| {
                tx.caller = deployer;
                tx.kind = TxKind::Create;
                tx.value = U256::ZERO;
                tx.data = bytecode;
                tx.gas_limit = MAX_GAS_PER_BLOCK;
                tx.nonce = nonce;
                tx.gas_price = 0;
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000;
            });

        let tx_env = ctx.tx.clone();

        let result_and_state = {
            let mut tuple_inspector = (
                &mut tracer,
                (&mut self.cheatcode_inspector, &mut self.coverage_inspector),
            );
            let mut evm = ctx.build_mainnet_with_inspector(&mut tuple_inspector);
            evm.inspect_tx(tx_env)
        };

        match result_and_state {
            Ok(ras) => {
                crate::evm::coverage::merge_deployment_coverage(
                    &mut self.init_coverage,
                    &self.coverage_inspector.touched,
                );

                let is_success = ras.result.is_success();
                let state_changes = self.extract_state_diffs(&ras.state, is_success);
                let result = self.build_exec_result(&ras.result, tracer, state_changes);
                self.db.commit(ras.state);
                self.apply_cheatcode_side_effects();
                result
            }
            Err(e) => ExecResult {
                success: false,
                gas_used: 0,
                output: Vec::new(),
                deployed_address: None,
                error: Some(format!("{e:?}")),
                arena: tracer.into_traces(),
                raw_logs: Vec::new(),
                state_changes: Vec::new(),
            },
        }
    }

    /// Deploy a contract at a specific address.
    pub fn deploy_contract_at(
        &mut self,
        deployer: Address,
        target_addr: Address,
        bytecode: Bytes,
        value: U256,
    ) -> ExecResult {
        self.ensure_account_exists(deployer);
        self.coverage_inspector.reset_for_new_tx();

        let init_bytecode = revm::bytecode::Bytecode::new_raw(bytecode.clone());
        let init_code_hash = init_bytecode.hash_slow();

        let target_info = revm::state::AccountInfo {
            balance: value,
            nonce: 1,
            code_hash: init_code_hash,
            code: Some(init_bytecode),
            ..Default::default()
        };
        self.db.insert_account_info(target_addr, target_info);

        let nonce = self.get_nonce(deployer);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);

        let mut tracer = create_tracing_inspector();

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
            })
            .modify_tx_chained(|tx| {
                tx.caller = deployer;
                tx.kind = TxKind::Call(target_addr);
                tx.value = U256::ZERO;
                tx.data = Bytes::new();
                tx.gas_limit = MAX_GAS_PER_BLOCK;
                tx.nonce = nonce;
                tx.gas_price = 0;
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000;
            });

        let tx_env = ctx.tx.clone();

        let result_and_state = {
            let mut tuple_inspector = (
                &mut tracer,
                (&mut self.cheatcode_inspector, &mut self.coverage_inspector),
            );
            let mut evm = ctx.build_mainnet_with_inspector(&mut tuple_inspector);
            evm.inspect_tx(tx_env)
        };

        match result_and_state {
            Ok(ras) => {
                crate::evm::coverage::merge_deployment_coverage(
                    &mut self.init_coverage,
                    &self.coverage_inspector.touched,
                );

                let is_success = ras.result.is_success();
                let state_changes = self.extract_state_diffs(&ras.state, is_success);

                match &ras.result {
                    ExecutionResult::Success { output: Output::Call(runtime_code), .. } => {
                        self.db.commit(ras.state);
                        self.apply_cheatcode_side_effects();

                        let runtime_bytecode = revm::bytecode::Bytecode::new_raw(runtime_code.clone());
                        let runtime_code_hash = runtime_bytecode.hash_slow();

                        if let Some(account) = self.db.cache.accounts.get_mut(&target_addr) {
                            account.info.code_hash = runtime_code_hash;
                            account.info.code = Some(runtime_bytecode);
                        }

                        ExecResult {
                            success: true,
                            gas_used: 0,
                            output: Vec::new(),
                            deployed_address: Some(target_addr),
                            error: None,
                            arena: tracer.into_traces(),
                            raw_logs: Vec::new(),
                            state_changes,
                        }
                    }
                    _ => {
                        let result = self.build_exec_result(&ras.result, tracer, state_changes);
                        self.db.commit(ras.state);
                        self.apply_cheatcode_side_effects();
                        result
                    }
                }
            }
            Err(e) => ExecResult {
                success: false,
                gas_used: 0,
                output: Vec::new(),
                deployed_address: None,
                error: Some(format!("{e:?}")),
                arena: tracer.into_traces(),
                raw_logs: Vec::new(),
                state_changes: Vec::new(),
            },
        }
    }

    /// Execute a call WITH coverage tracking, merging PCs into init_coverage.
    /// Used for setUp().
    pub fn exec_tx_with_revm_tracing(
        &mut self,
        from: Address,
        to: Address,
        calldata: Bytes,
        value: U256,
    ) -> ExecResult {
        self.last_calldata = calldata.to_vec();
        self.last_call_target = Some(to);
        self.ensure_account_exists(from);

        let nonce = self.get_nonce(from);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);

        let tracing_config = revm_inspectors::tracing::TracingInspectorConfig::default_parity()
            .with_state_diffs()
            .record_logs();
        let mut inspector = crate::evm::coverage::TracingWithCheatcodes::new(tracing_config);

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
            })
            .modify_tx_chained(|tx| {
                tx.caller = from;
                tx.kind = TxKind::Call(to);
                tx.value = value;
                tx.data = calldata;
                tx.gas_limit = MAX_GAS_PER_BLOCK;
                tx.nonce = nonce;
                tx.gas_price = 0;
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000;
            });

        let tx_env = ctx.tx.clone();

        let result_and_state = {
            let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
            evm.inspect_tx(tx_env)
        };

        match result_and_state {
            Ok(ras) => {
                self.last_result = Some(ras.result.clone());
                // Extract logs from arena nodes
                self.last_logs = inspector.tracing.traces().nodes().iter()
                    .flat_map(|node| node.logs.iter().map(|l| {
                        Log::new(node.trace.address, l.raw_log.topics().to_vec(), l.raw_log.data.clone())
                            .unwrap_or_else(|| Log::new_unchecked(node.trace.address, vec![], l.raw_log.data.clone()))
                    }))
                    .collect();

                crate::evm::coverage::merge_setup_coverage(
                    &mut self.init_coverage,
                    &inspector.pcs_hit,
                );

                let is_success = ras.result.is_success();
                let state_changes = self.extract_state_diffs(&ras.state, is_success);

                // Extract cheatcode state before consuming inspector
                let warp_timestamp = inspector.cheatcode.state.warp_timestamp;
                let roll_block = inspector.cheatcode.state.roll_block;
                let labels: Vec<_> = inspector.cheatcode.state.labels.drain().collect();

                // Build ExecResult using the revm TracingInspector (produces proper arena)
                let result = self.build_exec_result(&ras.result, inspector.tracing, state_changes);

                self.db.commit(ras.state);

                if let Some(warped) = warp_timestamp {
                    self.timestamp = warped.saturating_to();
                }
                if let Some(rolled) = roll_block {
                    self.block_number = rolled.saturating_to();
                }
                for (addr, label) in labels {
                    self.labels.insert(addr, label);
                }

                result
            }
            Err(e) => {
                self.last_result = None;
                self.last_logs.clear();
                ExecResult {
                    success: false,
                    gas_used: 0,
                    output: Vec::new(),
                    deployed_address: None,
                    error: Some(format!("{e:?}")),
                    arena: inspector.tracing.into_traces(),
                    raw_logs: Vec::new(),
                    state_changes: Vec::new(),
                }
            }
        }
    }

    /// Execute a call WITHOUT coverage tracking. Returns ExecResult.
    pub fn exec_tx(
        &mut self,
        from: Address,
        to: Address,
        calldata: Bytes,
        value: U256,
    ) -> ExecResult {
        self.last_calldata = calldata.to_vec();
        self.last_call_target = Some(to);
        self.ensure_account_exists(from);

        let nonce = self.get_nonce(from);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);

        let mut tracer = create_tracing_inspector();

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
            })
            .modify_tx_chained(|tx| {
                tx.caller = from;
                tx.kind = TxKind::Call(to);
                tx.value = value;
                tx.data = calldata;
                tx.gas_limit = MAX_GAS_PER_BLOCK;
                tx.nonce = nonce;
                tx.gas_price = 0;
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000;
            });

        let tx_env = ctx.tx.clone();

        let result_and_state = {
            let mut tuple_inspector = (&mut tracer, &mut self.cheatcode_inspector);
            let mut evm = ctx.build_mainnet_with_inspector(&mut tuple_inspector);
            evm.inspect_tx(tx_env)
        };

        match result_and_state {
            Ok(ras) => {
                self.last_result = Some(ras.result.clone());
                // Extract raw logs from arena
                self.last_logs = tracer.traces().nodes().iter()
                    .flat_map(|node| node.logs.iter().map(|l| {
                        Log::new(node.trace.address, l.raw_log.topics().to_vec(), l.raw_log.data.clone())
                            .unwrap_or_else(|| Log::new_unchecked(node.trace.address, vec![], l.raw_log.data.clone()))
                    }))
                    .collect();

                let is_success = ras.result.is_success();
                let state_changes = self.extract_state_diffs(&ras.state, is_success);
                let result = self.build_exec_result(&ras.result, tracer, state_changes);
                self.db.commit(ras.state);
                self.apply_cheatcode_side_effects();
                result
            }
            Err(e) => {
                self.last_result = None;
                self.last_logs.clear();
                ExecResult {
                    success: false,
                    gas_used: 0,
                    output: Vec::new(),
                    deployed_address: None,
                    error: Some(format!("{e:?}")),
                    arena: tracer.into_traces(),
                    raw_logs: Vec::new(),
                    state_changes: Vec::new(),
                }
            }
        }
    }

    /// Execute a call WITH coverage tracking.
    /// Returns (ExecResult, has_new_coverage).
    pub fn exec_tx_check_new_cov(
        &mut self,
        from: Address,
        to: Address,
        calldata: Bytes,
        value: U256,
    ) -> (ExecResult, bool) {
        self.last_calldata = calldata.to_vec();
        self.last_call_target = Some(to);
        self.ensure_account_exists(from);
        self.coverage_inspector.reset_for_new_tx();

        let nonce = self.get_nonce(from);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);

        let mut tracer = create_tracing_inspector();

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
            })
            .modify_tx_chained(|tx| {
                tx.caller = from;
                tx.kind = TxKind::Call(to);
                tx.value = value;
                tx.data = calldata;
                tx.gas_limit = MAX_GAS_PER_BLOCK;
                tx.nonce = nonce;
                tx.gas_price = 0;
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000;
            });

        let tx_env = ctx.tx.clone();

        let result_and_state = {
            let mut tuple_inspector = (
                &mut tracer,
                (&mut self.cheatcode_inspector, &mut self.coverage_inspector),
            );
            let mut evm = ctx.build_mainnet_with_inspector(&mut tuple_inspector);
            evm.inspect_tx(tx_env)
        };

        match result_and_state {
            Ok(ras) => {
                self.last_result = Some(ras.result.clone());
                self.last_logs = tracer.traces().nodes().iter()
                    .flat_map(|node| node.logs.iter().map(|l| {
                        Log::new(node.trace.address, l.raw_log.topics().to_vec(), l.raw_log.data.clone())
                            .unwrap_or_else(|| Log::new_unchecked(node.trace.address, vec![], l.raw_log.data.clone()))
                    }))
                    .collect();

                let tx_result = match &ras.result {
                    ExecutionResult::Success { .. } => TxResult::Success,
                    ExecutionResult::Revert { .. } => TxResult::Revert,
                    ExecutionResult::Halt { .. } => TxResult::Halt,
                };

                let has_new_coverage = check_and_merge_coverage(
                    &mut self.coverage,
                    &self.coverage_inspector.touched,
                    tx_result,
                );

                let is_success = ras.result.is_success();
                let state_changes = self.extract_state_diffs(&ras.state, is_success);
                let result = self.build_exec_result(&ras.result, tracer, state_changes);
                self.db.commit(ras.state);
                self.apply_cheatcode_side_effects();
                (result, has_new_coverage)
            }
            Err(e) => {
                self.last_result = None;
                self.last_logs.clear();
                (
                    ExecResult {
                        success: false,
                        gas_used: 0,
                        output: Vec::new(),
                        deployed_address: None,
                        error: Some(format!("{e:?}")),
                        arena: tracer.into_traces(),
                        raw_logs: Vec::new(),
                        state_changes: Vec::new(),
                    },
                    false,
                )
            }
        }
    }

    pub fn get_last_output(&self) -> Vec<u8> {
        match &self.last_result {
            Some(ExecutionResult::Success { output, .. }) => match output {
                Output::Call(bytes) => bytes.to_vec(),
                Output::Create(bytes, _) => bytes.to_vec(),
            },
            Some(ExecutionResult::Revert { output, .. }) => output.to_vec(),
            _ => Vec::new(),
        }
    }

    pub fn get_last_logs(&self) -> &[Log] {
        &self.last_logs
    }

    pub fn get_last_calldata(&self) -> &[u8] {
        &self.last_calldata
    }

    pub fn get_last_call_target(&self) -> Option<Address> {
        self.last_call_target
    }

    pub fn apply_delay(&mut self, delay: (u64, u64)) {
        self.timestamp = self.timestamp.saturating_add(delay.0);
        self.block_number = self.block_number.saturating_add(delay.1);
    }

    pub fn assume_rejected(&mut self) -> bool {
        let rejected = self.cheatcode_inspector.state.assume_failed;
        self.cheatcode_inspector.state.assume_failed = false;
        rejected
    }

    pub fn set_balance(&mut self, addr: Address, balance: U256) {
        let current = self.db.cache.accounts.get(&addr).map(|a| a.info.clone()).unwrap_or_default();
        let info = AccountInfo { balance, ..current };
        self.db.insert_account_info(addr, info);
    }

    pub fn set_code(&mut self, addr: Address, code: Bytes) {
        let bytecode = Bytecode::new_raw(code);
        let code_hash = bytecode.hash_slow();
        let current = self.db.cache.accounts.get(&addr).map(|a| a.info.clone()).unwrap_or_default();
        let info = AccountInfo {
            code_hash,
            code: Some(bytecode),
            nonce: if current.nonce == 0 { 1 } else { current.nonce },
            balance: current.balance,
            ..Default::default()
        };
        self.db.insert_account_info(addr, info);
    }

    pub fn get_storage(&self, addr: Address, slot: U256) -> U256 {
        self.db.cache.accounts.get(&addr)
            .and_then(|a| a.storage.get(&slot))
            .copied()
            .unwrap_or(U256::ZERO)
    }

    pub fn set_storage(&mut self, addr: Address, slot: U256, value: U256) {
        let account = self.db.cache.accounts.entry(addr).or_default();
        account.storage.insert(slot, value);
    }

    pub fn snapshot(&mut self) -> u32 {
        let id = self.next_snapshot_id;
        self.next_snapshot_id += 1;
        self.snapshots.insert(id, (self.db.clone(), self.block_number, self.timestamp));
        id
    }

    pub fn revert_to(&mut self, id: u32) -> bool {
        if let Some((db, block, ts)) = self.snapshots.get(&id) {
            self.db = db.clone();
            self.block_number = *block;
            self.timestamp = *ts;
            true
        } else {
            false
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    fn apply_cheatcode_side_effects(&mut self) {
        if let Some(ts) = self.cheatcode_inspector.state.warp_timestamp {
            self.timestamp = ts.saturating_to();
        }
        if let Some(bn) = self.cheatcode_inspector.state.roll_block {
            self.block_number = bn.saturating_to();
        }
        let deals: Vec<_> = self.cheatcode_inspector.state.deals.drain().collect();
        for (addr, balance) in deals {
            self.set_balance(addr, balance);
        }
        let etches: Vec<_> = self.cheatcode_inspector.state.etches.drain().collect();
        for (addr, code) in etches {
            self.set_code(addr, code);
        }
        let stores: Vec<_> = self.cheatcode_inspector.state.stores.drain(..).collect();
        for (addr, slot, value) in stores {
            self.set_storage(addr, slot.into(), value.into());
        }
        let labels: Vec<_> = self.cheatcode_inspector.state.labels.drain().collect();
        for (addr, label) in labels {
            self.labels.insert(addr, label);
        }
    }

    fn extract_state_diffs(
        &mut self,
        state: &revm::state::EvmState,
        is_success: bool,
    ) -> Vec<StateChange> {
        self.last_state_diff.clear();
        self.last_created_addresses.clear();

        if !is_success {
            return Vec::new();
        }

        let mut changes = Vec::new();
        for (addr, account) in state {
            if account.is_created() && account.info.code_hash != alloy_primitives::KECCAK256_EMPTY {
                self.last_created_addresses.push(*addr);
            }
            for (slot, slot_value) in &account.storage {
                let old_value = slot_value.original_value();
                let new_value = slot_value.present_value();
                if old_value != new_value {
                    self.last_state_diff.insert((*addr, *slot), (old_value, new_value));
                    changes.push(StateChange {
                        address: format!("{addr:?}"),
                        slot: format!("{slot:#066x}"),
                        old_value: format!("{old_value:#066x}"),
                        new_value: format!("{new_value:#066x}"),
                    });
                }
            }
        }
        changes
    }

    pub fn get_last_state_diff(&self) -> Vec<(Address, U256, U256, U256)> {
        self.last_state_diff.iter()
            .map(|((addr, slot), (old, new))| (*addr, *slot, *old, *new))
            .collect()
    }

    pub fn get_last_created_addresses(&self) -> &[Address] {
        &self.last_created_addresses
    }

    fn build_exec_result(
        &self,
        exec_result: &ExecutionResult,
        tracer: revm_inspectors::tracing::TracingInspector,
        state_changes: Vec<StateChange>,
    ) -> ExecResult {
        let (success, gas_used, output_bytes, deployed_address) = match exec_result {
            ExecutionResult::Success { gas_used, output, .. } => {
                let (bytes, deployed) = match output {
                    Output::Create(bytes, addr) => (bytes.clone(), *addr),
                    Output::Call(bytes) => (bytes.clone(), None),
                };
                (true, *gas_used, bytes, deployed)
            }
            ExecutionResult::Revert { gas_used, output } => {
                (false, *gas_used, output.clone(), None)
            }
            ExecutionResult::Halt { gas_used, .. } => (false, *gas_used, Bytes::new(), None),
        };

        // Extract raw logs from arena before consuming the inspector
        let raw_logs: Vec<Log> = tracer.traces().nodes().iter()
            .flat_map(|node| node.logs.iter().map(|l| {
                Log::new(node.trace.address, l.raw_log.topics().to_vec(), l.raw_log.data.clone())
                    .unwrap_or_else(|| Log::new_unchecked(node.trace.address, vec![], l.raw_log.data.clone()))
            }))
            .collect();

        ExecResult {
            success,
            gas_used,
            output: output_bytes.to_vec(),
            deployed_address,
            error: if success { None } else { Some(format!("revert: 0x{}", hex::encode(&output_bytes))) },
            arena: tracer.into_traces(),
            raw_logs,
            state_changes,
        }
    }

}
