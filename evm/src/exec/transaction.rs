//! Transaction execution methods for EvmState
//!
//! Contains all exec_tx* variants and deployment functions.

use alloy_primitives::{Address, Bytes, TxKind, U256};
use revm::bytecode::Bytecode;
use revm::context_interface::result::{ExecutionResult, Output};
use revm::state::AccountInfo;
use revm::{Context, Database, DatabaseCommit, InspectEvm, MainBuilder, MainContext};
use std::collections::HashMap;

use crate::types::{Tx, TxCall, TxResult};

use super::helpers::{classify_execution_result, encode_call};
use super::{CoverageMap, EvmState, ExecError};

impl EvmState {
    /// Deploy a contract at a specific address with coverage tracking AND trace capture
    /// This runs the constructor DIRECTLY at the target address so that address(this)
    /// returns the correct value during constructor execution.
    ///
    /// Uses triple inspector (CheatcodeInspector, DeploymentPcCounter, TracingInspector) to:
    /// - Handle cheatcodes correctly (CheatcodeInspector)
    /// - Track coverage during constructor (DeploymentPcCounter)
    /// - Capture call traces for dictionary extraction (TracingInspector)
    ///
    /// The approach:
    /// 1. Create an account at target_addr with init code
    /// 2. Execute init code as a CALL (not CREATE) so address(this) == target_addr
    /// 3. Track coverage using DeploymentPcCounter
    /// 4. Capture traces for extracting dictionary values from constructor calls
    /// 5. Replace init code with the returned runtime code
    ///
    /// Returns: (deployed_address, call_traces) - traces can be used to extract dictionary values
    pub fn deploy_contract_at(
        &mut self,
        deployer: Address,
        target_addr: Address,
        bytecode: Bytes,
        value: U256,
        coverage_ref: &std::sync::Arc<parking_lot::RwLock<CoverageMap>>,
        codehash_map: &std::sync::Arc<parking_lot::RwLock<crate::coverage::MetadataToCodehash>>,
    ) -> Result<(Address, revm_inspectors::tracing::CallTraceArena), ExecError> {
        use revm_inspectors::tracing::{
            TracingInspector as RevmTracingInspector, TracingInspectorConfig,
        };
        tracing::info!(
            "deploy_contract_at: target={:?}, gas_limit={}, bytecode_len={}",
            target_addr,
            self.gas_limit,
            bytecode.len()
        );

        let gas_limit = self.gas_limit;
        let block_number = self.block_number;
        let timestamp = self.timestamp;

        // Step 1: Create an account at target_addr with the init code as its "runtime" code
        // This is a hack - we temporarily set the init code as the contract's code
        // so that when we CALL it, the init code runs with address(this) == target_addr
        let init_bytecode = Bytecode::new_raw(bytecode.clone());
        let init_code_hash = init_bytecode.hash_slow();

        let target_info = AccountInfo {
            balance: value,
            nonce: 1, // Contracts start with nonce 1
            code_hash: init_code_hash,
            code: Some(init_bytecode),
            account_id: Default::default(),
        };
        self.db.insert_account_info(target_addr, target_info);

        // Get nonce AFTER inserting target account info
        // This handles the case where deployer == target_addr:
        // - If they're the same address, nonce will be 1 (from the AccountInfo we just inserted)
        // - If they're different, nonce will be the deployer's actual nonce
        let nonce = self.get_nonce(deployer);

        // Step 2: Execute the init code via CALL to target_addr
        // Use nested tuple inspector: ((CheatcodeInspector, DeploymentPcCounter), TracingInspector)
        // - CheatcodeInspector handles all cheatcodes (vm.addr, vm.prank, etc.)
        // - DeploymentPcCounter tracks coverage without touching cheatcode handling
        // - TracingInspector captures call traces for dictionary extraction
        let mut cheatcode_inspector = crate::cheatcodes::CheatcodeInspector::new();
        let mut pc_counter = crate::coverage::DeploymentPcCounter::new(codehash_map.clone());
        let tracing_config = TracingInspectorConfig::default_parity()
            .with_state_diffs();
        let mut tracing_inspector = RevmTracingInspector::new(tracing_config);

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
                cfg.tx_gas_limit_cap = Some(u64::MAX);
            })
            .modify_tx_chained(|tx_env| {
                tx_env.caller = deployer;
                tx_env.kind = TxKind::Call(target_addr); // CALL, not CREATE
                tx_env.value = U256::ZERO; // Value already set on account
                tx_env.data = Bytes::new(); // No calldata - init code runs directly
                tx_env.gas_limit = gas_limit;
                tx_env.nonce = nonce;
                tx_env.gas_price = 0;
            })
            .modify_block_chained(|block| {
                block.number = U256::from(block_number);
                block.timestamp = U256::from(timestamp);
                block.gas_limit = gas_limit;
            });

        let tx_env = ctx.tx.clone();

        // Use nested tuple inspector - REVM supports pairs, so we nest: (Tracing, (Cheat, PC))
        // TracingInspector MUST be first to receive call notifications before CheatcodeInspector
        // can intercept them (CheatcodeInspector returns Some for HEVM calls, breaking trace chain)
        let result_and_state = {
            let mut inner_pair = (&mut cheatcode_inspector, &mut pc_counter);
            let mut tuple_inspector = (&mut tracing_inspector, &mut inner_pair);
            let mut evm = ctx.build_mainnet_with_inspector(&mut tuple_inspector);
            evm.inspect_tx(tx_env)
                .map_err(|e| ExecError::EvmError(format!("Deploy error: {:?}", e)))?
        };

        let execution_result = result_and_state.result;
        tracing::debug!("Constructor execution result: {:?}", execution_result);

        // Commit state changes from constructor
        self.db.commit(result_and_state.state);

        // Persist vm.warp/vm.roll effects (Foundry parity)
        if let Some(warped) = cheatcode_inspector.state.warp_timestamp {
            self.timestamp = warped.saturating_to();
        }
        if let Some(rolled) = cheatcode_inspector.state.roll_block {
            self.block_number = rolled.saturating_to();
        }

        // Extract labels from cheatcode inspector and store in vm state
        for (addr, label) in cheatcode_inspector.state.labels.drain() {
            self.labels.insert(addr, label);
        }

        // Step 3: Merge constructor coverage into the coverage map
        if !pc_counter.touched.is_empty() {
            let mut coverage = coverage_ref.write();
            for &(codehash, pc, depth) in &pc_counter.touched {
                let contract_cov = coverage.entry(codehash).or_insert_with(HashMap::new);
                let depth_bit = if depth < 64 { 1u64 << depth } else { 1u64 << 63 };
                let entry = contract_cov.entry(pc).or_insert((0, 0));
                entry.0 |= depth_bit;
                // Constructor is a successful execution (result bit 0)
                entry.1 |= 1;
            }
            tracing::debug!("Deployment coverage: {} PCs tracked", pc_counter.touched.len());
        }

        // Step 4: Extract runtime code from the return value
        let runtime_code = match &execution_result {
            ExecutionResult::Success {
                output: Output::Call(code),
                gas_used,
                ..
            } => {
                tracing::info!(
                    "Constructor succeeded, gas_used={}, runtime_code_len={}",
                    gas_used,
                    code.len()
                );
                code.clone()
            }
            ExecutionResult::Revert { output, gas_used } => {
                eprintln!("\n=== Constructor Revert - Running with traces ===");
                if let Ok(mut traces) = self.deploy_contract_at_with_tracing(
                    deployer,
                    target_addr,
                    bytecode.clone(),
                    value,
                ) {
                    self.print_deployment_traces(&mut traces);
                }
                return Err(ExecError::EvmError(format!(
                    "Constructor reverted: gas_used={}, output=0x{}",
                    gas_used,
                    hex::encode(output)
                )));
            }
            other => {
                return Err(ExecError::EvmError(format!(
                    "Constructor failed: {:?}",
                    other
                )));
            }
        };

        // Step 5: Replace init code with runtime code at target address
        let runtime_bytecode = Bytecode::new_raw(runtime_code);
        let runtime_code_hash = runtime_bytecode.hash_slow();

        if let Some(account) = self.db.get_cached_account_mut(&target_addr) {
            account.info.code_hash = runtime_code_hash;
            account.info.code = Some(runtime_bytecode);
        }

        // Return address and traces for dictionary extraction
        let traces = tracing_inspector.into_traces();
        Ok((target_addr, traces))
    }

    /// Deploy a contract at a specific address with full tracing
    /// Used when deployment fails to get detailed traces for debugging
    pub fn deploy_contract_at_with_tracing(
        &mut self,
        deployer: Address,
        target_addr: Address,
        bytecode: Bytes,
        value: U256,
    ) -> Result<revm_inspectors::tracing::CallTraceArena, ExecError> {
        use revm_inspectors::tracing::{
            TracingInspector as RevmTracingInspector, TracingInspectorConfig,
        };

        let gas_limit = self.gas_limit;
        let block_number = self.block_number;
        let timestamp = self.timestamp;

        // Set up the target account with init code (already done in main deploy)
        let init_bytecode = Bytecode::new_raw(bytecode);
        let init_code_hash = init_bytecode.hash_slow();

        let target_info = AccountInfo {
            balance: value,
            nonce: 1,
            code_hash: init_code_hash,
            code: Some(init_bytecode),
            account_id: Default::default(),
        };
        self.db.insert_account_info(target_addr, target_info);

        // Get nonce AFTER inserting target account info (handles deployer == target_addr case)
        let nonce = self.get_nonce(deployer);

        // Create TracingInspector with full config
        let tracing_config = TracingInspectorConfig::default_parity().with_state_diffs();
        let mut inspector = RevmTracingInspector::new(tracing_config);

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
                cfg.tx_gas_limit_cap = Some(u64::MAX);
            })
            .modify_tx_chained(|tx_env| {
                tx_env.caller = deployer;
                tx_env.kind = TxKind::Call(target_addr);
                tx_env.value = U256::ZERO;
                tx_env.data = Bytes::new();
                tx_env.gas_limit = gas_limit;
                tx_env.nonce = nonce;
                tx_env.gas_price = 0;
            })
            .modify_block_chained(|block| {
                block.number = U256::from(block_number);
                block.timestamp = U256::from(timestamp);
                block.gas_limit = gas_limit;
            });

        let tx_env = ctx.tx.clone();

        let _result_and_state = {
            let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
            evm.inspect_tx(tx_env)
                .map_err(|e| ExecError::EvmError(format!("Tracing deploy error: {:?}", e)))?
        };

        // Return the traces
        Ok(inspector.into_traces())
    }

    /// Print deployment traces in a human-readable format
    /// Note: For richer output with contract names, use campaign::output::print_deployment_traces
    pub fn print_deployment_traces(
        &mut self,
        traces: &mut revm_inspectors::tracing::CallTraceArena,
    ) {
        use crate::tracing::{format_traces_decoded_with_state, TraceDecoder};
        use std::io::Write;

        eprintln!("\nDeployment Call Trace:");
        eprintln!("=======================");

        // Create a trace decoder - it will resolve addresses from state
        let mut decoder = TraceDecoder::new();

        // Format traces with the decoder, resolving addresses from VM state
        let trace_output =
            format_traces_decoded_with_state(traces, &mut decoder, &mut self.db, true);

        if !trace_output.is_empty() {
            for line in trace_output.lines() {
                eprintln!("  {}", line);
            }
        }

        eprintln!("=======================\n");
        let _ = std::io::stderr().flush();
    }

    /// Deploy a contract and return its address
    pub fn deploy_contract(
        &mut self,
        deployer: Address,
        bytecode: Bytes,
        _value: U256,
    ) -> Result<Address, ExecError> {
        // Calculate deployment address using nonce
        let nonce = self.get_nonce(deployer);
        let contract_addr = deployer.create(nonce);

        // Set the contract code directly (simplified deployment)
        self.set_code(contract_addr, bytecode);

        // Increment deployer nonce
        self.increment_nonce(deployer);

        Ok(contract_addr)
    }

    /// Execute a transaction
    pub fn exec_tx(&mut self, tx: &Tx) -> Result<TxResult, ExecError> {
        // Ensure sender account exists in the database to prevent REVM panic
        self.ensure_account_exists(tx.src);

        // Capture state before execution for potential rollback 
        let initial_block = self.block_number;
        let initial_timestamp = self.timestamp;

        // Apply time/block delay
        self.timestamp += tx.delay.0;
        self.block_number += tx.delay.1;

        // Handle NoCall (just delay, no actual execution)
        if matches!(tx.call, TxCall::NoCall) {
            self.last_result = None;
            self.last_calldata = Bytes::new();
            self.last_call_target = None;
            return Ok(TxResult::Stop);
        }

        // Encode calldata based on call type
        let (calldata, is_create) = match &tx.call {
            TxCall::SolCall { name, args } => (encode_call(name, args)?, false),
            TxCall::SolCalldata(data) => (data.clone(), false),
            TxCall::SolCreate(code) => (code.clone(), true),
            TxCall::NoCall => (Bytes::new(), false),
        };

        // Record calldata and target for assertion test precision 
        self.last_calldata = calldata.clone();
        self.last_call_target = if is_create { None } else { Some(tx.dst) };

        // Determine transaction kind
        let kind = if is_create {
            TxKind::Create
        } else {
            TxKind::Call(tx.dst)
        };

        // Pre-compute values that need self access
        let nonce = self.get_nonce(tx.src);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);
        let caller = tx.src;
        let value = tx.value;
        let gas_limit = tx.gas;

        // Use cheatcode inspector to handle HEVM calls
        let mut inspector = crate::cheatcodes::CheatcodeInspector::new();

        // Use REVM's MainBuilder to create and execute with inspector
        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX); // Unlimited contract size
                cfg.limit_contract_initcode_size = Some(usize::MAX); // Unlimited init code size
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true; // Allow txs from accounts with code
                cfg.disable_base_fee = true; // Allow zero gas price
            })
            .modify_tx_chained(|tx_env| {
                tx_env.caller = caller;
                tx_env.kind = kind;
                tx_env.value = value;
                tx_env.data = calldata;
                tx_env.gas_limit = gas_limit;
                tx_env.nonce = nonce;
                tx_env.gas_price = tx.gasprice.saturating_to();
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000; // 1 trillion gas for large contracts
            });

        // Capture tx_env before building to pass to inspect_tx()
        let tx_env = ctx.tx.clone();

        // Execute with inspector to handle cheatcodes
        let result_and_state = {
            let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
            evm.inspect_tx(tx_env)
                .map_err(|e| ExecError::EvmError(format!("{:?}", e)))?
        };

        let execution_result = result_and_state.result;
        let tx_result = classify_execution_result(&execution_result);

        // Handle result and persistence
        if tx_result.is_revert() || tx_result.is_error() {
            // Revert: Rollback state changes (do not commit)
            // And restore modified environment (timestamp/block)
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;

            // Note: We purposefully do NOT commit `result_and_state.state` here,
            // effectively rolling back nonce, balances, storage, etc.
            // However, we MUST update `last_result` for checking asserts
            self.last_result = Some(execution_result);
        } else {
            // Success: Commit state changes to DB
            self.db.commit(result_and_state.state);

            // Persist vm.warp/vm.roll effects (Foundry parity)
            // These cheatcodes should persist across transactions
            if let Some(warped) = inspector.state.warp_timestamp {
                self.timestamp = warped.saturating_to();
            }
            if let Some(rolled) = inspector.state.roll_block {
                self.block_number = rolled.saturating_to();
            }

            self.last_result = Some(execution_result);
        }

        Ok(tx_result)
    }

    /// Execute a transaction and track coverage
    pub fn exec_tx_with_cov(
        &mut self,
        tx: &Tx,
        coverage: &mut CoverageMap,
    ) -> Result<(TxResult, bool), ExecError> {
        // Ensure sender account exists in the database to prevent REVM panic
        self.ensure_account_exists(tx.src);

        // Get initial coverage size (number of unique PC hits)
        let initial_coverage_size: usize = coverage.values().map(|v| v.len()).sum();

        // 1. Setup context (similar to exec_tx but we need inspector)
        let initial_block = self.block_number;
        let initial_timestamp = self.timestamp;

        self.timestamp += tx.delay.0;
        self.block_number += tx.delay.1;

        if matches!(tx.call, TxCall::NoCall) {
            self.last_result = None;
            self.last_calldata = Bytes::new();
            self.last_call_target = None;
            return Ok((TxResult::Stop, false));
        }

        let (calldata, is_create) = match &tx.call {
            TxCall::SolCall { name, args } => (encode_call(name, args)?, false),
            TxCall::SolCalldata(data) => (data.clone(), false),
            TxCall::SolCreate(code) => (code.clone(), true),
            TxCall::NoCall => (Bytes::new(), false),
        };

        // Record calldata and target for assertion test precision 
        self.last_calldata = calldata.clone();
        self.last_call_target = if is_create { None } else { Some(tx.dst) };

        let kind = if is_create {
            TxKind::Create
        } else {
            TxKind::Call(tx.dst)
        };

        let nonce = self.get_nonce(tx.src);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);
        let caller = tx.src;
        let value = tx.value;
        let gas_limit = tx.gas;

        // Debug log target
        if let TxKind::Call(addr) = kind {
            let code_exists = match self.db.basic(addr) {
                Ok(Some(info)) => !info.is_empty(),
                _ => false,
            };
            tracing::debug!("Exec tx to {:?}, code exists: {}", addr, code_exists);
        }

        // 2. Build EVM with Combined Inspector (coverage + cheatcodes)
        let mut inspector = crate::coverage::CombinedInspector::new();
        inspector.set_coverage_mode(self.coverage_mode);

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX); // Unlimited contract size
                cfg.limit_contract_initcode_size = Some(usize::MAX); // Unlimited init code size
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true; // Allow txs from accounts with code
                cfg.disable_base_fee = true; // Allow zero gas price
            })
            .modify_tx_chained(|tx_env| {
                tx_env.caller = caller;
                tx_env.kind = kind;
                tx_env.value = value;
                tx_env.data = calldata;
                tx_env.gas_limit = gas_limit;
                tx_env.nonce = nonce;
                tx_env.gas_price = tx.gasprice.saturating_to();
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000; // 1 trillion gas for large contracts
            });

        // Capture tx_env for parity (though strict manual capture not needed if inspector works)
        let tx_env = ctx.tx.clone();

        // Build with inspector
        let result_and_state = {
            let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
            evm.inspect_tx(tx_env)
                .map_err(|e| ExecError::EvmError(format!("{:?}", e)))?
        };

        let execution_result = result_and_state.result;
        let tx_result = classify_execution_result(&execution_result);
        tracing::debug!("Tx result: {:?}", tx_result);

        // Check if assume() failed - skip this transaction 
        if inspector.cheatcode_state().assume_failed {
            // Reset and treat as if tx didn't happen
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;
            self.last_result = None;
            return Ok((TxResult::Stop, false));
        }

        // 4. Handle State Commit (Same logic as exec_tx)
        if tx_result.is_revert() || tx_result.is_error() {
            if let Some(ExecutionResult::Revert { output, .. }) = &self.last_result {
                tracing::debug!("Revert output: {}", hex::encode(output));
            }
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;
            self.last_result = Some(execution_result);
        } else {
            self.db.commit(result_and_state.state);

            // Persist vm.warp/vm.roll effects (Foundry parity)
            if let Some(warped) = inspector.cheatcode_state().warp_timestamp {
                self.timestamp = warped.saturating_to();
            }
            if let Some(rolled) = inspector.cheatcode_state().roll_block {
                self.block_number = rolled.saturating_to();
            }

            self.last_result = Some(execution_result);
        }

        // 5. Update Coverage Map from Inspector
        let result_bit = 1 << tx_result.to_bit_index();

        for (addr, pc, stack_depth) in inspector.touched {
            let contract_cov = coverage.entry(addr).or_insert_with(HashMap::new);
            let entry = contract_cov.entry(pc).or_insert((0, 0));

            // Update stack depth bits
            let depth_bit = if stack_depth < 64 {
                1 << stack_depth
            } else {
                1 << 63
            };
            entry.0 |= depth_bit;

            // Update tx result bits
            entry.1 |= result_bit;
        }

        // Check if coverage grew
        let new_coverage_size: usize = coverage.values().map(|v| v.len()).sum();
        let coverage_grew = new_coverage_size > initial_coverage_size;

        Ok((tx_result, coverage_grew))
    }

    /// Execute a transaction and check for new coverage with minimal locking
    /// Takes a reference to RwLock<CoverageMap> and only locks briefly to merge
    /// This reduces lock contention for multi-threaded fuzzing
    pub fn exec_tx_check_new_cov(
        &mut self,
        tx: &Tx,
        coverage_ref: &std::sync::Arc<parking_lot::RwLock<CoverageMap>>,
        codehash_map: &std::sync::Arc<parking_lot::RwLock<crate::coverage::MetadataToCodehash>>,
    ) -> Result<(TxResult, bool), ExecError> {
        // Ensure sender account exists in the database to prevent REVM panic
        // This handles corpus transactions with unknown senders
        self.ensure_account_exists(tx.src);

        // 1. Setup context
        let initial_block = self.block_number;
        let initial_timestamp = self.timestamp;

        self.timestamp += tx.delay.0;
        self.block_number += tx.delay.1;

        if matches!(tx.call, TxCall::NoCall) {
            self.last_result = None;
            self.last_calldata = Bytes::new();
            self.last_call_target = None;
            return Ok((TxResult::Stop, false));
        }

        let (calldata, is_create) = match &tx.call {
            TxCall::SolCall { name, args } => (encode_call(name, args)?, false),
            TxCall::SolCalldata(data) => (data.clone(), false),
            TxCall::SolCreate(code) => (code.clone(), true),
            TxCall::NoCall => (Bytes::new(), false),
        };

        self.last_calldata = calldata.clone();
        self.last_call_target = if is_create { None } else { Some(tx.dst) };

        let kind = if is_create {
            TxKind::Create
        } else {
            TxKind::Call(tx.dst)
        };

        let nonce = self.get_nonce(tx.src);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);
        let caller = tx.src;
        let value = tx.value;
        let gas_limit = tx.gas;

        // 2. Build EVM with Combined Inspector
        let mut inspector =
            crate::coverage::CombinedInspector::with_codehash_map(codehash_map.clone());

        // Set context for vm.generateCalls() cheatcode (on-demand reentrancy testing)
        if let Some((fuzzable_funcs, gen_dict, rng_seed)) = &self.generate_calls_context {
            inspector.set_generate_calls_context(
                fuzzable_funcs.clone(),
                gen_dict.clone(),
                *rng_seed,
            );
        }

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX); // Unlimited contract size
                cfg.limit_contract_initcode_size = Some(usize::MAX); // Unlimited init code size
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true; // Allow txs from accounts with code
                cfg.disable_base_fee = true; // Allow zero gas price
            })
            .modify_tx_chained(|tx_env| {
                tx_env.caller = caller;
                tx_env.kind = kind;
                tx_env.value = value;
                tx_env.data = calldata;
                tx_env.gas_limit = gas_limit;
                tx_env.nonce = nonce;
                tx_env.gas_price = tx.gasprice.saturating_to();
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000; // 1 trillion gas for large contracts
            });

        let tx_env = ctx.tx.clone();

        let result_and_state = {
            let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
            evm.inspect_tx(tx_env)
                .map_err(|e| ExecError::EvmError(format!("{:?}", e)))?
        };

        // Capture created addresses from inspector (for dictionary enrichment)
        self.last_created_addresses = inspector.created_addresses.clone();

        let execution_result = result_and_state.result;
        let tx_result = classify_execution_result(&execution_result);

        // Check if assume() failed
        if inspector.cheatcode_state().assume_failed {
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;
            self.last_result = None;
            self.last_created_addresses.clear();
            return Ok((TxResult::Stop, false));
        }

        // Handle State Commit
        if tx_result.is_revert() || tx_result.is_error() {
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;
            self.last_result = Some(execution_result);
            self.last_created_addresses.clear();
            self.last_state_diff.clear(); // No state changes on revert
        } else {
            // Extract newly created addresses BEFORE committing state
            self.last_created_addresses.clear();
            self.last_state_diff.clear();

            for (addr, account) in &result_and_state.state {
                // Check if account was created in this transaction
                let has_code = account.info.code_hash != alloy_primitives::KECCAK256_EMPTY;
                if account.is_created() && has_code {
                    self.last_created_addresses.push(*addr);
                }

                // Capture storage changes for state diff display
                for (slot, slot_value) in &account.storage {
                    let old_value = slot_value.original_value();
                    let new_value = slot_value.present_value();
                    if old_value != new_value {
                        self.last_state_diff
                            .insert((*addr, *slot), (old_value, new_value));
                    }
                }
            }

            self.db.commit(result_and_state.state);

            // Persist vm.warp/vm.roll effects (Foundry parity)
            if let Some(warped) = inspector.cheatcode_state().warp_timestamp {
                self.timestamp = warped.saturating_to();
            }
            if let Some(rolled) = inspector.cheatcode_state().roll_block {
                self.block_number = rolled.saturating_to();
            }

            self.last_result = Some(execution_result);
        }

        // 3. Check for new coverage - ONLY take write lock if there's actually new coverage
        let result_bit = 1u64 << tx_result.to_bit_index();
        let mut has_new_coverage = false;

        if !inspector.touched.is_empty() {
            let len = inspector.touched.len();

            // First pass: check if any of our coverage might be new (with read lock)
            let might_have_new = {
                let coverage = coverage_ref.read();

                inspector
                    .touched
                    .iter()
                    .enumerate()
                    .any(|(idx, &(codehash, pc, stack_depth))| {
                        let depth_bit = if stack_depth < 64 {
                            1u64 << stack_depth
                        } else {
                            1u64 << 63
                        };

                        // Result bit ONLY checked for last PC 
                        let is_last_pc = idx == len - 1;

                        if let Some(contract_cov) = coverage.get(&codehash) {
                            if let Some(&(depths, results)) = contract_cov.get(&pc) {
                                let new_depth = (depths & depth_bit) == 0;
                                let new_result = is_last_pc && (results & result_bit) == 0;
                                new_depth || new_result
                            } else {
                                true // New PC = new coverage
                            }
                        } else {
                            true // New codehash = new coverage
                        }
                    })
            };

            // Second pass: ONLY if we might have new coverage, take write lock and merge
            if might_have_new {
                let mut coverage = coverage_ref.write();

                for (idx, &(codehash, pc, stack_depth)) in inspector.touched.iter().enumerate() {
                    let contract_cov = coverage.entry(codehash).or_insert_with(HashMap::new);

                    let depth_bit = if stack_depth < 64 {
                        1u64 << stack_depth
                    } else {
                        1u64 << 63
                    };

                    // Result bit ONLY applied to last PC 
                    let is_last_pc = idx == len - 1;

                    let entry = contract_cov.entry(pc).or_insert((0, 0));
                    let new_depth = (entry.0 & depth_bit) == 0;
                    let new_result = is_last_pc && (entry.1 & result_bit) == 0;

                    if new_depth || new_result {
                        has_new_coverage = true;
                    }

                    // Always update depth bit for all PCs
                    entry.0 |= depth_bit;
                    // Result bit ONLY for last PC
                    if is_last_pc {
                        entry.1 |= result_bit;
                    }
                }
            }
        }

        Ok((tx_result, has_new_coverage))
    }

    /// Execute a transaction and check if it WOULD find new coverage (READ-ONLY)
    ///
    /// Unlike `exec_tx_check_new_cov`, this does NOT update the shared coverage map.
    /// Use this for verification when you don't want to affect the main fuzzer's coverage tracking.
    ///
    /// Returns: (TxResult, would_find_new_coverage)
    pub fn exec_tx_check_new_cov_readonly(
        &mut self,
        tx: &Tx,
        coverage_ref: &std::sync::Arc<parking_lot::RwLock<CoverageMap>>,
        codehash_map: &std::sync::Arc<parking_lot::RwLock<crate::coverage::MetadataToCodehash>>,
    ) -> Result<(TxResult, bool), ExecError> {
        // Ensure sender account exists in the database
        self.ensure_account_exists(tx.src);

        // Setup context
        let initial_block = self.block_number;
        let initial_timestamp = self.timestamp;

        self.timestamp += tx.delay.0;
        self.block_number += tx.delay.1;

        if matches!(tx.call, TxCall::NoCall) {
            self.last_result = None;
            self.last_calldata = Bytes::new();
            self.last_call_target = None;
            return Ok((TxResult::Stop, false));
        }

        let (calldata, is_create) = match &tx.call {
            TxCall::SolCall { name, args } => (encode_call(name, args)?, false),
            TxCall::SolCalldata(data) => (data.clone(), false),
            TxCall::SolCreate(code) => (code.clone(), true),
            TxCall::NoCall => (Bytes::new(), false),
        };

        self.last_calldata = calldata.clone();
        self.last_call_target = if is_create { None } else { Some(tx.dst) };

        let kind = if is_create {
            TxKind::Create
        } else {
            TxKind::Call(tx.dst)
        };

        let nonce = self.get_nonce(tx.src);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);
        let caller = tx.src;
        let value = tx.value;
        let gas_limit = tx.gas;

        // Build EVM with inspector (simplified - no extra tracking)
        let mut inspector =
            crate::coverage::CombinedInspector::with_codehash_map(codehash_map.clone());

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
                cfg.tx_gas_limit_cap = Some(u64::MAX);
            })
            .modify_tx_chained(|tx_env| {
                tx_env.caller = caller;
                tx_env.kind = kind;
                tx_env.value = value;
                tx_env.data = calldata;
                tx_env.gas_limit = gas_limit;
                tx_env.nonce = nonce;
                tx_env.gas_price = tx.gasprice.saturating_to();
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
                .map_err(|e| ExecError::EvmError(format!("{:?}", e)))?
        };

        self.last_created_addresses = inspector.created_addresses.clone();
        let execution_result = result_and_state.result;
        let tx_result = classify_execution_result(&execution_result);

        // Check if assume() failed
        if inspector.cheatcode_state().assume_failed {
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;
            self.last_result = None;
            self.last_created_addresses.clear();
            return Ok((TxResult::Stop, false));
        }

        // Handle State Commit (we still need to update VM state for subsequent txs)
        if tx_result.is_revert() || tx_result.is_error() {
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;
            self.last_result = Some(execution_result);
            self.last_created_addresses.clear();
            self.last_state_diff.clear();
        } else {
            self.last_created_addresses.clear();
            self.last_state_diff.clear();

            for (addr, account) in &result_and_state.state {
                let has_code = account.info.code_hash != alloy_primitives::KECCAK256_EMPTY;
                if account.is_created() && has_code {
                    self.last_created_addresses.push(*addr);
                }

                for (slot, slot_value) in &account.storage {
                    let old_value = slot_value.original_value();
                    let new_value = slot_value.present_value();
                    if old_value != new_value {
                        self.last_state_diff
                            .insert((*addr, *slot), (old_value, new_value));
                    }
                }
            }

            self.db.commit(result_and_state.state);

            // Persist vm.warp/vm.roll effects (Foundry parity)
            if let Some(warped) = inspector.cheatcode_state().warp_timestamp {
                self.timestamp = warped.saturating_to();
            }
            if let Some(rolled) = inspector.cheatcode_state().roll_block {
                self.block_number = rolled.saturating_to();
            }

            self.last_result = Some(execution_result);
        }

        // READ-ONLY coverage check - does NOT write to shared coverage map
        // Result bit ONLY checked for last PC
        let result_bit = 1u64 << tx_result.to_bit_index();
        let would_find_new_coverage = if !inspector.touched.is_empty() {
            let len = inspector.touched.len();

            let coverage = coverage_ref.read();

            inspector
                .touched
                .iter()
                .enumerate()
                .any(|(idx, &(codehash, pc, stack_depth))| {
                    let depth_bit = if stack_depth < 64 {
                        1u64 << stack_depth
                    } else {
                        1u64 << 63
                    };

                    // Result bit ONLY checked for last PC
                    let is_last_pc = idx == len - 1;

                    if let Some(contract_cov) = coverage.get(&codehash) {
                        if let Some(&(depths, results)) = contract_cov.get(&pc) {
                            // Existing PC - check if we have new depth or result
                            let new_depth = (depths & depth_bit) == 0;
                            let new_result = is_last_pc && (results & result_bit) == 0;
                            new_depth || new_result
                        } else {
                            true // New PC = new coverage
                        }
                    } else {
                        true // New codehash = new coverage
                    }
                })
        } else {
            false
        };

        Ok((tx_result, would_find_new_coverage))
    }

    /// Execute a transaction with revm-inspectors TracingInspector for detailed call traces
    /// This provides Foundry-style trace output with call tree, gas usage, and storage changes
    /// Uses CombinedInspectorWithTracing for consistent cheatcode handling with fuzzing
    ///
    /// Returns: (TxResult, CallTraceArena, storage_changes, storage_reads, output_bytes, logs, pcs_hit)
    pub fn exec_tx_with_revm_tracing(
        &mut self,
        tx: &Tx,
    ) -> Result<
        (
            TxResult,
            revm_inspectors::tracing::CallTraceArena,
            Vec<(Address, U256, U256, U256)>,
            HashMap<(Address, U256), U256>,
            Bytes,
            Vec<revm::primitives::Log>,
            Vec<(alloy_primitives::B256, usize)>, // PCs hit: (codehash, pc) for solver tracking
        ),
        ExecError,
    > {
        use revm_inspectors::tracing::TracingInspectorConfig;

        // Ensure sender account exists in the database
        self.ensure_account_exists(tx.src);

        // Capture state before execution for potential rollback
        let initial_block = self.block_number;
        let initial_timestamp = self.timestamp;

        // Apply time/block delay
        self.timestamp += tx.delay.0;
        self.block_number += tx.delay.1;

        // Handle NoCall (just delay, no actual execution)
        if matches!(tx.call, TxCall::NoCall) {
            self.last_result = None;
            self.last_calldata = Bytes::new();
            self.last_call_target = None;
            return Ok((
                TxResult::Stop,
                revm_inspectors::tracing::CallTraceArena::default(),
                vec![],
                HashMap::new(),
                Bytes::new(),
                vec![],
                vec![], // No PCs hit for NoCall
            ));
        }

        // Encode calldata based on call type
        let (calldata, is_create) = match &tx.call {
            TxCall::SolCall { name, args } => (encode_call(name, args)?, false),
            TxCall::SolCalldata(data) => (data.clone(), false),
            TxCall::SolCreate(code) => (code.clone(), true),
            TxCall::NoCall => (Bytes::new(), false),
        };

        // Record calldata and target
        self.last_calldata = calldata.clone();
        self.last_call_target = if is_create { None } else { Some(tx.dst) };

        // Determine transaction kind
        let kind = if is_create {
            TxKind::Create
        } else {
            TxKind::Call(tx.dst)
        };

        // Pre-compute values
        let nonce = self.get_nonce(tx.src);
        let block_number = U256::from(self.block_number);
        let block_timestamp = U256::from(self.timestamp);
        let caller = tx.src;
        let value = tx.value;
        let gas_limit = tx.gas;

        // Use TracingWithCheatcodes - a custom combined inspector that:
        // 1. Always calls TracingInspector.call() first to start trace (prevents panic)
        // 2. Then calls CheatcodeInspector.call() to handle pranks and HEVM calls
        // This ensures prank handling works exactly like fuzzing
        let tracing_config = TracingInspectorConfig::default_parity()
            .with_state_diffs()
            .record_logs();
        let mut inspector = crate::coverage::TracingWithCheatcodes::new(tracing_config);

        // Set context for vm.generateCalls() cheatcode (for trace display of reentrancy)
        if let Some((fuzzable_funcs, gen_dict, rng_seed)) = &self.generate_calls_context {
            use crate::cheatcodes::GenerateCallsContext;
            inspector.cheatcode.generate_calls_ctx = Some(GenerateCallsContext {
                fuzzable_functions: fuzzable_funcs.clone(),
                gen_dict: gen_dict.clone(),
                rng_seed: *rng_seed,
                call_count: 0,
            });
        }

        let ctx = Context::mainnet()
            .with_db(&mut self.db)
            .modify_cfg_chained(|cfg| {
                cfg.limit_contract_code_size = Some(usize::MAX);
                cfg.limit_contract_initcode_size = Some(usize::MAX);
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
                cfg.disable_eip3607 = true;
                cfg.disable_base_fee = true;
                cfg.tx_gas_limit_cap = Some(u64::MAX);
            })
            .modify_tx_chained(|tx_env| {
                tx_env.caller = caller;
                tx_env.kind = kind;
                tx_env.value = value;
                tx_env.data = calldata;
                tx_env.gas_limit = gas_limit;
                tx_env.nonce = nonce;
                tx_env.gas_price = tx.gasprice.saturating_to();
            })
            .modify_block_chained(|block| {
                block.number = block_number;
                block.timestamp = block_timestamp;
                block.gas_limit = 1_000_000_000_000;
            });

        let tx_env = ctx.tx.clone();

        // Execute with TracingInspector
        let result_and_state = {
            let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
            evm.inspect_tx(tx_env)
                .map_err(|e| ExecError::EvmError(format!("{:?}", e)))?
        };

        let execution_result = result_and_state.result;
        let tx_result = classify_execution_result(&execution_result);

        // Extract output bytes and logs
        let (output_bytes, logs) = match &execution_result {
            ExecutionResult::Success { output, logs, .. } => {
                let out = match output {
                    Output::Call(data) => data.clone(),
                    Output::Create(data, _) => data.clone(),
                };
                (out, logs.clone())
            }
            ExecutionResult::Revert { output, .. } => (output.clone(), vec![]),
            ExecutionResult::Halt { .. } => (Bytes::new(), vec![]),
        };

        // Extract storage changes
        let mut storage_changes = Vec::new();

        // Handle result and persistence
        if tx_result.is_revert() || tx_result.is_error() {
            // Revert: Rollback state changes
            self.block_number = initial_block;
            self.timestamp = initial_timestamp;
            self.last_result = Some(execution_result);
            self.last_state_diff.clear();
        } else {
            // Success: Extract storage changes before committing
            self.last_state_diff.clear();
            for (addr, account) in &result_and_state.state {
                for (slot, slot_value) in &account.storage {
                    let old_value = slot_value.original_value();
                    let new_value = slot_value.present_value();
                    if old_value != new_value {
                        self.last_state_diff
                            .insert((*addr, *slot), (old_value, new_value));
                        storage_changes.push((*addr, *slot, old_value, new_value));
                    }
                }
            }

            self.db.commit(result_and_state.state);

            // Persist vm.warp/vm.roll effects (Foundry parity)
            if let Some(warped) = inspector.cheatcode.state.warp_timestamp {
                self.timestamp = warped.saturating_to();
            }
            if let Some(rolled) = inspector.cheatcode.state.roll_block {
                self.block_number = rolled.saturating_to();
            }

            self.last_result = Some(execution_result);
        }

        // Extract labels from cheatcode state
        for (addr, label) in &inspector.cheatcode.state.labels {
            self.labels.insert(*addr, label.clone());
        }

        // Extract storage reads captured during execution (actual SLOAD operations)
        let storage_reads = std::mem::take(&mut inspector.storage_reads);

        // Extract PCs hit during execution (for solver closest approach tracking)
        let pcs_hit = std::mem::take(&mut inspector.pcs_hit);

        // Get the call trace arena from TracingInspector
        let traces = inspector.into_traces();

        Ok((
            tx_result,
            traces,
            storage_changes,
            storage_reads,
            output_bytes,
            logs,
            pcs_hit,
        ))
    }
}
