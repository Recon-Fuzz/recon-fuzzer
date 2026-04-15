//! Shortcuts Expansion Module
//!
//! This experimental feature expands `shortcut_*` functions when they succeed during fuzzing.
//! When the fuzzer discovers a successful shortcut call that leads to new coverage,
//! we trace the shortcut to capture all external calls and save expanded sequences.
//!
//! For a sequence like [tx0, tx1, shortcut_A, tx3, shortcut_B, tx5]:
//! - Original corpus saved as normal (e.g., 12345.txt)
//! - Expanded shortcut_A saved as 12345_2.txt (txs 0-1 successful + expanded shortcut_A)
//! - Expanded shortcut_B saved as 12345_4.txt (txs 0-3 successful + expanded shortcut_B)

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_primitives::{Address, Bytes, U256};
use revm::{
    context_interface::ContextTr,
    interpreter::{interpreter_types::InterpreterTypes, CallInputs, CallOutcome, Interpreter},
    Inspector,
};

use evm::{
    exec::EvmState,
    foundry::CompiledContract,
    types::{Tx, TxCall},
};
use primitives::MAX_GAS_PER_BLOCK;

use crate::worker_env::WorkerEnv;

/// A captured external call from shortcut execution
#[derive(Debug, Clone)]
struct CapturedCall {
    /// Target address of the call
    target: Address,
    /// Calldata (selector + args)
    calldata: Bytes,
    /// Value sent with the call
    value: U256,
    /// The caller address (msg.sender for this call)
    #[allow(dead_code)]
    caller: Address,
}

/// Inspector that captures external calls during execution
#[derive(Debug)]
struct CallCaptureInspector {
    /// Current call depth (0 = before any call, 1 = initial shortcut call, 2+ = subcalls)
    depth: u32,
    /// Captured external calls (excluding calls to target contract and precompiles)
    captured_calls: Vec<CapturedCall>,
    /// The target contract address (to filter out self-calls)
    target_contract: Address,
}

impl CallCaptureInspector {
    fn new(target_contract: Address) -> Self {
        Self {
            depth: 0,
            captured_calls: Vec::new(),
            target_contract,
        }
    }
}

impl<CTX: ContextTr, INTR: InterpreterTypes> Inspector<CTX, INTR> for CallCaptureInspector {
    fn step(&mut self, _interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        // We don't need opcode-level tracing, just call tracking
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // Increment depth when entering a call
        self.depth += 1;

        let target = inputs.target_address;
        let caller = inputs.caller;

        // Skip precompiles (addresses 0x1-0x9)
        let is_precompile = target.0[..19] == [0u8; 19] && target.0[19] < 10;

        // Only capture calls that ORIGINATE from the target contract
        // This includes both external calls (token.transfer()) and self-calls (this.foo())
        let is_from_target = caller == self.target_contract;

        tracing::trace!(
            "[Shortcuts] CALL depth={} caller={:?} target={:?} target_contract={:?} is_from_target={} is_precompile={}",
            self.depth, caller, target, self.target_contract, is_from_target, is_precompile
        );

        if !is_precompile && is_from_target {
            let calldata = inputs.input.bytes(context);
            self.captured_calls.push(CapturedCall {
                target,
                calldata,
                value: inputs.value.get(),
                caller,
            });
        }

        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, _outcome: &mut CallOutcome) {
        // Decrement depth when exiting a call
        self.depth = self.depth.saturating_sub(1);
    }
}

/// Try to decode calldata into function name and args using contract ABIs
fn try_decode_calldata(
    calldata: &Bytes,
    contracts: &[CompiledContract],
) -> Option<(String, Vec<DynSolValue>)> {
    if calldata.len() < 4 {
        return None;
    }

    let selector = &calldata[..4];
    let args_data = &calldata[4..];

    // Try to find the function in any known contract's ABI
    for contract in contracts {
        for func in contract.abi.functions() {
            if func.selector().as_slice() == selector {
                // Found matching function, try to decode args
                match func.abi_decode_input(args_data) {
                    Ok(decoded) => {
                        return Some((func.name.clone(), decoded));
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    None
}

/// Convert captured calls to a transaction sequence
fn captured_calls_to_tx_sequence(
    calls: &[CapturedCall],
    sender: Address,
    contracts: &[CompiledContract],
) -> Vec<Tx> {
    calls
        .iter()
        .map(|call| {
            // Try to decode calldata into function name + args
            let tx_call = if let Some((name, args)) = try_decode_calldata(&call.calldata, contracts)
            {
                TxCall::SolCall { name, args }
            } else {
                // Fall back to raw calldata if decoding fails
                TxCall::SolCalldata(call.calldata.clone())
            };

            Tx {
                call: tx_call,
                src: sender,
                dst: call.target,
                gas: MAX_GAS_PER_BLOCK,
                gasprice: U256::ZERO,
                value: call.value,
                delay: (0, 0),
            }
        })
        .collect()
}

/// Execute a call with the CallCaptureInspector to capture external calls
fn execute_with_call_capture(
    vm: &mut EvmState,
    caller: Address,
    target: Address,
    calldata: Bytes,
) -> anyhow::Result<Vec<CapturedCall>> {
    use alloy_primitives::TxKind;
    use revm::{Context, DatabaseCommit, InspectEvm, MainBuilder, MainContext};

    let nonce = vm.get_nonce(caller);
    let block_number = alloy_primitives::U256::from(vm.block_number);
    let block_timestamp = alloy_primitives::U256::from(vm.timestamp);
    let gas_limit = vm.gas_limit;

    // Create our call capture inspector
    let mut inspector = CallCaptureInspector::new(target);

    let ctx = Context::mainnet()
        .with_db(&mut vm.db)
        .modify_cfg_chained(|cfg| {
            cfg.limit_contract_code_size = Some(usize::MAX);
            cfg.limit_contract_initcode_size = Some(usize::MAX);
            cfg.disable_balance_check = true;
            cfg.disable_block_gas_limit = true;
            cfg.disable_eip3607 = true;
            cfg.disable_base_fee = true;
        })
        .modify_tx_chained(|tx_env| {
            tx_env.caller = caller;
            tx_env.kind = TxKind::Call(target);
            tx_env.value = alloy_primitives::U256::ZERO;
            tx_env.data = calldata;
            tx_env.gas_limit = gas_limit;
            tx_env.nonce = nonce;
            tx_env.gas_price = 0;
        })
        .modify_block_chained(|block| {
            block.number = block_number;
            block.timestamp = block_timestamp;
            block.gas_limit = gas_limit;
        });

    let tx_env = ctx.tx.clone();

    let result_and_state = {
        let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
        evm.inspect_tx(tx_env)
            .map_err(|e| anyhow::anyhow!("EVM error: {:?}", e))?
    };

    // Commit state changes (shortcuts may set up state we want to preserve)
    vm.db.commit(result_and_state.state);

    // Check if execution was successful - only return calls on success
    match &result_and_state.result {
        revm::context_interface::result::ExecutionResult::Success { .. } => {
            Ok(inspector.captured_calls)
        }
        revm::context_interface::result::ExecutionResult::Revert { .. } => {
            // Don't return calls from reverted shortcuts
            Ok(vec![])
        }
        revm::context_interface::result::ExecutionResult::Halt { .. } => Ok(vec![]),
    }
}

// =============================================================================
// ON-DEMAND SHORTCUT EXPANSION
// =============================================================================

/// Check if a transaction is a shortcut_* function call
pub fn is_shortcut_call(tx: &Tx) -> bool {
    match &tx.call {
        TxCall::SolCall { name, .. } => name.starts_with("shortcut_"),
        TxCall::SolCalldata(_) => {
            // Can't determine from raw calldata without ABI
            false
        }
        _ => false,
    }
}

/// Check if a transaction result indicates success (not reverted)
pub fn tx_succeeded(result: &evm::types::TxResult) -> bool {
    matches!(
        result,
        evm::types::TxResult::Stop | evm::types::TxResult::ReturnTrue | evm::types::TxResult::ReturnFalse
    )
}

/// Execute a single transaction on a VM (no tracing, just execution)
fn execute_tx_simple(vm: &mut EvmState, tx: &Tx) -> evm::types::TxResult {
    match vm.exec_tx(tx) {
        Ok(result) => result,
        Err(_) => evm::types::TxResult::ErrorRevert,
    }
}

/// Expand successful shortcut calls in an executed sequence.
///
/// For each successful shortcut at index N:
/// 1. Clone the initial VM state
/// 2. Execute txs 0 to N-1 (only successful ones) to build correct state
/// 3. Trace shortcut N to capture external calls
/// 4. Save as separate file: {corpus_hash}_{shortcut_index}.txt
///
/// Args:
/// - env: Worker environment with contracts and config
/// - initial_vm: The INITIAL VM state (before any transactions)
/// - tx_seq: The full transaction sequence
/// - results: Results from executing tx_seq
/// - corpus_hash: Hash of the original corpus (for naming expanded files)
///
/// Returns the number of expanded sequences saved.
pub fn expand_shortcuts_in_sequence(
    env: &WorkerEnv,
    initial_vm: &EvmState,
    tx_seq: &[Tx],
    results: &[evm::types::TxResult],
    corpus_hash: u64,
) -> usize {
    if !env.cfg.campaign_conf.shortcuts_enable {
        tracing::trace!("[Shortcuts] shortcuts_enable is false, skipping");
        return 0;
    }

    tracing::debug!(
        "[Shortcuts] Processing sequence with {} txs, corpus_hash={}",
        tx_seq.len(),
        corpus_hash
    );

    let mut expanded_count = 0;

    // Find all successful shortcut calls
    let successful_shortcuts: Vec<(usize, &Tx)> = tx_seq
        .iter()
        .zip(results.iter())
        .enumerate()
        .filter(|(_, (tx, result))| is_shortcut_call(tx) && tx_succeeded(result))
        .map(|(i, (tx, _))| (i, tx))
        .collect();

    if successful_shortcuts.is_empty() {
        tracing::debug!("[Shortcuts] No successful shortcuts found in sequence");
        return 0;
    }

    tracing::info!(
        "[Shortcuts] Found {} successful shortcuts in sequence (corpus_hash={})",
        successful_shortcuts.len(),
        corpus_hash
    );

    for (shortcut_idx, shortcut_tx) in successful_shortcuts {
        let shortcut_name = match &shortcut_tx.call {
            TxCall::SolCall { name, .. } => name.clone(),
            _ => continue,
        };

        tracing::debug!(
            "[Shortcuts] Expanding {} at index {}",
            shortcut_name,
            shortcut_idx
        );

        // Clone initial VM to build up state
        let mut vm = initial_vm.clone();

        // Execute all successful transactions BEFORE this shortcut
        let mut prefix_txs: Vec<Tx> = Vec::new();
        for i in 0..shortcut_idx {
            if tx_succeeded(&results[i]) {
                let tx = &tx_seq[i];
                let result = execute_tx_simple(&mut vm, tx);
                if tx_succeeded(&result) {
                    prefix_txs.push(tx.clone());
                }
            }
        }

        tracing::debug!(
            "[Shortcuts] Executed {} prefix txs before {}",
            prefix_txs.len(),
            shortcut_name
        );

        // Now trace the shortcut to capture external calls
        let calldata = match &shortcut_tx.call {
            TxCall::SolCall { name, args } => match evm::exec::encode_call(name, args) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!("[Shortcuts] Failed to encode {}: {}", name, e);
                    continue;
                }
            },
            _ => continue,
        };

        let captured =
            match execute_with_call_capture(&mut vm, shortcut_tx.src, shortcut_tx.dst, calldata) {
                Ok(calls) => calls,
                Err(e) => {
                    tracing::warn!("[Shortcuts] Failed to trace {}: {}", shortcut_name, e);
                    continue;
                }
            };

        if captured.is_empty() {
            tracing::debug!("[Shortcuts] {} made no external calls", shortcut_name);
            continue;
        }

        tracing::info!(
            "[Shortcuts] {} captured {} external calls",
            shortcut_name,
            captured.len()
        );

        // Convert captured calls to transaction sequence
        let expanded_txs =
            captured_calls_to_tx_sequence(&captured, shortcut_tx.src, &env.contracts);

        if expanded_txs.is_empty() {
            continue;
        }

        // Build final sequence: prefix_txs + expanded_txs
        let mut final_seq = prefix_txs;
        final_seq.extend(expanded_txs.clone());

        // Save to separate file
        if let Err(e) = save_expanded_sequence(env, &final_seq, corpus_hash, shortcut_idx) {
            tracing::warn!(
                "[Shortcuts] Failed to save expanded sequence for {}: {}",
                shortcut_name,
                e
            );
            continue;
        }

        tracing::info!(
            "[Shortcuts] Saved expanded {} ({} prefix + {} expanded txs) as {}_{}.txt",
            shortcut_name,
            final_seq.len() - expanded_txs.len(),
            expanded_txs.len(),
            corpus_hash,
            shortcut_idx
        );

        expanded_count += 1;
    }

    expanded_count
}

/// Save an expanded shortcut sequence to disk
/// Filename: {corpus_hash}_{shortcut_index}.txt in coverage/ folder
fn save_expanded_sequence(
    env: &WorkerEnv,
    tx_seq: &[Tx],
    corpus_hash: u64,
    shortcut_idx: usize,
) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("echidna"));

    // Save to coverage folder so fuzzer picks them up for mutation
    let coverage_dir = corpus_dir.join("coverage");
    std::fs::create_dir_all(&coverage_dir)?;

    let filename = coverage_dir.join(format!("{}_{}.txt", corpus_hash, shortcut_idx));
    let json = serde_json::to_string_pretty(tx_seq)?;

    if !filename.exists() {
        std::fs::write(&filename, &json)?;
        println!(
            "{} [Shortcuts] Saved expanded sequence to {}",
            crate::output::format_timestamp(),
            filename.display()
        );
    }

    Ok(())
}
