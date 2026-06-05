//! HEVM Cheatcode support
//!
//! Implements common cheatcodes from foundry/HEVM for testing
//! Cheatcode address: 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use revm::{
    context_interface::ContextTr,
    interpreter::{CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult},
    interpreter::interpreter_types::{InterpreterTypes, Jumps, StackTr, LegacyBytecode},
    Inspector,
};
use revm::context_interface::journaled_state::account::JournaledAccountTr;
use std::collections::HashMap;
use std::sync::Arc;
use crate::storage_layout::{StorageLayout, StorageEntry, StorageType, extract_packed};
use crate::storage_layout_compact;

// Re-export HEVM_ADDRESS from primitives for backwards compatibility
pub use primitives::HEVM_ADDRESS;

// Define cheatcode function selectors using alloy_sol_types
sol! {
    function warp(uint256 newTimestamp) external;
    function roll(uint256 newNumber) external;
    function chainId(uint256 newChainId) external;
    function assume(bool condition) external;
    function deal(address who, uint256 newBalance) external;
    function prank(address msgSender) external;
    function startPrank(address msgSender) external;
    function stopPrank() external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function etch(address target, bytes code) external;
    function label(address account, string memory newLabel) external;
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function generateCalls(uint256 count) external returns (bytes[] memory);

    function load(address target, bytes32 slot) external returns (bytes32);
    function loadVar(address target, string path) external returns (bytes32);
    function loadVar(address target, string path, bytes keys) external returns (bytes32);
    function loadVar(address target, bytes32 slot, uint8 offset, uint8 size) external returns (bytes32);

    function storeVar(address target, string path, bytes32 value) external;
    function storeVar(address target, string path, bytes keys, bytes32 value) external;
    function storeVar(address target, bytes32 slot, uint8 offset, uint8 size, bytes32 value) external;

    // --- Layout registration ---

    /// Register a storage layout for a target address.
    /// Accepts solc JSON or compact format:
    ///   JSON:    '{"storage":[...],"types":{...}}'
    ///   Compact: "uint256 a, (uint128 lo, bool flag) config, mapping(address => uint256) balances"
    function registerStorageLayout(address target, string layout) external;
    /// Assign a compiled contract's storage layout to a target address by name.
    function assignStorageLayout(address target, string contractName) external;
    /// Register a namespaced storage layout (ERC-7201).
    /// Computes base slot from `ns` string, offsets all members.
    function registerNamespace(address target, string ns, string layout) external;
    /// Register a namespaced storage layout at a manual base slot.
    function registerNamespace(address target, uint256 baseSlot, string layout) external;
}

/// Context for generating calls via `vm.generateCalls()`. Set before tx
/// execution by the campaign layer.
///
/// `gen_dict` is wrapped in `Arc` so propagating the context through the
/// per-sequence and per-tx wiring is a refcount bump rather than a deep
/// clone of the dict (which can hold thousands of entries that grow over
/// the lifetime of the run).
///
/// Determinism guarantee: given the same `rng_seed` and `gen_dict`, every
/// invocation of the cheatcode produces the same byte stream. The seed
/// used for each invocation `i` is `rng_seed + sum(n_0..n_{i-1})`, so
/// multiple `vm.generateCalls(n)` calls within the same tx are also
/// deterministic and independent.
#[derive(Debug, Clone)]
pub struct GenerateCallsContext {
    /// Fuzzable function metadata: (selector, name, param_types)
    pub fuzzable_functions: Vec<(alloy_primitives::FixedBytes<4>, String, Vec<alloy_dyn_abi::DynSolType>)>,
    /// Generation dictionary (same as main fuzzer). Read-only at runtime —
    /// the cheatcode never mutates it, so sharing via `Arc` is safe.
    pub gen_dict: std::sync::Arc<abi::types::GenDict>,
    /// RNG seed pinned per tx (per-invocation seed = `rng_seed + call_count`).
    pub rng_seed: u64,
    /// Cumulative count of calls generated so far in this tx — used to
    /// advance the seed between invocations so each invocation gets a
    /// fresh deterministic stream.
    pub call_count: usize,
    /// Number of invocations made so far in this tx — index into
    /// `return_masks` and `captured_records`.
    pub call_index: usize,
    /// Optional per-invocation keep-mask, indexed by invocation ordinal.
    /// When `Some(mask)`, only indices `i` with `mask[i] == true` are
    /// returned to the harness; the rest are generated (to keep the RNG
    /// stream consistent) but dropped. `None` = return everything.
    /// Empty vec = capture mode (fresh fuzz, no caller-supplied masks).
    pub return_masks: Vec<Option<Vec<bool>>>,
    /// Records captured during this tx, one per invocation in call order.
    /// Drained by `EvmState` after tx execution so the campaign layer can
    /// stamp seed + records onto the failing reproducer's `Tx`.
    pub captured_records: Vec<crate::types::GenerateCallRecord>,
}

/// Cheatcode state that persists across calls
#[derive(Debug, Default, Clone)]
pub struct CheatcodeState {
    /// Pending prank address (single call)
    pub prank_caller: Option<Address>,
    /// Persistent prank address (until stopPrank)
    pub start_prank_caller: Option<Address>,
    /// The original caller that invoked startPrank - prank only applies to calls FROM this address
    pub prank_origin: Option<Address>,
    /// Track the call depth when startPrank was called to properly scope the prank
    pub prank_depth: usize,
    /// Current call depth (incremented on call, decremented on return)
    pub call_depth: usize,
    /// Addresses to deal (set balance)
    pub deals: HashMap<Address, U256>,
    /// Storage slots to set
    pub stores: Vec<(Address, B256, B256)>,
    /// Code to etch at addresses
    pub etches: HashMap<Address, Bytes>,
    /// Warp timestamp
    pub warp_timestamp: Option<U256>,
    /// Roll block number
    pub roll_block: Option<U256>,
    /// Chain id override (vm.chainId)
    pub chain_id: Option<U256>,
    /// Labels for addresses
    pub labels: HashMap<Address, String>,
    /// Whether assume failed (skip this tx)
    pub assume_failed: bool,
}

impl CheatcodeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the effective caller (prank or real caller)
    pub fn effective_caller(&mut self, real_caller: Address) -> Address {
        // Single prank takes priority
        if let Some(pranked) = self.prank_caller.take() {
            return pranked;
        }
        // Persistent prank
        if let Some(pranked) = self.start_prank_caller {
            return pranked;
        }
        real_caller
    }

    /// Check if we should skip execution due to assume()
    pub fn should_skip(&self) -> bool {
        self.assume_failed
    }

    /// Reset per-transaction state
    pub fn reset_tx(&mut self) {
        self.prank_caller = None;
        self.assume_failed = false;
    }
}

/// Cheatcode Inspector for REVM
#[derive(Debug, Default, Clone)]
pub struct CheatcodeInspector {
    pub state: CheatcodeState,
    /// Last executed opcode (for step_end override of TIMESTAMP/NUMBER)
    last_opcode: u8,
    /// Context for vm.generateCalls() - set by campaign layer before tx execution
    pub generate_calls_ctx: Option<GenerateCallsContext>,
    /// Set if any sub-call (any depth) reverted with `Panic(0x01)` —
    /// solc 0.8+'s encoding of `assert(false)`. Mirrors the same flag on
    /// `CombinedInspector` so shrink replays (which use `exec_tx` with
    /// only this inspector) detect nested panics too.
    pub nested_panic_1: bool,
    /// Set if any sub-call halted with `InvalidFEOpcode` — the legacy
    /// (pre-0.8) encoding of `assert(false)`.
    pub nested_invalid_fe: bool,
    /// Storage layouts keyed by contract address (for loadVar/loadVarKeys)
    pub storage_layouts: Arc<HashMap<Address, StorageLayout>>,
    /// Available layouts by contract name (for assignStorageLayout)
    pub available_layouts: Arc<HashMap<String, StorageLayout>>,
}

/// Selector keccak256("Panic(uint256)")[..4] — Solidity 0.8+ Panic prefix.
pub(crate) const PANIC_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

/// TIMESTAMP opcode (0x42) - returns block.timestamp
const OP_TIMESTAMP: u8 = 0x42;
/// NUMBER opcode (0x43) - returns block.number
const OP_NUMBER: u8 = 0x43;
/// CHAINID opcode (0x46) - returns chain id (EIP-1344)
const OP_CHAINID: u8 = 0x46;

impl CheatcodeInspector {
    pub fn new() -> Self {
        Self {
            state: CheatcodeState::new(),
            last_opcode: 0,
            generate_calls_ctx: None,
            nested_panic_1: false,
            nested_invalid_fe: false,
            storage_layouts: Arc::new(HashMap::new()),
            available_layouts: Arc::new(HashMap::new()),
        }
    }

    /// Track opcode in step() for warp/roll override in step_end()
    pub fn track_opcode(&mut self, opcode: u8) {
        self.last_opcode = opcode;
    }

    /// Regenerate the kept calls for a single `vm.generateCalls(count)`
    /// invocation given `(rng_seed, count, keep_mask, gen_dict, fuzzable)`.
    /// Returns `(idx_within_batch, name, args)` for each call kept. Used for
    /// human-readable rendering of failing reproducers — the cheatcode
    /// itself uses the same logic but returns ABI-encoded bytes.
    ///
    /// The seed is derived externally as `rng_seed + call_count_so_far` so
    /// the caller can reproduce a specific invocation within a tx.
    pub fn regenerate_kept_calls(
        seed: u64,
        count: usize,
        keep_mask: Option<&Vec<bool>>,
        gen_dict: &abi::types::GenDict,
        fuzzable_functions: &[(
            alloy_primitives::FixedBytes<4>,
            String,
            Vec<alloy_dyn_abi::DynSolType>,
        )],
    ) -> Vec<(usize, String, Vec<alloy_dyn_abi::DynSolValue>)> {
        use rand::prelude::*;
        use rand_chacha::ChaCha8Rng;

        if fuzzable_functions.is_empty() {
            return Vec::new();
        }

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut out = Vec::new();
        for j in 0..count {
            let idx = rng.gen_range(0..fuzzable_functions.len());
            let (_selector, name, param_types) = &fuzzable_functions[idx];
            let (resolved_name, args) =
                abi::r#gen::gen_abi_call_m(&mut rng, gen_dict, name, param_types);
            let keep = match keep_mask {
                Some(m) => m.get(j).copied().unwrap_or(true),
                None => true,
            };
            if keep {
                out.push((j, resolved_name, args));
            }
        }
        out
    }

    /// Generate calldatas for `vm.generateCalls(count)`. Returns ABI-encoded
    /// `bytes[]`.
    ///
    /// Uses `gen_abi_call_m` directly — identical to the main fuzzer.
    /// Generation is deterministic given `(rng_seed, call_count)` so the
    /// same calls reproduce on shrink replay.
    ///
    /// If the context has a per-invocation keep-mask for this call index,
    /// the generated calls are filtered (still generated to keep the RNG
    /// stream consistent, but dropped from the return value). The full
    /// `count` always advances `call_count` so the next invocation in the
    /// tx gets the same seed it would have without any mask applied.
    pub fn generate_calls(&mut self, count: usize) -> Bytes {
        use alloy_dyn_abi::DynSolValue;
        use rand::prelude::*;
        use rand_chacha::ChaCha8Rng;

        let ctx = match &mut self.generate_calls_ctx {
            Some(c) => c,
            None => {
                tracing::trace!("vm.generateCalls: no context set, returning empty array");
                return encode_bytes_array(&[]);
            }
        };

        if ctx.fuzzable_functions.is_empty() {
            tracing::trace!("vm.generateCalls: no fuzzable functions in context");
            return encode_bytes_array(&[]);
        }

        // Look up the keep-mask for this invocation (if any). Cloned out of
        // the borrow so we can also push a captured_record below.
        let invocation_idx = ctx.call_index;
        let keep_mask: Option<Vec<bool>> = ctx
            .return_masks
            .get(invocation_idx)
            .and_then(|m| m.clone());

        // Per-invocation seed: stable across replays as long as previous
        // invocations consumed the same total count.
        let seed = ctx.rng_seed.wrapping_add(ctx.call_count as u64);
        // Advance by the *requested* count (not the kept count) so the
        // seed for invocation N+1 matches the original failing run even
        // when invocation N is being shrunk via keep_mask.
        ctx.call_count += count;
        ctx.call_index += 1;
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        let mut returned = Vec::with_capacity(count);
        for j in 0..count {
            // Pick a random function (same as gen_tx)
            let idx = rng.gen_range(0..ctx.fuzzable_functions.len());
            let (selector, name, param_types) = &ctx.fuzzable_functions[idx];

            // Generate call using gen_abi_call_m (identical to main fuzzer).
            // Always generate — keep_mask only filters the *return* set; the
            // RNG stream must advance identically to the original run.
            let (_name, args) =
                abi::r#gen::gen_abi_call_m(&mut rng, &ctx.gen_dict, name, param_types);

            let keep = match &keep_mask {
                Some(m) => m.get(j).copied().unwrap_or(true),
                None => true,
            };
            if keep {
                let encoded_args = DynSolValue::Tuple(args).abi_encode();
                let mut calldata = selector.to_vec();
                calldata.extend(encoded_args);
                returned.push(Bytes::from(calldata));
            }
        }

        // Record this invocation so the campaign can stamp it onto the tx
        // for shrink replay. Carry through any caller-supplied keep_mask so
        // a recorded record round-trips losslessly.
        ctx.captured_records.push(crate::types::GenerateCallRecord {
            n: count,
            keep_mask,
        });

        tracing::trace!(
            "vm.generateCalls: generated {} of {} calls (seed={}, invocation={})",
            returned.len(),
            count,
            seed,
            invocation_idx,
        );
        encode_bytes_array(&returned)
    }

    /// Resolve a storage path and read the value from the journal.
    fn resolve_and_read<CTX: ContextTr>(
        &self, context: &mut CTX, target: Address, path: &str, keys: &[u8],
    ) -> Result<U256, String> {
        use revm::context_interface::JournalTr;
        let layout = self.storage_layouts.get(&target)
            .ok_or_else(|| format!("no storage layout registered for {:?}", target))?;
        let resolved = layout.resolve(path, keys).map_err(|e| format!("{}", e))?;
        // Load account into journal first to avoid panics
        if context.journal_mut().load_account_mut(target).is_err() {
            return Err(format!("failed to load account {:?}", target));
        }
        let slot_revm = revm::primitives::U256::from_be_bytes(resolved.slot.to_be_bytes::<32>());
        let raw = context.journal_mut().sload(target, slot_revm)
            .map(|r| U256::from_be_bytes(r.data.to_be_bytes::<32>()))
            .unwrap_or(U256::ZERO);
        Ok(extract_packed(raw, resolved.offset, resolved.size))
    }

    /// Resolve a storage path and write a value via the journal.
    fn resolve_and_write<CTX: ContextTr>(
        &self, context: &mut CTX, target: Address, path: &str, keys: &[u8], value: U256,
    ) -> Result<(), String> {
        let layout = self.storage_layouts.get(&target)
            .ok_or_else(|| format!("no storage layout registered for {:?}", target))?;
        let resolved = layout.resolve(path, keys).map_err(|e| format!("{}", e))?;
        write_packed_via_journal(context, target, resolved.slot, resolved.offset, resolved.size, value);
        Ok(())
    }

    /// Handle a cheatcode call
    pub fn handle_cheatcode(&mut self, input: &Bytes) -> Option<Bytes> {
        if input.len() < 4 {
            return None;
        }

        let selector = &input[..4];

        // warp(uint256)
        if selector == warpCall::SELECTOR {
            if let Ok(decoded) = warpCall::abi_decode(input) {
                self.state.warp_timestamp = Some(decoded.newTimestamp);
                return Some(Bytes::new());
            }
        }

        // roll(uint256)
        if selector == rollCall::SELECTOR {
            if let Ok(decoded) = rollCall::abi_decode(input) {
                self.state.roll_block = Some(decoded.newNumber);
                return Some(Bytes::new());
            }
        }

        // chainId(uint256)
        if selector == chainIdCall::SELECTOR {
            if let Ok(decoded) = chainIdCall::abi_decode(input) {
                self.state.chain_id = Some(decoded.newChainId);
                return Some(Bytes::new());
            }
        }

        // assume(bool)
        if selector == assumeCall::SELECTOR {
            if let Ok(decoded) = assumeCall::abi_decode(input) {
                if !decoded.condition {
                    self.state.assume_failed = true;
                }
                return Some(Bytes::new());
            }
        }

        // deal(address, uint256) - Note: actual balance modification happens in handle_cheatcode_with_context
        if selector == dealCall::SELECTOR {
            // Just parse and return success - the actual deal will be applied in the Inspector
            if dealCall::abi_decode(input).is_ok() {
                return Some(Bytes::new());
            }
        }

        // prank(address)
        if selector == prankCall::SELECTOR {
            if let Ok(decoded) = prankCall::abi_decode(input) {
                self.state.prank_caller = Some(decoded.msgSender);
                return Some(Bytes::new());
            }
        }

        // startPrank(address) - handled in Inspector::call to capture caller
        // This is a fallback that shouldn't normally be hit
        if selector == startPrankCall::SELECTOR {
            // Just return success - actual handling in call() inspector
            return Some(Bytes::new());
        }

        // stopPrank() - handled in Inspector::call for proper state clearing
        // This is a fallback that shouldn't normally be hit
        if selector == stopPrankCall::SELECTOR {
            // Just return success - actual handling in call() inspector
            return Some(Bytes::new());
        }

        // store(address, bytes32, bytes32) — handled in call() with journal access
        if selector == storeCall::SELECTOR {
            return None;
        }

        // load(address, bytes32) - handled in call() with context access
        if selector == loadCall::SELECTOR {
            return None;
        }

        // etch(address, bytes)
        if selector == etchCall::SELECTOR {
            if let Ok(decoded) = etchCall::abi_decode(input) {
                self.state.etches.insert(decoded.target, decoded.code);
                return Some(Bytes::new());
            }
        }

        // label(address, string)
        if selector == labelCall::SELECTOR {
            if let Ok(decoded) = labelCall::abi_decode(input) {
                self.state.labels.insert(decoded.account, decoded.newLabel);
                return Some(Bytes::new());
            }
        }

        // addr(uint256) - derive address from private key using secp256k1
        if selector == addrCall::SELECTOR {
            if let Ok(decoded) = addrCall::abi_decode(input) {
                // Use secp256k1 to derive the public key and then the address
                let pk_bytes = decoded.privateKey.to_be_bytes::<32>();
                
                // Try to create a signing key from the private key
                if let Ok(signing_key) = k256::ecdsa::SigningKey::from_bytes((&pk_bytes).into()) {
                    let verifying_key = signing_key.verifying_key();
                    let public_key_bytes = verifying_key.to_encoded_point(false);
                    // Keccak256 of the uncompressed public key (without the 0x04 prefix)
                    let hash = alloy_primitives::keccak256(&public_key_bytes.as_bytes()[1..]);
                    let addr = Address::from_slice(&hash[12..]);
                    // Return ABI-encoded address (32 bytes, left-padded)
                    let mut result = [0u8; 32];
                    result[12..].copy_from_slice(addr.as_slice());
                    return Some(Bytes::from(result.to_vec()));
                } else {
                    // Invalid private key, return zero address
                    return Some(Bytes::from(vec![0u8; 32]));
                }
            }
        }

        None
    }
}

impl<CTX: ContextTr, INTR: InterpreterTypes> Inspector<CTX, INTR> for CheatcodeInspector {
    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        // Track opcode for step_end() to handle warp/roll overrides
        let pc = interp.bytecode.pc();
        let bytecode = interp.bytecode.bytecode_slice();
        let opcode = if pc < bytecode.len() { bytecode[pc] } else { 0 };
        self.last_opcode = opcode;
    }
    
    fn step_end(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        // Handle vm.warp() - override TIMESTAMP opcode result
        // TIMESTAMP (0x42) pushes block.timestamp to stack
        // If warp is active, replace with our warped value
        if self.last_opcode == OP_TIMESTAMP {
            if let Some(warped) = self.state.warp_timestamp {
                // Pop the original timestamp and push the warped value
                if interp.stack.pop().is_some() {
                    let _ = interp.stack.push(warped);
                    tracing::trace!("Warp: Overrode TIMESTAMP with {:?}", warped);
                }
            }
        }
        
        // Handle vm.roll() - override NUMBER opcode result
        // NUMBER (0x43) pushes block.number to stack
        // If roll is active, replace with our rolled value
        if self.last_opcode == OP_NUMBER {
            if let Some(rolled) = self.state.roll_block {
                // Pop the original block number and push the rolled value
                if interp.stack.pop().is_some() {
                    let _ = interp.stack.push(rolled);
                    tracing::trace!("Roll: Overrode NUMBER with {:?}", rolled);
                }
            }
        }

        // Handle vm.chainId() — override CHAINID opcode result (EIP-1344).
        if self.last_opcode == OP_CHAINID {
            if let Some(new_id) = self.state.chain_id {
                if interp.stack.pop().is_some() {
                    let _ = interp.stack.push(new_id);
                    tracing::trace!("ChainId: Overrode CHAINID with {:?}", new_id);
                }
            }
        }

        // Reset last_opcode after handling
        self.last_opcode = 0;
    }
    
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        use revm::context_interface::JournalTr;
        
        let target = inputs.target_address;
        
        tracing::trace!("Inspector::call to {:?}, gas_limit={}", target, inputs.gas_limit);
        
        // Check if this is a call to the cheatcode address
        if target == HEVM_ADDRESS {
            // Extract bytes from CallInput using the context (handles SharedBuffer properly)
            let input_data: Bytes = inputs.input.bytes(context);
            
            // Handle startPrank specially - we need to record the caller that invoked startPrank
            // Foundry behavior: startPrank reverts if already pranking
            if input_data.len() >= 4 && &input_data[..4] == startPrankCall::SELECTOR {
                if let Ok(decoded) = startPrankCall::abi_decode(&input_data) {
                    // Check if already pranking - Foundry reverts in this case
                    if self.state.start_prank_caller.is_some() {
                        // Return revert - can't start a new prank while one is active
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::from_static(b"already pranking"),
                                gas: Gas::new(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                            precompile_call_logs: vec![],
                            was_precompile_called: false,
                            charged_new_account_state_gas: false,
                        });
                    }
                    
                    self.state.start_prank_caller = Some(decoded.msgSender);
                    // Record the caller of startPrank - this is who the prank should apply to
                    self.state.prank_origin = Some(inputs.caller);
                    self.state.prank_depth = self.state.call_depth;
                    
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::new(),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                        precompile_call_logs: vec![],
                        was_precompile_called: false,
                        charged_new_account_state_gas: false,
                    });
                }
            }
            
            // Handle stopPrank in inspector to properly clear state
            if input_data.len() >= 4 && &input_data[..4] == stopPrankCall::SELECTOR {
                self.state.start_prank_caller = None;
                self.state.prank_origin = None;
                self.state.prank_depth = 0;
                
                return Some(CallOutcome {
                    result: InterpreterResult {
                        result: InstructionResult::Return,
                        output: Bytes::new(),
                        gas: Gas::new(inputs.gas_limit),
                    },
                    memory_offset: inputs.return_memory_offset.clone(),
                    precompile_call_logs: vec![],
                    was_precompile_called: false,
                    charged_new_account_state_gas: false,
                });
            }
            
            // Handle deal(address, uint256) - requires DB access
            if input_data.len() >= 4 && &input_data[..4] == dealCall::SELECTOR {
                if let Ok(decoded) = dealCall::abi_decode(&input_data) {
                    // Load account mutably from the journal
                    if let Ok(mut account_load) = context.journal_mut().load_account_mut(decoded.who) {
                        // Use the set_balance method on JournaledAccount which properly journals the change
                        // StateLoad implements DerefMut so we can access the JournaledAccount directly
                        account_load.data.set_balance(decoded.newBalance);
                    }
                    
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::new(),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                        precompile_call_logs: vec![],
                        was_precompile_called: false,
                        charged_new_account_state_gas: false,
                    });
                }
            }

            // Handle etch(address, bytes) - requires DB access to set bytecode
            if input_data.len() >= 4 && &input_data[..4] == etchCall::SELECTOR {
                if let Ok(decoded) = etchCall::abi_decode(&input_data) {
                    // First, ensure the account exists in the journal by loading it
                    // This creates the account if it doesn't exist (similar to how deal works)
                    let _ = context.journal_mut().load_account_mut(decoded.target);

                    // Now use journal's set_code_with_hash to properly set bytecode
                    use revm::bytecode::Bytecode;
                    let bytecode = Bytecode::new_raw(decoded.code.clone());
                    let code_hash = bytecode.hash_slow();
                    context.journal_mut().set_code_with_hash(decoded.target, bytecode, code_hash);
                    tracing::debug!("vm.etch: set code at {:?}, len={}, hash={:?}", decoded.target, decoded.code.len(), code_hash);

                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::new(),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                        precompile_call_logs: vec![],
                        was_precompile_called: false,
                        charged_new_account_state_gas: false,
                    });
                }
            }

            // Handle generateCalls(uint256 count) - generate random calldatas for reentrancy testing
            if input_data.len() >= 4 && &input_data[..4] == generateCallsCall::SELECTOR {
                if let Ok(decoded) = generateCallsCall::abi_decode(&input_data) {
                    let count = decoded.count.try_into().unwrap_or(0usize);
                    let output = self.generate_calls(count);

                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output,
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                        precompile_call_logs: vec![],
                        was_precompile_called: false,
                        charged_new_account_state_gas: false,
                    });
                }
            }

            // Handle vm.load(address, bytes32) — read raw storage slot via journal
            if input_data.len() >= 4 && &input_data[..4] == loadCall::SELECTOR {
                if let Ok(decoded) = loadCall::abi_decode(&input_data) {
                    let val = read_storage_via_journal(context, decoded.target, decoded.slot.into());
                    return Some(make_return(val.to_be_bytes::<32>().to_vec(), inputs));
                }
            }

            // Handle vm.store(address, bytes32, bytes32) — write raw storage slot via journal
            if input_data.len() >= 4 && &input_data[..4] == storeCall::SELECTOR {
                if let Ok(decoded) = storeCall::abi_decode(&input_data) {
                    write_storage_via_journal(context, decoded.target, decoded.slot.into(), decoded.value.into());
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle vm.loadVar(address, bytes32, uint8, uint8)
            if input_data.len() >= 4 && &input_data[..4] == loadVar_2Call::SELECTOR {
                if let Ok(decoded) = loadVar_2Call::abi_decode(&input_data) {
                    let raw = read_storage_via_journal(context, decoded.target, decoded.slot.into());
                    let val = extract_packed(raw, decoded.offset as usize, decoded.size as usize);
                    return Some(make_return(val.to_be_bytes::<32>().to_vec(), inputs));
                }
            }

            // Handle vm.loadVar(address, string) — named path
            if input_data.len() >= 4 && &input_data[..4] == loadVar_0Call::SELECTOR {
                if let Ok(decoded) = loadVar_0Call::abi_decode(&input_data) {
                    match self.resolve_and_read(context, decoded.target, &decoded.path, &[]) {
                        Ok(val) => return Some(make_return(val.to_be_bytes::<32>().to_vec(), inputs)),
                        Err(e) => {
                            tracing::warn!("vm.load(path) failed: {}", e);
                            return Some(make_return(U256::ZERO.to_be_bytes::<32>().to_vec(), inputs));
                        }
                    }
                }
            }

            // Handle vm.loadVar(address, string, bytes) — named path + keys
            if input_data.len() >= 4 && &input_data[..4] == loadVar_1Call::SELECTOR {
                if let Ok(decoded) = loadVar_1Call::abi_decode(&input_data) {
                    match self.resolve_and_read(context, decoded.target, &decoded.path, &decoded.keys) {
                        Ok(val) => return Some(make_return(val.to_be_bytes::<32>().to_vec(), inputs)),
                        Err(e) => {
                            tracing::warn!("vm.load(path, keys) failed: {}", e);
                            return Some(make_return(U256::ZERO.to_be_bytes::<32>().to_vec(), inputs));
                        }
                    }
                }
            }

            // Handle vm.storeVar(address, string, bytes32) — named path write
            if input_data.len() >= 4 && &input_data[..4] == storeVar_0Call::SELECTOR {
                if let Ok(decoded) = storeVar_0Call::abi_decode(&input_data) {
                    match self.resolve_and_write(context, decoded.target, &decoded.path, &[], decoded.value.into()) {
                        Ok(()) => {}
                        Err(e) => tracing::warn!("vm.storeVar(path) failed: {}", e),
                    }
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle vm.storeVar(address, string, bytes, bytes32) — named path + keys write
            if input_data.len() >= 4 && &input_data[..4] == storeVar_1Call::SELECTOR {
                if let Ok(decoded) = storeVar_1Call::abi_decode(&input_data) {
                    match self.resolve_and_write(context, decoded.target, &decoded.path, &decoded.keys, decoded.value.into()) {
                        Ok(()) => {}
                        Err(e) => tracing::warn!("vm.storeVar(path, keys) failed: {}", e),
                    }
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle vm.storeVar(address, bytes32, uint8, uint8, bytes32) — packed write
            if input_data.len() >= 4 && &input_data[..4] == storeVar_2Call::SELECTOR {
                if let Ok(decoded) = storeVar_2Call::abi_decode(&input_data) {
                    write_packed_via_journal(
                        context, decoded.target, decoded.slot.into(),
                        decoded.offset as usize, decoded.size as usize, decoded.value.into(),
                    );
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle vm.registerStorageLayout(address, string)
            if input_data.len() >= 4 && &input_data[..4] == registerStorageLayoutCall::SELECTOR {
                if let Ok(decoded) = registerStorageLayoutCall::abi_decode(&input_data) {
                    match parse_layout_string(&decoded.layout) {
                        Ok(layout) => {
                            Arc::make_mut(&mut self.storage_layouts).insert(decoded.target, layout);
                            tracing::debug!("Registered storage layout for {:?}", decoded.target);
                        }
                        Err(e) => {
                            tracing::warn!("vm.registerStorageLayout: {}", e);
                        }
                    }
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle vm.registerNamespace(address, string ns, string layout) — ERC-7201
            if input_data.len() >= 4 && &input_data[..4] == registerNamespace_0Call::SELECTOR {
                if let Ok(decoded) = registerNamespace_0Call::abi_decode(&input_data) {
                    match parse_layout_string(&decoded.layout) {
                        Ok(layout) => {
                            let ns_layout = apply_namespace(&decoded.ns, layout);
                            merge_namespace_layout(&mut self.storage_layouts, decoded.target, ns_layout);
                            tracing::debug!("Registered namespace '{}' for {:?}", decoded.ns, decoded.target);
                        }
                        Err(e) => tracing::warn!("vm.registerNamespace: {}", e),
                    }
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle vm.registerNamespace(address, uint256 baseSlot, string layout) — manual slot
            if input_data.len() >= 4 && &input_data[..4] == registerNamespace_1Call::SELECTOR {
                if let Ok(decoded) = registerNamespace_1Call::abi_decode(&input_data) {
                    match parse_layout_string(&decoded.layout) {
                        Ok(layout) => {
                            let ns_layout = apply_namespace_at(decoded.baseSlot, layout);
                            merge_namespace_layout(&mut self.storage_layouts, decoded.target, ns_layout);
                            tracing::debug!("Registered namespace at slot {} for {:?}", decoded.baseSlot, decoded.target);
                        }
                        Err(e) => tracing::warn!("vm.registerNamespace: {}", e),
                    }
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle vm.assignStorageLayout(address, string)
            if input_data.len() >= 4 && &input_data[..4] == assignStorageLayoutCall::SELECTOR {
                if let Ok(decoded) = assignStorageLayoutCall::abi_decode(&input_data) {
                    let name = &decoded.contractName;
                    // Exact match first, then suffix match with ":{name}"
                    let layout = self.available_layouts.get(name.as_str()).cloned()
                        .or_else(|| {
                            let suffix = format!(":{}", name);
                            self.available_layouts.iter()
                                .find(|(k, _)| k.ends_with(&suffix))
                                .map(|(_, v)| v.clone())
                        });
                    if let Some(layout) = layout {
                        Arc::make_mut(&mut self.storage_layouts).insert(decoded.target, layout);
                        tracing::info!("Assigned storage layout '{}' to {:?}", name, decoded.target);
                    } else {
                        tracing::warn!("vm.assignStorageLayout: no layout found for '{}'", name);
                    }
                    return Some(make_return(Vec::new(), inputs));
                }
            }

            // Handle other cheatcodes that don't need DB access
            let result = self.handle_cheatcode(&input_data).unwrap_or_else(|| {
                // Unknown cheatcode - log it and return empty success
                if input_data.len() >= 4 {
                    tracing::debug!(
                        "[CHEATCODE] Unknown selector: 0x{}",
                        hex::encode(&input_data[..4])
                    );
                }
                Bytes::new()
            });
            
            // Return success with the result - NEVER revert on HEVM calls
            // Use the incoming gas limit to properly track gas
            // IMPORTANT: Use return_memory_offset from inputs so the return data is written
            // to the correct location in the caller's memory
            return Some(CallOutcome {
                result: InterpreterResult {
                    result: InstructionResult::Return,
                    output: result,
                    gas: Gas::new(inputs.gas_limit),
                },
                memory_offset: inputs.return_memory_offset.clone(),
                precompile_call_logs: vec![],
                was_precompile_called: false,
                charged_new_account_state_gas: false,
            });
        }
        
        // Apply prank if set (modify the caller for the next call)
        // IMPORTANT: Prank only applies to calls where the current caller matches the prank origin
        // This ensures internal contract-to-contract calls are NOT affected
        // For example: TestContract calls startPrank(ADMIN), then calls Target
        // The Target call should have msg.sender=ADMIN
        // But if Target calls SubTarget, that should have msg.sender=Target (NOT ADMIN)
        
        let current_caller = inputs.caller;
        let transfers_value = inputs.transfers_value();
        
        // Debug: log call details when prank is active
        if self.state.start_prank_caller.is_some() || self.state.prank_caller.is_some() {
            tracing::debug!(
                "Call with prank active: target={:?}, caller={:?}, prank_origin={:?}, start_prank_caller={:?}, prank_caller={:?}, transfers_value={}",
                target, current_caller, self.state.prank_origin, self.state.start_prank_caller, self.state.prank_caller, transfers_value
            );
        }
        
        if !transfers_value {
            // Check for single-use prank first
            if let Some(prank_addr) = self.state.prank_caller.take() {
                // Single prank - always apply to the next call and clear
                inputs.caller = prank_addr;
                tracing::debug!("Applied single prank: caller changed from {:?} to {:?}", current_caller, prank_addr);
            } else if let Some(prank_addr) = self.state.start_prank_caller {
                // Persistent prank - only apply if caller matches the prank origin
                // prank_origin is set when startPrank is called to the address that called startPrank
                
                // Only apply prank if this call is from the original pranked context
                if self.state.prank_origin == Some(current_caller) {
                    inputs.caller = prank_addr;
                    tracing::debug!("Applied startPrank: caller changed from {:?} to {:?}", current_caller, prank_addr);
                } else {
                    tracing::debug!(
                        "Prank NOT applied: current_caller {:?} != prank_origin {:?}",
                        current_caller, self.state.prank_origin
                    );
                }
                // If caller doesn't match origin, this is an internal call - don't modify
            }
        } else {
            // Value transfer - consume single prank but don't apply it
            if self.state.prank_caller.is_some() {
                let _ = self.state.prank_caller.take();
                tracing::debug!("Prank skipped due to value transfer, prank consumed");
            }
        }
        
        None
    }

    fn call_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        // Cheap any-depth assertion-failure detection. Mirrors the equivalent
        // logic in CombinedInspector so callers that use only this inspector
        // (notably `EvmState::exec_tx`, hit by every shrink replay) still
        // observe nested `assert(false)` failures from sub-calls.
        use revm::interpreter::InstructionResult;
        match outcome.result.result {
            InstructionResult::Revert if !self.nested_panic_1 => {
                let out = &outcome.result.output;
                if out.len() >= 4 + 32 && out[..4] == PANIC_SELECTOR && out[4 + 31] == 1 {
                    self.nested_panic_1 = true;
                }
            }
            InstructionResult::InvalidFEOpcode | InstructionResult::OpcodeNotFound => {
                self.nested_invalid_fe = true;
            }
            _ => {}
        }
    }

    fn create(
        &mut self,
        _context: &mut CTX,
        inputs: &mut revm::interpreter::CreateInputs,
    ) -> Option<revm::interpreter::CreateOutcome> {
        // Apply prank to CREATE operations
        let current_caller = inputs.caller();

        // Check for single-use prank first
        if let Some(prank_addr) = self.state.prank_caller.take() {
            // Single prank - apply once and clear
            inputs.set_call(prank_addr);
            tracing::debug!("Applied single prank to CREATE: caller changed from {:?} to {:?}", current_caller, prank_addr);
        } else if let Some(prank_addr) = self.state.start_prank_caller {
            // Persistent prank - only apply if caller matches the prank origin
            // prank_origin is set when startPrank is called
            if self.state.prank_origin == Some(current_caller) {
                inputs.set_call(prank_addr);
                tracing::debug!("Applied startPrank to CREATE: caller changed from {:?} to {:?}", current_caller, prank_addr);
            }
        }

        None
    }
}

fn read_storage_via_journal<CTX: ContextTr>(context: &mut CTX, target: Address, slot: U256) -> U256 {
    use revm::context_interface::JournalTr;
    if context.journal_mut().load_account_mut(target).is_err() {
        return U256::ZERO;
    }
    let slot_revm = revm::primitives::U256::from_be_bytes(slot.to_be_bytes::<32>());
    context.journal_mut().sload(target, slot_revm)
        .map(|r| U256::from_be_bytes(r.data.to_be_bytes::<32>()))
        .unwrap_or(U256::ZERO)
}

fn write_storage_via_journal<CTX: ContextTr>(context: &mut CTX, target: Address, slot: U256, value: U256) {
    use revm::context_interface::JournalTr;
    if context.journal_mut().load_account_mut(target).is_err() {
        return;
    }
    let slot_revm = revm::primitives::U256::from_be_bytes(slot.to_be_bytes::<32>());
    let val_revm = revm::primitives::U256::from_be_bytes(value.to_be_bytes::<32>());
    let _ = context.journal_mut().sstore(target, slot_revm, val_revm);
}

/// Write a packed value into a storage slot: read the slot, mask out the old
/// bits at (offset, size), insert the new value, write back.
fn write_packed_via_journal<CTX: ContextTr>(
    context: &mut CTX, target: Address, slot: U256,
    offset: usize, size: usize, value: U256,
) {
    let raw = read_storage_via_journal(context, target, slot);
    let shift = offset * 8;
    let mask = if size >= 32 {
        U256::MAX
    } else {
        (U256::from(1) << (size * 8)) - U256::from(1)
    };
    // Clear the target bits, insert new value
    let cleared = raw & !(mask << shift);
    let new_val = cleared | ((value & mask) << shift);
    write_storage_via_journal(context, target, slot, new_val);
}

fn make_return(output: Vec<u8>, inputs: &CallInputs) -> CallOutcome {
    CallOutcome {
        result: InterpreterResult {
            result: InstructionResult::Return,
            output: Bytes::from(output),
            gas: Gas::new(inputs.gas_limit),
        },
        memory_offset: inputs.return_memory_offset.clone(),
        precompile_call_logs: vec![],
        was_precompile_called: false,
        charged_new_account_state_gas: false,
    }
}

/// Parse a layout string — tries JSON first, falls back to compact format.
fn parse_layout_string(input: &str) -> Result<StorageLayout, String> {
    let trimmed = input.trim();
    if trimmed.starts_with('{') {
        serde_json::from_str::<StorageLayout>(trimmed)
            .map_err(|e| format!("invalid JSON: {}", e))
    } else {
        storage_layout_compact::parse_compact(trimmed)
            .map_err(|e| format!("invalid compact format: {}", e))
    }
}

/// Compute ERC-7201 namespace base slot and offset all storage entries.
///
/// Base slot = `keccak256(abi.encode(uint256(keccak256(ns)) - 1)) & ~bytes32(uint256(0xff))`
///
/// Each storage entry's slot is offset by the base. The namespace name
/// becomes a prefix: entry "value" becomes "ns.value" so `loadVar` can
/// resolve "example.main.value".
fn apply_namespace(ns: &str, layout: StorageLayout) -> StorageLayout {
    use alloy_primitives::keccak256;

    let ns_hash = keccak256(ns.as_bytes());
    let ns_val = U256::from_be_bytes(ns_hash.0).wrapping_sub(U256::from(1));
    let encoded = ns_val.to_be_bytes::<32>();
    let slot_hash = keccak256(&encoded);
    let mut base_bytes = slot_hash.0;
    base_bytes[31] = 0;
    let base_slot = U256::from_be_bytes(base_bytes);

    // Create a synthetic struct type with the layout's storage entries as members.
    // The struct is placed at the ERC-7201 base slot. This way the path resolver
    // sees "example.main" as a top-level variable and ".value" as a struct member.
    let type_id = format!("t_ns_{}", ns.replace('.', "_"));
    let mut types = layout.types;

    // Compute total size from members
    let total_size: usize = layout.storage.iter().map(|e| {
        let ty = types.get(&e.type_id);
        let slot: usize = e.slot.parse().unwrap_or(0);
        let size: usize = ty.map(|t| t.number_of_bytes.parse().unwrap_or(32)).unwrap_or(32);
        slot * 32 + e.offset + size
    }).max().unwrap_or(32);
    let total_slots = (total_size + 31) / 32;

    types.insert(
        type_id.clone(),
        StorageType {
            encoding: "inplace".into(),
            label: format!("namespace {}", ns),
            number_of_bytes: (total_slots * 32).to_string(),
            key: None,
            value: None,
            base: None,
            members: Some(layout.storage),
        },
    );

    let storage = vec![StorageEntry {
        label: ns.to_string(),
        offset: 0,
        slot: base_slot.to_string(),
        type_id,
        contract: None,
    }];

    StorageLayout { storage, types }
}

/// Merge a namespace layout into the storage layouts map for a target address.
fn merge_namespace_layout(
    storage_layouts: &mut Arc<HashMap<Address, StorageLayout>>,
    target: Address,
    ns_layout: StorageLayout,
) {
    let layouts = Arc::make_mut(storage_layouts);
    let existing = layouts.entry(target).or_insert_with(|| {
        StorageLayout { storage: Vec::new(), types: std::collections::HashMap::new() }
    });
    for entry in ns_layout.storage {
        existing.storage.push(entry);
    }
    for (k, v) in ns_layout.types {
        existing.types.insert(k, v);
    }
}

/// Apply a manual base slot to a layout (no ERC-7201 computation).
/// The slot number from the layout entry becomes an offset label (e.g. "ns_0x1234").
fn apply_namespace_at(base_slot: U256, layout: StorageLayout) -> StorageLayout {
    let label = format!("ns_{:#x}", base_slot);

    let type_id = format!("t_ns_{}", label.replace('.', "_"));
    let mut types = layout.types;

    let total_size: usize = layout.storage.iter().map(|e| {
        let ty = types.get(&e.type_id);
        let slot: usize = e.slot.parse().unwrap_or(0);
        let size: usize = ty.map(|t| t.number_of_bytes.parse().unwrap_or(32)).unwrap_or(32);
        slot * 32 + e.offset + size
    }).max().unwrap_or(32);
    let total_slots = (total_size + 31) / 32;

    types.insert(
        type_id.clone(),
        StorageType {
            encoding: "inplace".into(),
            label: format!("namespace {}", label),
            number_of_bytes: (total_slots * 32).to_string(),
            key: None,
            value: None,
            base: None,
            members: Some(layout.storage),
        },
    );

    let storage = vec![StorageEntry {
        label,
        offset: 0,
        slot: base_slot.to_string(),
        type_id,
        contract: None,
    }];

    StorageLayout { storage, types }
}

/// Encode a bytes[] array for ABI return
fn encode_bytes_array(calls: &[Bytes]) -> Bytes {
    use alloy_dyn_abi::DynSolValue;

    // Convert to DynSolValue::Array of DynSolValue::Bytes
    let values: Vec<DynSolValue> = calls
        .iter()
        .map(|b| DynSolValue::Bytes(b.to_vec()))
        .collect();

    let array = DynSolValue::Array(values);
    Bytes::from(array.abi_encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hevm_address() {
        // Verify the HEVM address matches the expected value
        let expected = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d";
        assert_eq!(format!("{:?}", HEVM_ADDRESS), expected);
    }

    #[test]
    fn test_warp_selector() {
        // warp(uint256) selector
        let selector = warpCall::SELECTOR;
        assert_eq!(selector.len(), 4);
    }

    #[test]
    fn test_namespace_base_slot() {
        let layout = StorageLayout { storage: vec![], types: std::collections::HashMap::new() };
        let result = apply_namespace("example.main", layout);
        assert_eq!(result.storage.len(), 1);
        assert_eq!(result.storage[0].label, "example.main");
        let base: U256 = result.storage[0].slot.parse().unwrap();
        assert_eq!(
            format!("{:#066x}", base),
            "0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500"
        );
    }

    #[test]
    fn test_namespace_offsets_slots() {
        use crate::storage_layout_compact::parse_compact;
        let layout = parse_compact("uint256 value, address owner").unwrap();
        let result = apply_namespace("example.main", layout);
        // Single top-level entry for the namespace
        assert_eq!(result.storage.len(), 1);
        assert_eq!(result.storage[0].label, "example.main");
        // Base slot matches ERC-7201 computation
        let base_slot: U256 = result.storage[0].slot.parse().unwrap();
        assert_eq!(
            format!("{:#066x}", base_slot),
            "0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500"
        );
        // Resolve through the struct: "example.main.value" and "example.main.owner"
        let r_val = result.resolve("example.main.value", &[]).unwrap();
        assert_eq!(r_val.slot, base_slot);
        assert_eq!(r_val.size, 32);
        let r_own = result.resolve("example.main.owner", &[]).unwrap();
        assert_eq!(r_own.slot, base_slot + U256::from(1));
        assert_eq!(r_own.size, 20);
    }
}
