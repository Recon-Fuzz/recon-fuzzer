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
    function load(address target, bytes32 slot) external returns (bytes32);
    function etch(address target, bytes code) external;
    function label(address account, string memory newLabel) external;
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    /// Generate random calls for reentrancy testing
    /// Returns an array of calldata that can be executed via address(this).call()
    function generateCalls(uint256 count) external returns (bytes[] memory);
}

/// Context for generating calls via vm.generateCalls()
/// Set before tx execution by the campaign layer.
///
/// `gen_dict` is wrapped in `Arc` so propagating the context through the
/// per-sequence and per-tx wiring is a refcount bump instead of a deep
/// clone of the entire dictionary (which holds large `whole_calls` /
/// `dict_values` collections that grow over the lifetime of the run).
#[derive(Debug, Clone)]
pub struct GenerateCallsContext {
    /// Fuzzable function metadata: (selector, name, param_types)
    pub fuzzable_functions: Vec<(alloy_primitives::FixedBytes<4>, String, Vec<alloy_dyn_abi::DynSolType>)>,
    /// Generation dictionary (same as main fuzzer). Read-only at runtime —
    /// the cheatcode never mutates it, so sharing via `Arc` is safe.
    pub gen_dict: std::sync::Arc<abi::types::GenDict>,
    /// RNG seed for reproducibility
    pub rng_seed: u64,
    /// Call counter for incrementing seed
    pub call_count: usize,
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
}

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
        }
    }

    /// Track opcode in step() for warp/roll override in step_end()
    pub fn track_opcode(&mut self, opcode: u8) {
        self.last_opcode = opcode;
    }

    /// Generate calldatas for vm.generateCalls(count)
    /// Returns ABI-encoded bytes[] (array of calldata)
    ///
    /// Uses gen_abi_call_m directly - identical to main fuzzer behavior
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

        // Use seeded RNG - increment seed each call for different values
        let seed = ctx.rng_seed.wrapping_add(ctx.call_count as u64);
        ctx.call_count += count;
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        let mut calls = Vec::with_capacity(count);
        for _ in 0..count {
            // Pick a random function (same as gen_tx)
            let idx = rng.gen_range(0..ctx.fuzzable_functions.len());
            let (selector, name, param_types) = &ctx.fuzzable_functions[idx];

            // Generate call using gen_abi_call_m (identical to main fuzzer)
            let (_name, args) = abi::r#gen::gen_abi_call_m(&mut rng, &ctx.gen_dict, name, param_types);

            // Encode to calldata: selector + ABI-encoded args
            let encoded_args = DynSolValue::Tuple(args).abi_encode();
            let mut calldata = selector.to_vec();
            calldata.extend(encoded_args);

            calls.push(Bytes::from(calldata));
        }

        tracing::trace!(
            "vm.generateCalls: generated {} calls (seed={})",
            calls.len(),
            seed
        );
        encode_bytes_array(&calls)
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

        // store(address, bytes32, bytes32)
        if selector == storeCall::SELECTOR {
            if let Ok(decoded) = storeCall::abi_decode(input) {
                self.state
                    .stores
                    .push((decoded.target, decoded.slot, decoded.value));
                return Some(Bytes::new());
            }
        }

        // load(address, bytes32) - returns bytes32
        // This is tricky because we need to actually read from storage
        // For now, return zeros - proper implementation needs DB access
        if selector == loadCall::SELECTOR {
            // Return 32 zero bytes
            return Some(Bytes::from(vec![0u8; 32]));
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
                    });
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

}
