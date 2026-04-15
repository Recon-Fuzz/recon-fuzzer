//! HEVM Cheatcode support for browser-fuzzer
//!
//! Implements common cheatcodes from foundry/HEVM for testing
//! Cheatcode address: 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D
//!
//! This is identical to evm/src/cheatcodes.rs except:
//! - HEVM_ADDRESS defined inline (no primitives crate)
//! - generateCalls returns empty array (no abi crate)

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use revm::{
    context_interface::ContextTr,
    interpreter::{
        interpreter_types::{InterpreterTypes, Jumps, LegacyBytecode, StackTr},
        CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    Inspector,
};
use revm::context_interface::journaled_state::account::JournaledAccountTr;
use std::collections::HashMap;

/// Foundry/HEVM cheatcode address
pub const HEVM_ADDRESS: Address = Address::new([
    0x71, 0x09, 0x70, 0x9E, 0xCf, 0xa9, 0x1a, 0x80, 0x62, 0x6f, 0xF3, 0x98, 0x9D, 0x68, 0xf6,
    0x7F, 0x5b, 0x1D, 0xD1, 0x2D,
]);

// Define cheatcode function selectors using alloy_sol_types
sol! {
    function warp(uint256 newTimestamp) external;
    function roll(uint256 newNumber) external;
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
    function getNonce(address account) external returns (uint64);
    function setNonce(address account, uint64 newNonce) external;
    /// Generate random calls for reentrancy testing
    /// Returns an array of calldata that can be executed via address(this).call()
    function generateCalls(uint256 count) external returns (bytes[] memory);
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
}

/// TIMESTAMP opcode (0x42) - returns block.timestamp
const OP_TIMESTAMP: u8 = 0x42;
/// NUMBER opcode (0x43) - returns block.number
const OP_NUMBER: u8 = 0x43;

impl CheatcodeInspector {
    pub fn new() -> Self {
        Self {
            state: CheatcodeState::new(),
            last_opcode: 0,
        }
    }

    /// Track opcode in step() for warp/roll override in step_end()
    pub fn track_opcode(&mut self, opcode: u8) {
        self.last_opcode = opcode;
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

        // assume(bool)
        if selector == assumeCall::SELECTOR {
            if let Ok(decoded) = assumeCall::abi_decode(input) {
                if !decoded.condition {
                    self.state.assume_failed = true;
                }
                return Some(Bytes::new());
            }
        }

        // deal(address, uint256) - Note: actual balance modification happens in Inspector::call
        if selector == dealCall::SELECTOR {
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
            return Some(Bytes::new());
        }

        // stopPrank() - handled in Inspector::call for proper state clearing
        // This is a fallback that shouldn't normally be hit
        if selector == stopPrankCall::SELECTOR {
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
        // For now, return zeros - proper implementation needs DB access
        if selector == loadCall::SELECTOR {
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
                let pk_bytes = decoded.privateKey.to_be_bytes::<32>();

                if let Ok(signing_key) = k256::ecdsa::SigningKey::from_bytes((&pk_bytes).into()) {
                    let verifying_key = signing_key.verifying_key();
                    let public_key_bytes = verifying_key.to_encoded_point(false);
                    let hash = alloy_primitives::keccak256(&public_key_bytes.as_bytes()[1..]);
                    let addr = Address::from_slice(&hash[12..]);
                    let mut result = [0u8; 32];
                    result[12..].copy_from_slice(addr.as_slice());
                    return Some(Bytes::from(result.to_vec()));
                } else {
                    return Some(Bytes::from(vec![0u8; 32]));
                }
            }
        }

        // sign(uint256, bytes32) - sign digest with private key
        if selector == signCall::SELECTOR {
            if let Ok(decoded) = signCall::abi_decode(input) {
                let pk_bytes = decoded.privateKey.to_be_bytes::<32>();
                if let Ok(signing_key) = k256::ecdsa::SigningKey::from_bytes((&pk_bytes).into()) {
                    use k256::ecdsa::signature::hazmat::PrehashSigner;
                    if let Ok((sig, recid)) = signing_key.sign_prehash(decoded.digest.as_slice()) {
                        let sig_bytes = sig.to_bytes();
                        let v = recid.to_byte() + 27;
                        let mut result = vec![0u8; 96];
                        result[31] = v;
                        result[32..64].copy_from_slice(&sig_bytes[..32]); // r
                        result[64..96].copy_from_slice(&sig_bytes[32..64]); // s
                        return Some(Bytes::from(result));
                    }
                }
                return Some(Bytes::from(vec![0u8; 96]));
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
        if self.last_opcode == OP_TIMESTAMP {
            if let Some(warped) = self.state.warp_timestamp {
                if interp.stack.pop().is_some() {
                    let _ = interp.stack.push(warped);
                    tracing::trace!("Warp: Overrode TIMESTAMP with {:?}", warped);
                }
            }
        }

        // Handle vm.roll() - override NUMBER opcode result
        if self.last_opcode == OP_NUMBER {
            if let Some(rolled) = self.state.roll_block {
                if interp.stack.pop().is_some() {
                    let _ = interp.stack.push(rolled);
                    tracing::trace!("Roll: Overrode NUMBER with {:?}", rolled);
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
                    if let Ok(mut account_load) = context.journal_mut().load_account_mut(decoded.who) {
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
                    let _ = context.journal_mut().load_account_mut(decoded.target);

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

            // Handle getNonce(address) - requires DB access
            if input_data.len() >= 4 && &input_data[..4] == getNonceCall::SELECTOR {
                if let Ok(decoded) = getNonceCall::abi_decode(&input_data) {
                    use revm::context_interface::journaled_state::account::JournaledAccountTr as _;
                    let nonce = if let Ok(account_load) =
                        context.journal_mut().load_account_mut(decoded.account)
                    {
                        account_load.data.nonce()
                    } else {
                        0
                    };
                    let mut output = vec![0u8; 32];
                    output[24..32].copy_from_slice(&nonce.to_be_bytes());
                    return Some(CallOutcome {
                        result: InterpreterResult {
                            result: InstructionResult::Return,
                            output: Bytes::from(output),
                            gas: Gas::new(inputs.gas_limit),
                        },
                        memory_offset: inputs.return_memory_offset.clone(),
                        precompile_call_logs: vec![],
                        was_precompile_called: false,
                    });
                }
            }

            // Handle setNonce(address, uint64) - requires DB access
            if input_data.len() >= 4 && &input_data[..4] == setNonceCall::SELECTOR {
                if let Ok(decoded) = setNonceCall::abi_decode(&input_data) {
                    use revm::context_interface::journaled_state::account::JournaledAccountTr as _;
                    if let Ok(mut account_load) =
                        context.journal_mut().load_account_mut(decoded.account)
                    {
                        account_load.data.set_nonce(decoded.newNonce);
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

            // Handle generateCalls(uint256 count) - returns empty array (no abi crate in WASM)
            if input_data.len() >= 4 && &input_data[..4] == generateCallsCall::SELECTOR {
                return Some(CallOutcome {
                    result: InterpreterResult {
                        result: InstructionResult::Return,
                        output: encode_bytes_array(&[]),
                        gas: Gas::new(inputs.gas_limit),
                    },
                    memory_offset: inputs.return_memory_offset.clone(),
                    precompile_call_logs: vec![],
                    was_precompile_called: false,
                });
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
                if self.state.prank_origin == Some(current_caller) {
                    inputs.caller = prank_addr;
                    tracing::debug!("Applied startPrank: caller changed from {:?} to {:?}", current_caller, prank_addr);
                } else {
                    tracing::debug!(
                        "Prank NOT applied: current_caller {:?} != prank_origin {:?}",
                        current_caller, self.state.prank_origin
                    );
                }
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
            inputs.set_call(prank_addr);
            tracing::debug!("Applied single prank to CREATE: caller changed from {:?} to {:?}", current_caller, prank_addr);
        } else if let Some(prank_addr) = self.state.start_prank_caller {
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

    let values: Vec<DynSolValue> = calls
        .iter()
        .map(|b| DynSolValue::Bytes(b.to_vec()))
        .collect();

    let array = DynSolValue::Array(values);
    Bytes::from(array.abi_encode())
}
