//! Tracing Inspector for LLM-guided fuzzing
//!
//! Captures detailed execution traces including:
//! - PC, opcode, gas at each step
//! - Branch outcomes
//! - Storage reads/writes
//!
//! This is separate from CoverageInspector for performance reasons -
//! only used during LLM exploration, not during normal fuzzing.

use alloy_primitives::{B256, U256};
use revm::{
    context_interface::ContextTr,
    interpreter::interpreter_types::{InputsTr, InterpreterTypes, Jumps, LegacyBytecode},
    interpreter::{CallInputs, CallOutcome, InstructionResult, Interpreter},
    Inspector,
};
use std::collections::HashMap;

use crate::coverage::{compute_metadata_hash, CombinedInspector, MetadataToCodehash};

/// A single execution step in the trace
#[derive(Debug, Clone)]
pub struct TraceStep {
    /// Contract codehash being executed
    pub codehash: B256,
    /// Program counter
    pub pc: usize,
    /// Opcode byte
    pub opcode: u8,
    /// Opcode name (e.g., "JUMPI", "SSTORE")
    pub opcode_name: String,
    /// Gas remaining before this step
    pub gas_remaining: u64,
    /// For JUMPI: whether the jump was taken
    pub jump_taken: Option<bool>,
    /// For SLOAD/SSTORE: the slot
    pub storage_slot: Option<U256>,
    /// For SLOAD: the value loaded
    pub storage_value: Option<U256>,
    /// Call depth
    pub depth: u32,
}

/// Execution trace for a transaction
#[derive(Debug, Clone, Default)]
pub struct ExecutionTrace {
    /// All execution steps
    pub steps: Vec<TraceStep>,
    /// Branch outcomes: (codehash, pc) -> taken/not_taken count
    pub branches: HashMap<(B256, usize), (u32, u32)>,
    /// Final execution result
    pub result: Option<InstructionResult>,
    /// Revert reason if any
    pub revert_reason: Option<String>,
}

impl ExecutionTrace {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a condensed summary for LLM context
    pub fn summary(&self, max_steps: usize) -> String {
        let mut output = String::new();

        // Show last N steps leading to result
        let start = self.steps.len().saturating_sub(max_steps);
        for step in &self.steps[start..] {
            output.push_str(&format!("PC 0x{:x}: {} ", step.pc, step.opcode_name));

            if let Some(taken) = step.jump_taken {
                output.push_str(&format!(
                    "[branch: {}] ",
                    if taken { "TAKEN" } else { "NOT TAKEN" }
                ));
            }
            output.push('\n');
        }

        if let Some(result) = &self.result {
            output.push_str(&format!("\nResult: {:?}\n", result));
        }

        if let Some(reason) = &self.revert_reason {
            output.push_str(&format!("Revert: {}\n", reason));
        }

        output
    }
}

/// Inspector that captures detailed execution traces for LLM analysis
#[derive(Debug, Clone)]
pub struct TracingInspector {
    /// Base inspector for coverage + cheatcodes
    pub base: CombinedInspector,
    /// Current trace being built
    pub trace: ExecutionTrace,
    /// Maximum steps to record (to avoid memory issues)
    pub max_steps: usize,
    /// Current call depth
    depth: u32,
}

impl Default for TracingInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingInspector {
    pub fn new() -> Self {
        Self {
            base: CombinedInspector::new(),
            trace: ExecutionTrace::new(),
            max_steps: 10000,
            depth: 0,
        }
    }

    /// Create with a shared metadata-to-codehash map
    pub fn with_codehash_map(
        metadata_to_codehash: std::sync::Arc<parking_lot::RwLock<MetadataToCodehash>>,
    ) -> Self {
        Self {
            base: CombinedInspector::with_codehash_map(metadata_to_codehash),
            trace: ExecutionTrace::new(),
            max_steps: 10000,
            depth: 0,
        }
    }

    /// Reset trace for new transaction
    pub fn reset_trace(&mut self) {
        self.trace = ExecutionTrace::new();
        self.depth = 0;
    }

    /// Take the trace (moves ownership)
    pub fn take_trace(&mut self) -> ExecutionTrace {
        std::mem::take(&mut self.trace)
    }

    /// Get opcode name from byte
    fn opcode_name(opcode: u8) -> &'static str {
        match opcode {
            0x00 => "STOP",
            0x01 => "ADD",
            0x02 => "MUL",
            0x03 => "SUB",
            0x04 => "DIV",
            0x05 => "SDIV",
            0x06 => "MOD",
            0x07 => "SMOD",
            0x08 => "ADDMOD",
            0x09 => "MULMOD",
            0x0a => "EXP",
            0x0b => "SIGNEXTEND",
            0x10 => "LT",
            0x11 => "GT",
            0x12 => "SLT",
            0x13 => "SGT",
            0x14 => "EQ",
            0x15 => "ISZERO",
            0x16 => "AND",
            0x17 => "OR",
            0x18 => "XOR",
            0x19 => "NOT",
            0x1a => "BYTE",
            0x1b => "SHL",
            0x1c => "SHR",
            0x1d => "SAR",
            0x20 => "SHA3",
            0x30 => "ADDRESS",
            0x31 => "BALANCE",
            0x32 => "ORIGIN",
            0x33 => "CALLER",
            0x34 => "CALLVALUE",
            0x35 => "CALLDATALOAD",
            0x36 => "CALLDATASIZE",
            0x37 => "CALLDATACOPY",
            0x38 => "CODESIZE",
            0x39 => "CODECOPY",
            0x3a => "GASPRICE",
            0x3b => "EXTCODESIZE",
            0x3c => "EXTCODECOPY",
            0x3d => "RETURNDATASIZE",
            0x3e => "RETURNDATACOPY",
            0x3f => "EXTCODEHASH",
            0x40 => "BLOCKHASH",
            0x41 => "COINBASE",
            0x42 => "TIMESTAMP",
            0x43 => "NUMBER",
            0x44 => "DIFFICULTY",
            0x45 => "GASLIMIT",
            0x46 => "CHAINID",
            0x47 => "SELFBALANCE",
            0x48 => "BASEFEE",
            0x50 => "POP",
            0x51 => "MLOAD",
            0x52 => "MSTORE",
            0x53 => "MSTORE8",
            0x54 => "SLOAD",
            0x55 => "SSTORE",
            0x56 => "JUMP",
            0x57 => "JUMPI",
            0x58 => "PC",
            0x59 => "MSIZE",
            0x5a => "GAS",
            0x5b => "JUMPDEST",
            0x5f => "PUSH0",
            0x60..=0x7f => "PUSH",
            0x80..=0x8f => "DUP",
            0x90..=0x9f => "SWAP",
            0xa0..=0xa4 => "LOG",
            0xf0 => "CREATE",
            0xf1 => "CALL",
            0xf2 => "CALLCODE",
            0xf3 => "RETURN",
            0xf4 => "DELEGATECALL",
            0xf5 => "CREATE2",
            0xfa => "STATICCALL",
            0xfd => "REVERT",
            0xfe => "INVALID",
            0xff => "SELFDESTRUCT",
            _ => "UNKNOWN",
        }
    }
}

impl<CTX: ContextTr, INTR: InterpreterTypes> Inspector<CTX, INTR> for TracingInspector {
    fn step(&mut self, interp: &mut Interpreter<INTR>, context: &mut CTX) {
        // Delegate to base for coverage tracking
        self.base.step(interp, context);

        // Skip if we've recorded too many steps
        if self.trace.steps.len() >= self.max_steps {
            return;
        }

        let pc = interp.bytecode.pc();
        let _contract_addr = interp.input.target_address();

        // Get bytecode slice to read opcode
        let bytecode = interp.bytecode.bytecode_slice();
        let opcode = if pc < bytecode.len() { bytecode[pc] } else { 0 };

        // Get codehash - use the ptr cache that base.step() already populated
        // This avoids expensive compute_metadata_hash on every step
        let bytecode_ptr = bytecode.as_ptr() as usize;
        let bytecode_len = bytecode.len();
        let ptr_key = (bytecode_ptr, bytecode_len);

        let codehash = self
            .base
            .bytecode_ptr_cache
            .get(&ptr_key)
            .cloned()
            .unwrap_or_else(|| {
                // Fallback: compute hash (shouldn't happen since base.step() runs first)
                compute_metadata_hash(bytecode)
            });

        // Branch info simplified - would need concrete stack type access for full implementation
        let jump_taken = if opcode == 0x57 {
            // JUMPI - we can't easily access stack values with generic INTR
            None
        } else {
            None
        };

        // Record step (without full stack introspection)
        self.trace.steps.push(TraceStep {
            codehash,
            pc,
            opcode,
            opcode_name: Self::opcode_name(opcode).to_string(),
            gas_remaining: interp.gas.remaining(),
            jump_taken,
            storage_slot: None,
            storage_value: None,
            depth: self.depth,
        });
    }

    fn call(&mut self, _context: &mut CTX, _inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.depth += 1;
        // Note: Cheatcode handling is in CombinedInspector
        // For tracing, we just track depth. Cheatcodes will be handled when
        // we use TracingInspector in an exec context with cheatcode support.
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        self.depth = self.depth.saturating_sub(1);

        // Record final result
        if self.depth == 0 {
            self.trace.result = Some(outcome.result.result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_names() {
        assert_eq!(TracingInspector::opcode_name(0x57), "JUMPI");
        assert_eq!(TracingInspector::opcode_name(0x54), "SLOAD");
        assert_eq!(TracingInspector::opcode_name(0x14), "EQ");
    }

    #[test]
    fn test_trace_summary() {
        let mut trace = ExecutionTrace::new();
        trace.steps.push(TraceStep {
            codehash: B256::ZERO,
            pc: 0x100,
            opcode: 0x57,
            opcode_name: "JUMPI".to_string(),
            gas_remaining: 1000,
            jump_taken: Some(false),
            storage_slot: None,
            storage_value: None,
            depth: 0,
        });
        trace.result = Some(InstructionResult::Revert);

        let summary = trace.summary(10);
        assert!(summary.contains("JUMPI"));
        assert!(summary.contains("NOT TAKEN"));
        assert!(summary.contains("Revert"));
    }
}
