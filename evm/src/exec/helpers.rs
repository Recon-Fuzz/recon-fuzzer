//! Helper functions for EVM execution
//!
//! Contains utility functions for result classification and calldata encoding.

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::Bytes;
use revm::context_interface::result::{ExecutionResult, HaltReason, Output};

use crate::types::TxResult;

use super::ExecError;

/// Classify REVM execution result into our TxResult
pub fn classify_execution_result(result: &ExecutionResult) -> TxResult {
    match result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                if data.len() >= 32 {
                    let last_byte = data[31];
                    if last_byte == 1 {
                        TxResult::ReturnTrue
                    } else if last_byte == 0 {
                        TxResult::ReturnFalse
                    } else {
                        TxResult::Stop
                    }
                } else {
                    TxResult::Stop
                }
            }
            Output::Create(_, addr) => {
                if addr.is_some() {
                    TxResult::Stop
                } else {
                    TxResult::ErrorRevert
                }
            }
        },
        ExecutionResult::Revert { .. } => TxResult::ErrorRevert,
        ExecutionResult::Halt { reason, .. } => match reason {
            HaltReason::OutOfGas(_) => TxResult::ErrorOutOfGas,
            HaltReason::OpcodeNotFound | HaltReason::InvalidFEOpcode => {
                TxResult::ErrorAssertionFailed
            }
            _ => TxResult::ErrorRevert,
        },
    }
}

/// Encode a function call to calldata
pub fn encode_call(name: &str, args: &[DynSolValue]) -> Result<Bytes, ExecError> {
    let param_types: Vec<_> = args.iter().filter_map(|a| a.sol_type_name()).collect();
    let sig = format!("{}({})", name, param_types.join(","));
    let selector = alloy_primitives::keccak256(sig.as_bytes());
    let selector_bytes = &selector[..4];

    tracing::trace!(
        "encode_call: name={}, sig={}, selector=0x{}",
        name,
        sig,
        hex::encode(selector_bytes)
    );

    let encoded_args = if args.is_empty() {
        vec![]
    } else {
        let tuple = DynSolValue::Tuple(args.to_vec());
        tuple.abi_encode_params()
    };

    let mut calldata = Vec::with_capacity(4 + encoded_args.len());
    calldata.extend_from_slice(selector_bytes);
    calldata.extend_from_slice(&encoded_args);

    Ok(Bytes::from(calldata))
}
