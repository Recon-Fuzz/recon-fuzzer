//! ABI decompiler using evmole for unverified contracts
//!
//! Extracts function selectors and argument types from EVM bytecode
//! when source code or verified ABI is unavailable.

use alloy_json_abi::{Function, JsonAbi, Param, StateMutability};
use evmole::{contract_info, ContractInfoArgs};
use serde::{Deserialize, Serialize};

/// Decompiled function information from bytecode analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    /// 4-byte function selector
    pub selector: [u8; 4],
    /// Hex-encoded selector (used as function name when unknown)
    pub selector_hex: String,
    /// Solidity-style argument signature, e.g., "(uint256,address)"
    pub arguments: String,
    /// Whether the function is marked as view/pure (non-state-changing)
    pub is_view: bool,
    /// Whether the function is payable
    pub is_payable: bool,
}

impl DecompiledFunction {
    /// Returns the full signature string, e.g., "a9059cbb(address,uint256)"
    pub fn signature(&self) -> String {
        format!("{}{}", self.selector_hex, self.arguments)
    }
}

/// Result of ABI decompilation
#[derive(Debug, Clone, Default)]
pub struct DecompiledAbi {
    /// List of decompiled functions
    pub functions: Vec<DecompiledFunction>,
}

impl DecompiledAbi {
    /// Convert to alloy JsonAbi format for compatibility with existing code
    pub fn to_json_abi(&self) -> JsonAbi {
        let mut abi = JsonAbi::new();

        for func in &self.functions {
            // Parse arguments string to create Param list
            let inputs = parse_arguments_to_params(&func.arguments);

            let state_mutability = if func.is_payable {
                StateMutability::Payable
            } else if func.is_view {
                StateMutability::View
            } else {
                StateMutability::NonPayable
            };

            let function = Function {
                name: format!("func_{}", func.selector_hex),
                inputs,
                outputs: vec![], // Unknown from bytecode analysis
                state_mutability,
            };

            abi.functions
                .entry(function.name.clone())
                .or_default()
                .push(function);
        }

        abi
    }

    /// Check if the decompiled ABI is empty
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Get function by selector
    pub fn get_function(&self, selector: &[u8; 4]) -> Option<&DecompiledFunction> {
        self.functions.iter().find(|f| &f.selector == selector)
    }
}

/// Decompile ABI from EVM bytecode using evmole
///
/// # Arguments
/// * `bytecode` - The deployed contract bytecode (not creation code)
///
/// # Returns
/// Decompiled ABI information including function selectors and argument types
pub fn decompile_abi(bytecode: &[u8]) -> DecompiledAbi {
    if bytecode.is_empty() {
        return DecompiledAbi::default();
    }

    // Use evmole to analyze the bytecode
    let args = ContractInfoArgs::new(bytecode)
        .with_selectors()
        .with_arguments();

    let contract = contract_info(args);

    let functions = contract
        .functions
        .unwrap_or_default()
        .into_iter()
        .map(|func| {
            let selector: [u8; 4] = func.selector;
            let selector_hex = hex::encode(selector);

            // Format arguments as Solidity-style signature
            let arguments = if let Some(args) = func.arguments {
                format!(
                    "({})",
                    args.iter()
                        .map(|arg| arg.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            } else {
                "()".to_string()
            };

            // Determine state mutability
            let (is_view, is_payable) = match func.state_mutability {
                Some(evmole::StateMutability::Pure) | Some(evmole::StateMutability::View) => {
                    (true, false)
                }
                Some(evmole::StateMutability::Payable) => (false, true),
                Some(evmole::StateMutability::NonPayable) | None => (false, false),
            };

            DecompiledFunction {
                selector,
                selector_hex,
                arguments,
                is_view,
                is_payable,
            }
        })
        .collect();

    DecompiledAbi { functions }
}

/// Parse a Solidity-style argument string into Param list
/// e.g., "(uint256,address)" -> [Param { ty: "uint256", .. }, Param { ty: "address", .. }]
fn parse_arguments_to_params(args: &str) -> Vec<Param> {
    let trimmed = args.trim_start_matches('(').trim_end_matches(')');
    if trimmed.is_empty() {
        return vec![];
    }

    trimmed
        .split(',')
        .enumerate()
        .map(|(i, ty)| Param {
            name: format!("arg{}", i),
            ty: ty.trim().to_string(),
            components: vec![],
            internal_type: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_empty_bytecode() {
        let result = decompile_abi(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_decompile_erc20_bytecode() {
        // Minimal ERC20-like bytecode with transfer function
        // This is a simplified test - real bytecode would be much larger
        let bytecode = hex::decode(
            "608060405234801561001057600080fd5b506004361061002b5760003560e01c8063a9059cbb14610030575b600080fd5b61004a600480360381019061004591906100b4565b610060565b60405161005791906100ff565b60405180910390f35b6000600190509392505050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061009d82610072565b9050919050565b6100ad81610092565b81146100b857600080fd5b50565b6000813590506100ca816100a4565b92915050565b6000819050919050565b6100e3816100d0565b81146100ee57600080fd5b50565b600081359050610100816100da565b92915050565b6000806040838503121561011d5761011c61006d565b5b600061012b858286016100bb565b925050602061013c858286016100f1565b9150509250929050565b60008115159050919050565b61015b81610146565b82525050565b60006020820190506101766000830184610152565b9291505056"
        ).unwrap();

        let result = decompile_abi(&bytecode);

        // Should find the transfer function selector (a9059cbb)
        assert!(!result.is_empty());
        let transfer = result.get_function(&[0xa9, 0x05, 0x9c, 0xbb]);
        assert!(transfer.is_some());
    }

    #[test]
    fn test_parse_arguments() {
        let params = parse_arguments_to_params("(uint256,address,bool)");
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].ty, "uint256");
        assert_eq!(params[1].ty, "address");
        assert_eq!(params[2].ty, "bool");
    }

    #[test]
    fn test_parse_empty_arguments() {
        let params = parse_arguments_to_params("()");
        assert!(params.is_empty());
    }

    #[test]
    fn test_decompiled_function_signature() {
        let func = DecompiledFunction {
            selector: [0xa9, 0x05, 0x9c, 0xbb],
            selector_hex: "a9059cbb".to_string(),
            arguments: "(address,uint256)".to_string(),
            is_view: false,
            is_payable: false,
        };
        assert_eq!(func.signature(), "a9059cbb(address,uint256)");
    }

    #[test]
    fn test_to_json_abi() {
        let decompiled = DecompiledAbi {
            functions: vec![DecompiledFunction {
                selector: [0xa9, 0x05, 0x9c, 0xbb],
                selector_hex: "a9059cbb".to_string(),
                arguments: "(address,uint256)".to_string(),
                is_view: false,
                is_payable: false,
            }],
        };

        let json_abi = decompiled.to_json_abi();
        assert_eq!(json_abi.functions.len(), 1);
        assert!(json_abi.functions.contains_key("func_a9059cbb"));
    }
}
