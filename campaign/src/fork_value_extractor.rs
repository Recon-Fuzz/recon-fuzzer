//! Fork value extractor
//!
//! Extracts return values and event data from external contract calls
//! using the ABI decompiler for unverified contracts.
//!
//! This enables the fuzzer to learn values from forked mainnet contracts
//! like pool.totalSupply(), pool.reserve(), etc.

use alloy_primitives::{Address, U256, B256};
use evm::{fork::{DecompiledAbi, decompile_abi}, tracing::CallTraceArena};
use std::collections::HashMap;
use tracing::{debug, trace};

/// Cache of decompiled ABIs for external contracts
/// Key: contract address
/// Value: decompiled ABI info
#[derive(Debug, Default)]
pub struct ForkAbiCache {
    /// Decompiled ABIs by address
    abis: HashMap<Address, DecompiledAbi>,
    /// Bytecode hashes we've already processed (to avoid re-decompiling)
    processed_codehashes: HashMap<B256, DecompiledAbi>,
}

impl ForkAbiCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create decompiled ABI for an address
    pub fn get_or_decompile(&mut self, address: Address, bytecode: &[u8]) -> &DecompiledAbi {
        // Check if we already have it by address
        if self.abis.contains_key(&address) {
            return self.abis.get(&address).unwrap();
        }

        // Check by codehash to reuse decompilation across proxy patterns
        let codehash = B256::from(alloy_primitives::keccak256(bytecode));
        if let Some(abi) = self.processed_codehashes.get(&codehash) {
            self.abis.insert(address, abi.clone());
            return self.abis.get(&address).unwrap();
        }

        // Decompile the bytecode
        debug!(
            "[ForkValueExtractor] Decompiling ABI for {:?} ({} bytes)",
            address,
            bytecode.len()
        );
        let decompiled = decompile_abi(bytecode);
        debug!(
            "[ForkValueExtractor] Found {} functions in {:?}",
            decompiled.functions.len(),
            address
        );

        // Cache both by address and codehash
        self.processed_codehashes.insert(codehash, decompiled.clone());
        self.abis.insert(address, decompiled);
        self.abis.get(&address).unwrap()
    }

    /// Get cached ABI for an address (if already decompiled)
    pub fn get(&self, address: &Address) -> Option<&DecompiledAbi> {
        self.abis.get(address)
    }
}

/// Extract U256 values from external call return data
///
/// This function:
/// 1. Gets the decompiled ABI for the target contract
/// 2. Looks up the function by selector
/// 3. Decodes the return value based on decompiled argument types
/// 4. Extracts numeric values for the fuzzing dictionary
pub fn extract_values_from_call_traces(
    traces: &CallTraceArena,
    abi_cache: &mut ForkAbiCache,
    get_bytecode: impl Fn(Address) -> Option<Vec<u8>>,
) -> Vec<U256> {
    let mut values = Vec::new();

    for node in traces.nodes() {
        let call_trace = &node.trace;

        // Skip top-level call and CREATE calls
        if call_trace.depth == 0 || call_trace.kind.is_any_create() {
            continue;
        }

        // Only process successful calls with return data
        if !call_trace.success || call_trace.output.is_empty() {
            continue;
        }

        // Need at least 4 bytes for selector
        if call_trace.data.len() < 4 {
            continue;
        }

        let target = call_trace.address;
        let selector: [u8; 4] = call_trace.data[0..4].try_into().unwrap_or([0; 4]);

        // Get bytecode for the target contract
        let bytecode = match get_bytecode(target) {
            Some(bc) if !bc.is_empty() => bc,
            _ => continue,
        };

        // Get or create decompiled ABI
        let abi = abi_cache.get_or_decompile(target, &bytecode);

        // Find the function by selector
        if let Some(func) = abi.get_function(&selector) {
            // Try to decode the return value
            if let Some(decoded_values) = decode_return_data(&func.arguments, &call_trace.output) {
                trace!(
                    "[ForkValueExtractor] Decoded {:?} return for {:?}: {} values",
                    hex::encode(selector),
                    target,
                    decoded_values.len()
                );
                values.extend(decoded_values);
            }
        } else {
            // Even without ABI, try to extract raw values from return data
            // Many simple getters return a single uint256
            if call_trace.output.len() == 32 {
                let val = U256::from_be_slice(&call_trace.output);
                trace!(
                    "[ForkValueExtractor] Extracted raw U256 from {:?} call to {:?}: {}",
                    hex::encode(selector),
                    target,
                    val
                );
                values.push(val);
            }
        }
    }

    values
}

/// Decode return data based on decompiled argument signature
///
/// The evmole decompiler gives us argument types like "(uint256,address)"
/// We can use similar logic to infer return types for simple cases.
fn decode_return_data(args_signature: &str, output: &[u8]) -> Option<Vec<U256>> {
    // For simple single-value returns, extract directly
    if output.len() == 32 {
        return Some(vec![U256::from_be_slice(output)]);
    }

    // For multi-word returns, try to extract as multiple uint256
    if output.len() % 32 == 0 && output.len() <= 256 {
        let mut values = Vec::new();
        for chunk in output.chunks(32) {
            values.push(U256::from_be_slice(chunk));
        }
        return Some(values);
    }

    // Try to parse the argument signature to infer return type
    // Note: evmole gives us input args, not outputs, but many functions
    // have outputs that match a common pattern
    let trimmed = args_signature.trim_start_matches('(').trim_end_matches(')');
    if trimmed.is_empty() {
        // No args function - might return uint256
        if output.len() == 32 {
            return Some(vec![U256::from_be_slice(output)]);
        }
    }

    None
}

/// Extract values from event logs in traces
pub fn extract_values_from_events(traces: &CallTraceArena) -> Vec<U256> {
    let mut values = Vec::new();

    for node in traces.nodes() {
        // Extract values from event topics and data
        for log in &node.logs {
            // Topics (indexed parameters) - each is 32 bytes
            for topic in log.raw_log.topics() {
                // Skip topic0 (event signature)
                values.push(U256::from_be_slice(topic.as_slice()));
            }

            // Data (non-indexed parameters)
            let data = log.raw_log.data.as_ref();
            if data.len() % 32 == 0 {
                for chunk in data.chunks(32) {
                    values.push(U256::from_be_slice(chunk));
                }
            }
        }
    }

    values
}

/// Combined extraction from traces
pub fn extract_all_values_from_traces(
    traces: &CallTraceArena,
    abi_cache: &mut ForkAbiCache,
    get_bytecode: impl Fn(Address) -> Option<Vec<u8>>,
) -> Vec<U256> {
    let mut values = Vec::new();

    // Extract from call return values
    values.extend(extract_values_from_call_traces(traces, abi_cache, get_bytecode));

    // Extract from events
    values.extend(extract_values_from_events(traces));

    // Deduplicate
    values.sort();
    values.dedup();

    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_single_uint256() {
        let output = U256::from(12345u64).to_be_bytes_vec();
        let values = decode_return_data("(uint256)", &output).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], U256::from(12345u64));
    }

    #[test]
    fn test_decode_multiple_uint256() {
        let mut output = Vec::new();
        output.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        output.extend_from_slice(&U256::from(200u64).to_be_bytes::<32>());

        let values = decode_return_data("(uint256,uint256)", &output).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], U256::from(100u64));
        assert_eq!(values[1], U256::from(200u64));
    }
}
