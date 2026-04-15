//! Transaction sequence execution
//!
//! Browser-fuzzer equivalent of campaign/src/execution.rs.
//! Contains functions for executing and replaying transaction sequences.
//! Identical to main fuzzer except: no WorkerState, no Slither, no World, no concolic,
//! no shortcuts, no web_state, no generate_calls_context.

use std::collections::HashMap;

use alloy_dyn_abi::{DynSolType, Specifier};
use alloy_primitives::{Address, I256, U256};

use crate::abi::types::GenDict;
use crate::evm::exec::EvmState;

use super::transaction::Tx;

/// Add a return value to the dictionary, recursively extracting tuple elements
///
/// This function:
/// 1. Preserves the whole value (for struct-level reuse across functions)
/// 2. Also decomposes into primitives (for mixing components)
pub fn add_return_value_to_dict(dict: &mut GenDict, val: alloy_dyn_abi::DynSolValue) {
    use alloy_dyn_abi::DynSolValue;

    // ALWAYS add the whole value first (preserves structs for reuse)
    // This enables passing complete structs to other functions
    dict.add_value(val.clone());

    // ALSO decompose for primitive extraction (enables mixing struct fields)
    match &val {
        // For tuples/structs, also extract each element individually
        DynSolValue::Tuple(elements) => {
            for elem in elements {
                add_return_value_to_dict(dict, elem.clone());
            }
        }
        // For arrays, also extract each element
        DynSolValue::Array(elements) | DynSolValue::FixedArray(elements) => {
            for elem in elements {
                add_return_value_to_dict(dict, elem.clone());
            }
        }
        // Primitive types are already added above
        _ => {}
    }
}

/// Extract dictionary values from call traces at ALL depths
///
/// This function iterates through the CallTraceArena and extracts:
/// 1. Call inputs (arguments passed to external calls)
/// 2. Call outputs (return values from external calls)
/// 3. Event parameters (both indexed and non-indexed)
/// 4. Created contract addresses
///
/// This is essential for setUp extraction and corpus replay to capture
/// values from nested calls (e.g., vault.addMarket(MarketParams{...}))
pub fn extract_dict_from_traces(
    traces: &crate::evm::tracing::CallTraceArena,
    dict: &mut GenDict,
    event_map: &HashMap<alloy_primitives::B256, alloy_json_abi::Event>,
    function_map: &HashMap<alloy_primitives::FixedBytes<4>, alloy_json_abi::Function>,
) {
    use alloy_dyn_abi::DynSolValue;

    for node in traces.nodes() {
        let trace = &node.trace;

        // Skip calls to HEVM (cheatcodes) and console.log
        if trace.address == crate::evm::cheatcodes::HEVM_ADDRESS {
            continue;
        }
        let console_addr = Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63,
            0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x6c, 0x6f, 0x67,
        ]);
        if trace.address == console_addr {
            continue;
        }

        // Extract call inputs (arguments passed to external calls)
        if trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                // Decode call input arguments using manual ABI decoding
                let input_types: Vec<DynSolType> = func.inputs.iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();
                if !input_types.is_empty() {
                    let tuple_ty = DynSolType::Tuple(input_types);
                    if let Ok(val) = tuple_ty.abi_decode(&trace.data[4..]) {
                        if let DynSolValue::Tuple(args) = val {
                            for arg in args {
                                add_return_value_to_dict(dict, arg);
                            }
                        }
                    }
                }
            }
        }

        // Extract call outputs (return values) for successful calls
        if trace.success && !trace.output.is_empty() && trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                let output_types: Vec<DynSolType> = func.outputs.iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();
                if !output_types.is_empty() {
                    let tuple_ty = DynSolType::Tuple(output_types);
                    if let Ok(val) = tuple_ty.abi_decode(&trace.output) {
                        if let DynSolValue::Tuple(outputs) = val {
                            for output in outputs {
                                add_return_value_to_dict(dict, output);
                            }
                        }
                    }
                }
            } else {
                // Fallback: try to extract raw U256 values from output
                if trace.output.len() == 32 {
                    let val = U256::from_be_slice(&trace.output);
                    dict.dict_values.insert(val);
                } else if trace.output.len() % 32 == 0 && trace.output.len() <= 256 {
                    for chunk in trace.output.chunks(32) {
                        dict.dict_values.insert(U256::from_be_slice(chunk));
                    }
                }
            }
        }

        // Extract addresses from CREATE/CREATE2 operations
        if trace.kind.is_any_create() && trace.success {
            dict.add_value(DynSolValue::Address(trace.address));
        }

        // Extract event parameters from this node's logs
        for log_entry in &node.logs {
            // CallTraceNode.logs is Vec<LogCallOrder> — extract the Log variant
            let log = &log_entry.raw_log;

            if let Some(topic0) = log.topics().first() {
                if let Some(event) = event_map.get(topic0) {
                    // Extract NON-INDEXED parameters from log.data
                    let mut non_indexed_types = Vec::new();
                    for input in &event.inputs {
                        if !input.indexed {
                            if let Ok(ty) = input.resolve() {
                                non_indexed_types.push(ty);
                            }
                        }
                    }

                    if !non_indexed_types.is_empty() {
                        let tuple_ty = DynSolType::Tuple(non_indexed_types);
                        if let Ok(val) = tuple_ty.abi_decode(log.data.as_ref()) {
                            if let DynSolValue::Tuple(vals) = val {
                                for v in vals {
                                    add_return_value_to_dict(dict, v);
                                }
                            }
                        }
                    }

                    // Extract INDEXED parameters from topics[1..]
                    let indexed_inputs: Vec<_> = event.inputs.iter()
                        .filter(|input| input.indexed)
                        .collect();

                    for (topic, input) in log.topics().iter().skip(1).zip(indexed_inputs.iter()) {
                        if let Ok(ty) = input.resolve() {
                            match &ty {
                                DynSolType::Address => {
                                    let addr = Address::from_slice(&topic.0[12..32]);
                                    dict.add_value(DynSolValue::Address(addr));
                                }
                                DynSolType::Uint(_) => {
                                    let val = U256::from_be_bytes(topic.0);
                                    dict.dict_values.insert(val);
                                }
                                DynSolType::Int(_) => {
                                    let val = I256::from_be_bytes(topic.0);
                                    dict.signed_dict_values.insert(val);
                                }
                                DynSolType::Bool => {
                                    let val = topic.0[31] != 0;
                                    dict.add_value(DynSolValue::Bool(val));
                                }
                                DynSolType::FixedBytes(n) => {
                                    let bytes = topic.0[..*n].to_vec();
                                    dict.add_value(DynSolValue::FixedBytes(
                                        alloy_primitives::FixedBytes::from_slice(&bytes), *n
                                    ));
                                }
                                _ => {
                                    let val = U256::from_be_bytes(topic.0);
                                    dict.dict_values.insert(val);
                                }
                            }
                        } else {
                            let val = U256::from_be_bytes(topic.0);
                            dict.dict_values.insert(val);
                        }
                    }
                } else {
                    // Unknown event: extract raw topic values
                    for topic in log.topics().iter().skip(1) {
                        dict.dict_values.insert(U256::from_be_bytes(topic.0));
                    }
                    // Extract raw data as U256 chunks
                    if log.data.len() % 32 == 0 {
                        for chunk in log.data.chunks(32) {
                            dict.dict_values.insert(U256::from_be_slice(chunk));
                        }
                    }
                }
            }
        }
    }
}

/// Extracted dictionary values from traces (for passing to Env)
#[derive(Default, Clone)]
pub struct ExtractedDictValues {
    pub uint_values: Vec<U256>,
    pub int_values: Vec<I256>,
    pub addresses: Vec<Address>,
    /// Tuples/structs extracted from traces (e.g., MarketParams)
    pub tuples: Vec<alloy_dyn_abi::DynSolValue>,
}

/// Extract dictionary values from call traces at ALL depths (simple return version)
///
/// This is a simpler version that returns raw values instead of populating a GenDict.
/// Used to populate setup_dict_* fields before workers are created.
pub fn extract_values_from_traces(
    traces: &crate::evm::tracing::CallTraceArena,
    event_map: &HashMap<alloy_primitives::B256, alloy_json_abi::Event>,
    function_map: &HashMap<alloy_primitives::FixedBytes<4>, alloy_json_abi::Function>,
) -> ExtractedDictValues {
    use std::collections::BTreeSet;
    use alloy_dyn_abi::DynSolValue;

    let mut uint_values: BTreeSet<U256> = BTreeSet::new();
    let mut int_values: BTreeSet<I256> = BTreeSet::new();
    let mut addresses: BTreeSet<Address> = BTreeSet::new();
    let mut tuples: Vec<DynSolValue> = Vec::new();

    for node in traces.nodes() {
        let trace = &node.trace;

        // Skip calls to HEVM (cheatcodes) and console.log
        if trace.address == crate::evm::cheatcodes::HEVM_ADDRESS {
            continue;
        }
        let console_addr = Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63,
            0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x6c, 0x6f, 0x67,
        ]);
        if trace.address == console_addr {
            continue;
        }

        // Extract call inputs
        if trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                let input_types: Vec<DynSolType> = func.inputs.iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();
                if !input_types.is_empty() {
                    let tuple_ty = DynSolType::Tuple(input_types);
                    if let Ok(val) = tuple_ty.abi_decode(&trace.data[4..]) {
                        if let DynSolValue::Tuple(args) = val {
                            for arg in &args {
                                extract_raw_values(arg, &mut uint_values, &mut int_values, &mut addresses);
                                extract_tuples_recursive(arg, &mut tuples);
                            }
                        }
                    }
                }
            }
        }

        // Extract call outputs for successful calls
        if trace.success && !trace.output.is_empty() && trace.data.len() >= 4 {
            let selector: [u8; 4] = trace.data[0..4].try_into().unwrap_or([0; 4]);
            let selector_fixed = alloy_primitives::FixedBytes::from(selector);

            if let Some(func) = function_map.get(&selector_fixed) {
                let output_types: Vec<DynSolType> = func.outputs.iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();
                if !output_types.is_empty() {
                    let tuple_ty = DynSolType::Tuple(output_types);
                    if let Ok(val) = tuple_ty.abi_decode(&trace.output) {
                        if let DynSolValue::Tuple(outputs) = val {
                            for output in &outputs {
                                extract_raw_values(output, &mut uint_values, &mut int_values, &mut addresses);
                                extract_tuples_recursive(output, &mut tuples);
                            }
                        }
                    }
                }
            } else {
                // Fallback: extract raw U256 from output
                if trace.output.len() == 32 {
                    uint_values.insert(U256::from_be_slice(&trace.output));
                } else if trace.output.len() % 32 == 0 && trace.output.len() <= 256 {
                    for chunk in trace.output.chunks(32) {
                        uint_values.insert(U256::from_be_slice(chunk));
                    }
                }
            }
        }

        // Extract addresses from CREATE/CREATE2
        if trace.kind.is_any_create() && trace.success {
            addresses.insert(trace.address);
        }

        // Extract event parameters
        for log_entry in &node.logs {
            let log = &log_entry.raw_log;

            if let Some(topic0) = log.topics().first() {
                if let Some(event) = event_map.get(topic0) {
                    // Non-indexed parameters
                    let mut non_indexed_types = Vec::new();
                    for input in &event.inputs {
                        if !input.indexed {
                            if let Ok(ty) = input.resolve() {
                                non_indexed_types.push(ty);
                            }
                        }
                    }

                    if !non_indexed_types.is_empty() {
                        let tuple_ty = DynSolType::Tuple(non_indexed_types);
                        if let Ok(val) = tuple_ty.abi_decode(log.data.as_ref()) {
                            extract_raw_values(&val, &mut uint_values, &mut int_values, &mut addresses);
                            extract_tuples_recursive(&val, &mut tuples);
                        }
                    }

                    // Indexed parameters
                    let indexed_inputs: Vec<_> = event.inputs.iter()
                        .filter(|input| input.indexed)
                        .collect();

                    for (topic, input) in log.topics().iter().skip(1).zip(indexed_inputs.iter()) {
                        if let Ok(ty) = input.resolve() {
                            match &ty {
                                DynSolType::Address => {
                                    addresses.insert(Address::from_slice(&topic.0[12..32]));
                                }
                                DynSolType::Uint(_) => {
                                    uint_values.insert(U256::from_be_bytes(topic.0));
                                }
                                DynSolType::Int(_) => {
                                    int_values.insert(I256::from_be_bytes(topic.0));
                                }
                                _ => {
                                    uint_values.insert(U256::from_be_bytes(topic.0));
                                }
                            }
                        } else {
                            uint_values.insert(U256::from_be_bytes(topic.0));
                        }
                    }
                } else {
                    // Unknown event: extract raw values
                    for topic in log.topics().iter().skip(1) {
                        uint_values.insert(U256::from_be_bytes(topic.0));
                    }
                    if log.data.len() % 32 == 0 {
                        for chunk in log.data.chunks(32) {
                            uint_values.insert(U256::from_be_slice(chunk));
                        }
                    }
                }
            }
        }
    }

    ExtractedDictValues {
        uint_values: uint_values.into_iter().collect(),
        int_values: int_values.into_iter().collect(),
        addresses: addresses.into_iter().collect(),
        tuples,
    }
}

/// Recursively extract tuples from a DynSolValue
fn extract_tuples_recursive(val: &alloy_dyn_abi::DynSolValue, tuples: &mut Vec<alloy_dyn_abi::DynSolValue>) {
    use alloy_dyn_abi::DynSolValue;

    match val {
        DynSolValue::Tuple(elements) => {
            tuples.push(val.clone());
            for elem in elements {
                extract_tuples_recursive(elem, tuples);
            }
        }
        DynSolValue::Array(elements) | DynSolValue::FixedArray(elements) => {
            for elem in elements {
                extract_tuples_recursive(elem, tuples);
            }
        }
        _ => {}
    }
}

/// Helper to recursively extract raw values from DynSolValue
fn extract_raw_values(
    val: &alloy_dyn_abi::DynSolValue,
    uint_values: &mut std::collections::BTreeSet<U256>,
    int_values: &mut std::collections::BTreeSet<I256>,
    addresses: &mut std::collections::BTreeSet<Address>,
) {
    use alloy_dyn_abi::DynSolValue;

    match val {
        DynSolValue::Uint(v, _) => {
            uint_values.insert(*v);
        }
        DynSolValue::Int(v, _) => {
            int_values.insert(*v);
        }
        DynSolValue::Address(a) => {
            addresses.insert(*a);
        }
        DynSolValue::Bool(_) => {}
        DynSolValue::FixedBytes(b, _) => {
            if b.len() == 32 {
                uint_values.insert(U256::from_be_slice(b.as_slice()));
            }
        }
        DynSolValue::Bytes(b) => {
            if b.len() == 32 {
                uint_values.insert(U256::from_be_slice(b));
            }
        }
        DynSolValue::String(_) => {}
        DynSolValue::Tuple(elements) => {
            for elem in elements {
                extract_raw_values(elem, uint_values, int_values, addresses);
            }
        }
        DynSolValue::Array(elements) | DynSolValue::FixedArray(elements) => {
            for elem in elements {
                extract_raw_values(elem, uint_values, int_values, addresses);
            }
        }
        _ => {}
    }
}

// =========================================================================
// execute_sequence_worker — the main per-tx execution loop
// =========================================================================
// In the main fuzzer, this is execute_sequence_worker() which takes WorkerEnv + WorkerState.
// In the browser fuzzer, the per-tx dictionary extraction logic is inlined in
// CampaignState::fuzz_one_iteration() and WorkerEnv::fuzz_one_iteration() because
// there's no separate WorkerState. The extraction patterns below match exactly:
//
// 1. Type-aware return value extraction (rTypes / returnValues)
// 2. Type-aware event extraction (ABI-decoded indexed + non-indexed)
// 3. State diff extraction (storage values → dict)
// 4. Created address capture (CREATE/CREATE2)
// 5. Coverage-finding call dictionary (gaddCalls)
//
// These are called directly from fuzz_one_iteration in mod.rs and worker_env.rs.

/// Per-tx dictionary extraction — called after each successful tx execution.
/// Matches main fuzzer's execute_sequence_worker per-tx extraction block.
///
/// Extracts:
/// - Return values (type-aware via rTypes)
/// - Event params (ABI-decoded, indexed + non-indexed)
/// - State diff values (storage writes)
/// - Created addresses (CREATE/CREATE2)
pub fn extract_dict_from_tx(
    evm: &EvmState,
    dict: &mut GenDict,
    tx: &Tx,
    event_map: &HashMap<alloy_primitives::B256, alloy_json_abi::Event>,
) {
    // 1. Type-aware return value extraction (rTypes)
    let output = evm.get_last_output();
    if !output.is_empty() {
        if let Some(ty) = dict.return_types.get(&tx.function_name).cloned() {
            if let Ok(val) = ty.abi_decode(&output) {
                add_return_value_to_dict(dict, val);
            }
        } else if output.len() >= 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&output[..32]);
            dict.dict_values.insert(U256::from_be_bytes(bytes));
        }
    }

    // 2. Type-aware event extraction (matches main fuzzer's execute_sequence_worker)
    let logs = evm.get_last_logs();
    for log in logs {
        if let Some(topic0) = log.topics().first() {
            if let Some(event) = event_map.get(topic0) {
                // Extract NON-INDEXED parameters from log.data
                let mut non_indexed_types = Vec::new();
                for input in &event.inputs {
                    if !input.indexed {
                        if let Ok(ty) = input.resolve() {
                            non_indexed_types.push(ty);
                        }
                    }
                }

                if !non_indexed_types.is_empty() {
                    let tuple_ty = DynSolType::Tuple(non_indexed_types);
                    if let Ok(val) = tuple_ty.abi_decode(&log.data.data) {
                        add_return_value_to_dict(dict, val);
                    }
                }

                // Extract INDEXED parameters from topics[1..]
                let indexed_inputs: Vec<_> = event.inputs.iter()
                    .filter(|input| input.indexed)
                    .collect();

                for (topic, input) in log.topics().iter().skip(1).zip(indexed_inputs.iter()) {
                    if let Ok(ty) = input.resolve() {
                        match &ty {
                            DynSolType::Address => {
                                let addr = Address::from_slice(&topic.0[12..32]);
                                dict.add_value(alloy_dyn_abi::DynSolValue::Address(addr));
                            }
                            DynSolType::Uint(_) => {
                                dict.dict_values.insert(U256::from_be_bytes(topic.0));
                            }
                            DynSolType::Int(_) => {
                                dict.signed_dict_values.insert(I256::from_be_bytes(topic.0));
                            }
                            DynSolType::Bool => {
                                dict.add_value(alloy_dyn_abi::DynSolValue::Bool(topic.0[31] != 0));
                            }
                            DynSolType::FixedBytes(n) => {
                                let bytes = topic.0[..*n].to_vec();
                                dict.add_value(alloy_dyn_abi::DynSolValue::FixedBytes(
                                    alloy_primitives::FixedBytes::from_slice(&bytes), *n
                                ));
                            }
                            _ => {
                                dict.dict_values.insert(U256::from_be_bytes(topic.0));
                            }
                        }
                    } else {
                        dict.dict_values.insert(U256::from_be_bytes(topic.0));
                    }
                }
            } else {
                // Unknown event: extract raw values
                for topic in log.topics().iter().skip(1) {
                    dict.dict_values.insert(U256::from_be_bytes(topic.0));
                }
                let data = &log.data.data;
                if data.len() % 32 == 0 {
                    for chunk in data.chunks(32) {
                        dict.dict_values.insert(U256::from_be_slice(chunk));
                    }
                }
            }
        }
    }

    // 3. State diff extraction (matches main fuzzer: get_last_state_diff)
    for (_addr, _slot, _old_val, new_val) in evm.get_last_state_diff() {
        if !new_val.is_zero() {
            dict.dict_values.insert(new_val);
        }
    }

    // 4. Created address capture (CREATE/CREATE2)
    if let Some(revm::context_interface::result::ExecutionResult::Success {
        output: revm::context_interface::result::Output::Create(_, Some(addr)),
        ..
    }) = &evm.last_result
    {
        dict.add_value(alloy_dyn_abi::DynSolValue::Address(*addr));
    }
    for addr in &evm.last_created_addresses {
        dict.add_value(alloy_dyn_abi::DynSolValue::Address(*addr));
    }
}
