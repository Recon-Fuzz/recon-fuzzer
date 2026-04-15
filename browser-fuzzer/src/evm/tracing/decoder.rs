//! Trace decoder for Foundry-style formatted output
//!
//! Port of evm/src/tracing/decoder.rs adapted for WASM (no reqwest, no evmole).
//! Uses revm-inspectors' CallTraceArena + TraceWriter for identical output
//! to the main fuzzer's format_traces_decoded_with_state().

use alloy_dyn_abi::{JsonAbiExt, FunctionExt};
use alloy_primitives::{Address, FixedBytes};
use alloy_json_abi::Function;
use revm_inspectors::tracing::{
    types::{CallTraceNode, DecodedCallData as RevmDecodedCallData, DecodedCallTrace},
};
use revm_inspectors::ColorChoice;
use std::collections::HashMap;

pub use revm_inspectors::tracing::{CallTraceArena, TraceWriter};

use crate::evm::cheatcodes::HEVM_ADDRESS;

const SELECTOR_LEN: usize = 4;

/// Decoder context for resolving addresses and function selectors.
/// Follows Foundry's CallTraceDecoder pattern — copied from main fuzzer's evm/src/tracing/decoder.rs.
pub struct TraceDecoder {
    /// Address to contract name mapping
    pub contracts: HashMap<Address, String>,
    /// Address labels for well-known addresses
    pub labels: HashMap<Address, String>,
    /// All known functions by selector (handles collisions like Foundry)
    pub functions: HashMap<FixedBytes<4>, Vec<Function>>,
    /// All known errors by selector (for decoding revert reasons)
    pub errors: HashMap<FixedBytes<4>, Vec<alloy_json_abi::Error>>,
    /// All known events by topic0 (event signature hash)
    pub events: HashMap<alloy_primitives::B256, Vec<alloy_json_abi::Event>>,
    /// Codehash to contract name mapping (for resolving unknown addresses)
    pub codehash_to_name: HashMap<alloy_primitives::B256, String>,
    /// Selector hash to contract name mapping (more robust than codehash for contracts with immutables)
    pub selector_hash_to_name: HashMap<alloy_primitives::B256, String>,
    /// CBOR metadata hash to contract name (most accurate - based on source hash)
    pub cbor_hash_to_name: HashMap<alloy_primitives::B256, String>,
}

impl TraceDecoder {
    pub fn new() -> Self {
        let mut decoder = Self {
            contracts: HashMap::new(),
            labels: HashMap::new(),
            functions: HashMap::new(),
            errors: HashMap::new(),
            events: HashMap::new(),
            codehash_to_name: HashMap::new(),
            selector_hash_to_name: HashMap::new(),
            cbor_hash_to_name: HashMap::new(),
        };

        decoder.add_well_known_labels();
        decoder.add_cheatcode_functions();

        decoder
    }

    fn add_well_known_labels(&mut self) {
        self.labels.insert(HEVM_ADDRESS, "VM".to_string());

        // Console.log address
        self.labels.insert(
            Address::new([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63,
                0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x6c, 0x6f, 0x67,
            ]),
            "console".to_string(),
        );

        // Common precompile addresses
        self.labels.insert(
            Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "ECRECOVER".to_string(),
        );
        self.labels.insert(
            Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            "SHA256".to_string(),
        );
        self.labels.insert(
            Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]),
            "IDENTITY".to_string(),
        );
    }

    fn add_cheatcode_functions(&mut self) {
        use alloy_json_abi::{Function, Param, StateMutability};

        let make_func = |name: &str, inputs: Vec<(&str, &str)>| -> Function {
            Function {
                name: name.to_string(),
                inputs: inputs
                    .into_iter()
                    .map(|(name, ty)| Param {
                        name: name.to_string(),
                        ty: ty.to_string(),
                        internal_type: None,
                        components: vec![],
                    })
                    .collect(),
                outputs: vec![],
                state_mutability: StateMutability::NonPayable,
            }
        };

        self.push_function(make_func("prank", vec![("msgSender", "address")]));
        self.push_function(make_func("startPrank", vec![("msgSender", "address")]));
        self.push_function(make_func("stopPrank", vec![]));
        self.push_function(make_func("deal", vec![("who", "address"), ("newBalance", "uint256")]));
        self.push_function(make_func("warp", vec![("newTimestamp", "uint256")]));
        self.push_function(make_func("roll", vec![("newNumber", "uint256")]));
        self.push_function(make_func("assume", vec![("condition", "bool")]));
        self.push_function(make_func("store", vec![("target", "address"), ("slot", "bytes32"), ("value", "bytes32")]));
        self.push_function(make_func("load", vec![("target", "address"), ("slot", "bytes32")]));
        self.push_function(make_func("etch", vec![("target", "address"), ("code", "bytes")]));
        self.push_function(make_func("label", vec![("account", "address"), ("newLabel", "string")]));
        self.push_function(make_func("addr", vec![("privateKey", "uint256")]));
        self.push_function(make_func("expectRevert", vec![]));
        self.push_function(make_func("expectRevert", vec![("message", "bytes")]));
        self.push_function(make_func("expectRevert", vec![("message", "bytes4")]));
        self.push_function(make_func("expectEmit", vec![("checkTopic1", "bool"), ("checkTopic2", "bool"), ("checkTopic3", "bool"), ("checkData", "bool")]));
        self.push_function(make_func("record", vec![]));
        self.push_function(make_func("accesses", vec![("target", "address")]));
        self.push_function(make_func("snapshot", vec![]));
        self.push_function(make_func("revertTo", vec![("snapshotId", "uint256")]));
        self.push_function(make_func("generateCalls", vec![("count", "uint256")]));

        self.add_console_log_functions();
    }

    fn add_console_log_functions(&mut self) {
        use alloy_json_abi::{Function, Param, StateMutability};

        let make_log = |inputs: Vec<&str>| -> Function {
            Function {
                name: "log".to_string(),
                inputs: inputs
                    .into_iter()
                    .enumerate()
                    .map(|(i, ty)| Param {
                        name: format!("p{}", i),
                        ty: ty.to_string(),
                        internal_type: None,
                        components: vec![],
                    })
                    .collect(),
                outputs: vec![],
                state_mutability: StateMutability::View,
            }
        };

        // Single argument logs
        self.push_function(make_log(vec![]));
        self.push_function(make_log(vec!["string"]));
        self.push_function(make_log(vec!["uint256"]));
        self.push_function(make_log(vec!["int256"]));
        self.push_function(make_log(vec!["bool"]));
        self.push_function(make_log(vec!["address"]));
        self.push_function(make_log(vec!["bytes"]));
        self.push_function(make_log(vec!["bytes32"]));

        // Two argument logs
        self.push_function(make_log(vec!["string", "string"]));
        self.push_function(make_log(vec!["string", "uint256"]));
        self.push_function(make_log(vec!["string", "int256"]));
        self.push_function(make_log(vec!["string", "bool"]));
        self.push_function(make_log(vec!["string", "address"]));
        self.push_function(make_log(vec!["string", "bytes32"]));
        self.push_function(make_log(vec!["uint256", "uint256"]));
        self.push_function(make_log(vec!["address", "uint256"]));
        self.push_function(make_log(vec!["address", "address"]));
        self.push_function(make_log(vec!["bool", "bool"]));

        // Three argument logs
        self.push_function(make_log(vec!["string", "string", "string"]));
        self.push_function(make_log(vec!["string", "string", "uint256"]));
        self.push_function(make_log(vec!["string", "uint256", "uint256"]));
        self.push_function(make_log(vec!["string", "address", "uint256"]));
        self.push_function(make_log(vec!["string", "address", "address"]));
        self.push_function(make_log(vec!["string", "bool", "bool"]));
        self.push_function(make_log(vec!["address", "address", "uint256"]));
        self.push_function(make_log(vec!["uint256", "uint256", "uint256"]));

        // Four argument logs
        self.push_function(make_log(vec!["string", "string", "string", "string"]));
        self.push_function(make_log(vec!["string", "string", "string", "uint256"]));
        self.push_function(make_log(vec!["string", "uint256", "uint256", "uint256"]));
        self.push_function(make_log(vec!["string", "address", "address", "uint256"]));
        self.push_function(make_log(vec!["uint256", "uint256", "uint256", "uint256"]));
        self.push_function(make_log(vec!["address", "address", "address", "address"]));
    }

    /// Register a contract's ABI with the decoder
    pub fn add_abi(&mut self, addr: Address, name: &str, abi: &alloy_json_abi::JsonAbi) {
        self.contracts.insert(addr, name.to_string());
        self.labels.insert(addr, name.to_string());

        for func in abi.functions() {
            self.push_function(func.clone());
        }
        for error in abi.errors() {
            self.push_error(error.clone());
        }
        for event in abi.events() {
            self.push_event(event.clone());
        }
    }

    pub fn push_function(&mut self, function: Function) {
        let selector = function.selector();
        self.functions.entry(selector).or_default().push(function);
    }

    pub fn push_error(&mut self, error: alloy_json_abi::Error) {
        let selector = error.selector();
        self.errors.entry(selector).or_default().push(error);
    }

    pub fn push_event(&mut self, event: alloy_json_abi::Event) {
        let selector = event.selector();
        self.events.entry(selector).or_default().push(event);
    }

    pub fn add_label(&mut self, address: Address, label: String) {
        self.labels.insert(address, label);
    }

    /// Add contract by multiple hash methods for identification
    pub fn add_contract_by_codehash(&mut self, name: &str, deployed_bytecode: &[u8], abi: &alloy_json_abi::JsonAbi) {
        let partial_hash = compute_partial_codehash(deployed_bytecode);
        let selector_hash = compute_selector_hash(deployed_bytecode);
        let cbor_hash = compute_cbor_hash(deployed_bytecode);

        self.codehash_to_name.insert(partial_hash, name.to_string());
        self.selector_hash_to_name.insert(selector_hash, name.to_string());
        if let Some(cbor) = cbor_hash {
            self.cbor_hash_to_name.insert(cbor, name.to_string());
        }

        for func in abi.functions() {
            self.push_function(func.clone());
        }
        for error in abi.errors() {
            self.push_error(error.clone());
        }
        for event in abi.events() {
            self.push_event(event.clone());
        }
    }

    /// Resolve an address to a label (contract name or hex)
    pub fn resolve_address(&self, addr: &Address) -> String {
        self.labels
            .get(addr)
            .cloned()
            .unwrap_or_else(|| format!("{}", addr))
    }

    /// Resolve address string "0x..." to label
    pub fn resolve_address_str(&self, addr_hex: &str) -> String {
        let stripped = addr_hex.strip_prefix("0x").unwrap_or(addr_hex);
        if let Ok(bytes) = hex::decode(stripped) {
            if bytes.len() == 20 {
                let addr = Address::from_slice(&bytes);
                if let Some(name) = self.labels.get(&addr) {
                    return name.clone();
                }
            }
        }
        addr_hex.to_string()
    }

    // =========================================================================
    // CallTraceArena population (Foundry pattern) — identical to main fuzzer
    // =========================================================================

    /// Populate labels from CREATE traces by matching runtime bytecode
    pub fn populate_labels_from_create_traces(&mut self, traces: &CallTraceArena) {
        let created = extract_created_contracts_with_codehash(traces);
        for (addr, codehash) in created {
            if self.labels.contains_key(&addr) {
                continue;
            }
            if let Some(name) = self.codehash_to_name.get(&codehash) {
                self.labels.insert(addr, name.clone());
            }
        }
    }

    /// Populate labels for all addresses in traces by looking up their bytecode in state
    pub fn populate_labels_from_state<DB: revm::Database>(
        &mut self,
        traces: &CallTraceArena,
        db: &mut DB,
    ) {
        for node in traces.nodes() {
            let addr = node.trace.address;
            if self.labels.contains_key(&addr) {
                continue;
            }

            if let Ok(Some(account)) = db.basic(addr) {
                if let Some(code) = &account.code {
                    let bytecode = code.original_bytes();
                    if !bytecode.is_empty() {
                        // 1. CBOR metadata hash (most accurate)
                        if let Some(cbor_hash) = compute_cbor_hash(&bytecode) {
                            if let Some(name) = self.cbor_hash_to_name.get(&cbor_hash) {
                                self.labels.insert(addr, name.clone());
                                continue;
                            }
                        }
                        // 2. Selector hash (handles immutables)
                        let selector_hash = compute_selector_hash(&bytecode);
                        if let Some(name) = self.selector_hash_to_name.get(&selector_hash) {
                            self.labels.insert(addr, name.clone());
                            continue;
                        }
                        // 3. Partial codehash (handles linked libraries)
                        let partial_hash = compute_partial_codehash(&bytecode);
                        if let Some(name) = self.codehash_to_name.get(&partial_hash) {
                            self.labels.insert(addr, name.clone());
                            continue;
                        }
                    }
                }
            }
        }
    }

    /// Populate decoded fields on all trace nodes
    pub fn populate_traces(&self, traces: &mut CallTraceArena) {
        for node in traces.nodes_mut() {
            self.populate_trace_node(node);
        }
    }

    fn populate_trace_node(&self, node: &mut CallTraceNode) {
        let trace = &node.trace;
        let label = self.labels.get(&trace.address).cloned();

        let (call_data, return_data) = if trace.kind.is_any_create() {
            (None, None)
        } else {
            let decoded = self.decode_calldata_internal(&trace.data);
            let call_data = Some(RevmDecodedCallData {
                signature: decoded.signature.clone(),
                args: decoded.args,
            });

            let return_data = if trace.success && !trace.output.is_empty() {
                self.decode_return_data(&decoded.signature, &trace.output)
            } else if !trace.success && !trace.output.is_empty() {
                self.decode_error_data(&trace.output)
            } else {
                None
            };

            (call_data, return_data)
        };

        *node.trace.decoded() = DecodedCallTrace {
            label,
            call_data,
            return_data,
        };

        // Decode logs/events
        for log in &mut node.logs {
            if let Some(decoded_log) = self.decode_log(&log.raw_log) {
                *log.decoded() = decoded_log;
            }
        }
    }

    fn decode_log(
        &self,
        log: &revm::primitives::LogData,
    ) -> Option<revm_inspectors::tracing::types::DecodedCallLog> {
        use revm_inspectors::tracing::types::DecodedCallLog as RevmDecodedCallLog;
        use alloy_dyn_abi::EventExt;

        let topics = log.topics();
        if topics.is_empty() {
            return None;
        }

        let topic0 = topics[0];

        if let Some(events) = self.events.get(&topic0) {
            if let Some(event) = events.first() {
                if let Ok(decoded) = event.decode_log(log) {
                    let params: Vec<(String, String)> = event
                        .inputs
                        .iter()
                        .zip(decoded.indexed.iter().chain(decoded.body.iter()))
                        .map(|(input, value)| {
                            let name = if input.name.is_empty() {
                                format!("arg{}", input.name)
                            } else {
                                input.name.clone()
                            };
                            (name, self.format_value(value))
                        })
                        .collect();

                    return Some(RevmDecodedCallLog {
                        name: Some(event.name.clone()),
                        params: Some(params),
                    });
                }
                return Some(RevmDecodedCallLog {
                    name: Some(event.name.clone()),
                    params: None,
                });
            }
        }

        None
    }

    // =========================================================================
    // Calldata / return / error decoding — identical to main fuzzer
    // =========================================================================

    fn select_function<'a>(&self, functions: &'a [Function], data: &[u8]) -> Option<&'a Function> {
        if functions.is_empty() {
            return None;
        }
        if functions.len() == 1 {
            return Some(&functions[0]);
        }
        if data.len() >= SELECTOR_LEN {
            for func in functions {
                if func.abi_decode_input(&data[SELECTOR_LEN..]).is_ok() {
                    return Some(func);
                }
            }
        }
        Some(&functions[0])
    }

    fn decode_calldata_internal(&self, data: &[u8]) -> DecodedCallData {
        if data.len() < SELECTOR_LEN {
            if data.is_empty() {
                return DecodedCallData {
                    signature: "()".to_string(),
                    args: vec![],
                };
            }
            return DecodedCallData {
                signature: format!("0x{}", hex::encode(data)),
                args: vec![],
            };
        }

        let selector: FixedBytes<4> = data[..SELECTOR_LEN].try_into().unwrap_or_default();

        if let Some(functions) = self.functions.get(&selector) {
            if let Some(func) = self.select_function(functions, data) {
                let input_data = &data[SELECTOR_LEN..];
                match func.abi_decode_input(input_data) {
                    Ok(decoded_args) => {
                        let args: Vec<String> = decoded_args
                            .iter()
                            .map(|v| self.format_value(v))
                            .collect();
                        return DecodedCallData {
                            signature: func.signature(),
                            args,
                        };
                    }
                    Err(_) => {
                        return DecodedCallData {
                            signature: func.signature(),
                            args: vec![format!("0x{}", hex::encode(input_data))],
                        };
                    }
                }
            }
        }

        DecodedCallData {
            signature: format!("0x{}", hex::encode(&selector[..])),
            args: vec![format!("0x{}", hex::encode(&data[SELECTOR_LEN..]))],
        }
    }

    /// Public calldata decoding (used by campaign.rs for call sequence formatting)
    pub fn decode_calldata(&self, data_hex: &str) -> String {
        let data = match hex::decode(data_hex) {
            Ok(d) => d,
            Err(_) => return format!("0x{data_hex}"),
        };
        let decoded = self.decode_calldata_internal(&data);
        decoded.format()
    }

    fn decode_return_data(&self, signature: &str, output: &[u8]) -> Option<String> {
        let selector = alloy_primitives::keccak256(signature.as_bytes());
        let selector_bytes: [u8; 4] = selector[..4].try_into().ok()?;
        let selector = alloy_primitives::FixedBytes::<4>::from(selector_bytes);

        let functions = self.functions.get(&selector)?;
        let func = functions.first()?;
        if func.outputs.is_empty() {
            return None;
        }

        match func.abi_decode_output(output) {
            Ok(values) => {
                if values.is_empty() {
                    None
                } else if values.len() == 1 {
                    Some(self.format_value(&values[0]))
                } else {
                    let formatted: Vec<String> =
                        values.iter().map(|v| self.format_value(v)).collect();
                    Some(format!("({})", formatted.join(", ")))
                }
            }
            Err(_) => None,
        }
    }

    fn decode_error_data(&self, data: &[u8]) -> Option<String> {
        if data.len() < SELECTOR_LEN {
            return None;
        }

        if let Some(reason) = decode_revert_reason(data) {
            if !reason.starts_with("0x") {
                return Some(reason);
            }
        }

        let selector: FixedBytes<4> = data[..SELECTOR_LEN].try_into().ok()?;
        if let Some(errors) = self.errors.get(&selector) {
            if let Some(error) = errors.first() {
                return Some(self.format_custom_error(error, data));
            }
        }

        None
    }

    fn format_custom_error(&self, error: &alloy_json_abi::Error, data: &[u8]) -> String {
        if error.inputs.is_empty() {
            return format!("{}()", error.name);
        }
        if data.len() > SELECTOR_LEN {
            if let Ok(values) = error.abi_decode_input(&data[SELECTOR_LEN..]) {
                let formatted: Vec<String> = error
                    .inputs
                    .iter()
                    .zip(values.iter())
                    .map(|(input, v)| {
                        if input.name.is_empty() {
                            self.format_value(v)
                        } else {
                            format!("{}: {}", input.name, self.format_value(v))
                        }
                    })
                    .collect();
                return format!("{}({})", error.name, formatted.join(", "));
            }
        }
        format!("{}(<decode failed>)", error.name)
    }

    /// Format a DynSolValue with address label resolution (Foundry-style)
    pub fn format_value(&self, val: &alloy_dyn_abi::DynSolValue) -> String {
        use alloy_dyn_abi::DynSolValue;
        match val {
            DynSolValue::Address(addr) => {
                if let Some(label) = self.labels.get(addr) {
                    format!("{}: [{}]", label, addr)
                } else {
                    format!("{}", addr)
                }
            }
            DynSolValue::Bool(b) => b.to_string(),
            DynSolValue::Bytes(b) => {
                if b.len() <= 32 {
                    format!("0x{}", hex::encode(b))
                } else {
                    format!("0x{}... ({} bytes)", hex::encode(&b[..16]), b.len())
                }
            }
            DynSolValue::FixedBytes(b, _) => format!("0x{}", hex::encode(b.as_slice())),
            DynSolValue::Int(i, _) => i.to_string(),
            DynSolValue::Uint(u, _) => u.to_string(),
            DynSolValue::String(s) => format!("\"{}\"", s),
            DynSolValue::Array(arr) | DynSolValue::FixedArray(arr) => {
                let items: Vec<String> = arr.iter().map(|v| self.format_value(v)).collect();
                format!("[{}]", items.join(", "))
            }
            DynSolValue::Tuple(items) => {
                let formatted: Vec<String> = items.iter().map(|v| self.format_value(v)).collect();
                format!("({})", formatted.join(", "))
            }
            _ => format!("{:?}", val),
        }
    }
}

impl Default for TraceDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoded call data
#[derive(Debug, Clone)]
pub struct DecodedCallData {
    pub signature: String,
    pub args: Vec<String>,
}

impl DecodedCallData {
    pub fn format(&self) -> String {
        if self.args.is_empty() {
            self.signature.clone()
        } else {
            let name = self.signature.split('(').next().unwrap_or(&self.signature);
            format!("{}({})", name, self.args.join(", "))
        }
    }
}

// =========================================================================
// Format functions — identical to main fuzzer
// =========================================================================

/// Format traces with decoded addresses, resolving unknown addresses by codehash from state.
/// This is the main fuzzer's format_traces_decoded_with_state() — copy-pasted.
pub fn format_traces_decoded_with_state<DB: revm::Database>(
    traces: &mut CallTraceArena,
    decoder: &mut TraceDecoder,
    db: &mut DB,
    with_storage: bool,
) -> String {
    // First, try to resolve addresses from CREATE traces in the trace itself
    decoder.populate_labels_from_create_traces(traces);

    // Then, resolve any remaining unknown addresses by looking up their codehash in state
    decoder.populate_labels_from_state(traces, db);

    // Populate decoded fields on all trace nodes
    decoder.populate_traces(traces);

    // Use TraceWriter for proper formatting (it reads from decoded fields)
    let mut output = Vec::new();
    let mut writer = TraceWriter::new(&mut output)
        .use_colors(ColorChoice::Never)
        .with_storage_changes(with_storage);

    if let Err(e) = writer.write_arena(traces) {
        return format!("Error formatting traces: {}", e);
    }

    String::from_utf8_lossy(&output).to_string()
}

/// Format traces with decoded fields only (no state lookup)
pub fn format_traces_decoded(
    traces: &mut CallTraceArena,
    decoder: &TraceDecoder,
    with_storage: bool,
) -> String {
    decoder.populate_traces(traces);

    let mut output = Vec::new();
    let mut writer = TraceWriter::new(&mut output)
        .use_colors(ColorChoice::Never)
        .with_storage_changes(with_storage);

    if let Err(e) = writer.write_arena(traces) {
        return format!("Error formatting traces: {}", e);
    }

    String::from_utf8_lossy(&output).to_string()
}

// =========================================================================
// Bytecode hash utilities — identical to main fuzzer
// =========================================================================

fn normalize_bytecode_for_hash(bytecode: &[u8]) -> Vec<u8> {
    let mut normalized = bytecode.to_vec();
    let mut i = 0;
    while i + 21 <= normalized.len() {
        if normalized[i] == 0x73 {
            for j in i + 1..i + 21 {
                normalized[j] = 0;
            }
            i += 21;
        } else {
            i += 1;
        }
    }
    normalized
}

fn extract_selectors_from_bytecode(bytecode: &[u8]) -> Vec<[u8; 4]> {
    let mut selectors = Vec::new();
    let mut i = 0;
    while i + 5 <= bytecode.len() {
        if bytecode[i] == 0x63 {
            let selector: [u8; 4] = bytecode[i + 1..i + 5].try_into().unwrap_or_default();
            if selector != [0, 0, 0, 0] && selector != [0xff, 0xff, 0xff, 0xff] {
                selectors.push(selector);
            }
            i += 5;
        } else {
            i += 1;
        }
    }
    selectors.sort();
    selectors.dedup();
    selectors
}

fn compute_selector_hash(bytecode: &[u8]) -> alloy_primitives::B256 {
    use alloy_primitives::keccak256;
    let selectors = extract_selectors_from_bytecode(bytecode);
    let mut data = Vec::with_capacity(selectors.len() * 4);
    for sel in selectors {
        data.extend_from_slice(&sel);
    }
    keccak256(&data)
}

fn extract_cbor_metadata(bytecode: &[u8]) -> Option<Vec<u8>> {
    if bytecode.len() < 2 {
        return None;
    }
    let len_bytes = &bytecode[bytecode.len() - 2..];
    let cbor_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if cbor_len < 10 || cbor_len > 200 || cbor_len + 2 > bytecode.len() {
        return None;
    }
    let cbor_start = bytecode.len() - 2 - cbor_len;
    let cbor_data = &bytecode[cbor_start..bytecode.len() - 2];
    if !cbor_data.is_empty()
        && (cbor_data[0] == 0xa2 || cbor_data[0] == 0xa3 || cbor_data[0] == 0xa1)
    {
        Some(cbor_data.to_vec())
    } else {
        None
    }
}

fn compute_cbor_hash(bytecode: &[u8]) -> Option<alloy_primitives::B256> {
    use alloy_primitives::keccak256;
    extract_cbor_metadata(bytecode).map(|cbor| keccak256(&cbor))
}

pub fn compute_partial_codehash(bytecode: &[u8]) -> alloy_primitives::B256 {
    use alloy_primitives::keccak256;
    let normalized = normalize_bytecode_for_hash(bytecode);
    let half = normalized.len() / 2;
    let len = half.max(32).min(normalized.len());
    keccak256(&normalized[..len])
}

fn extract_created_contracts_with_codehash(
    traces: &CallTraceArena,
) -> Vec<(Address, alloy_primitives::B256)> {
    let mut created = Vec::new();
    for node in traces.nodes() {
        if node.trace.kind.is_any_create() && node.trace.success {
            let addr = node.trace.address;
            let runtime_code = &node.trace.output;
            if !runtime_code.is_empty() {
                let partial_hash = compute_partial_codehash(runtime_code);
                created.push((addr, partial_hash));
            }
        }
    }
    created
}

/// Decode revert reason from output bytes
pub fn decode_revert_reason(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    // Error(string) - 0x08c379a0
    if data[0..4] == [0x08, 0xc3, 0x79, 0xa0] && data.len() >= 68 {
        let string_len = {
            let len_bytes = &data[36..68];
            u32::from_be_bytes([len_bytes[28], len_bytes[29], len_bytes[30], len_bytes[31]])
                as usize
        };
        if data.len() >= 68 + string_len {
            return String::from_utf8(data[68..68 + string_len].to_vec())
                .ok()
                .map(|s| format!("\"{}\"", s));
        }
    }

    // Panic(uint256) - 0x4e487b71
    if data[0..4] == [0x4e, 0x48, 0x7b, 0x71] && data.len() >= 36 {
        let panic_code = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let reason = match panic_code {
            0x00 => "generic compiler panic",
            0x01 => "assert(false)",
            0x11 => "arithmetic overflow/underflow",
            0x12 => "division/modulo by zero",
            0x21 => "invalid enum conversion",
            0x22 => "storage byte array encoding error",
            0x31 => "pop() on empty array",
            0x32 => "array index out of bounds",
            0x41 => "memory allocation overflow",
            0x51 => "zero-initialized function pointer call",
            _ => "unknown panic code",
        };
        return Some(format!("Panic(0x{:02x}): {}", panic_code, reason));
    }

    let selector = hex::encode(&data[0..4]);
    Some(format!("0x{}", selector))
}

/// Extract vm.label() calls from traces
pub fn extract_labels_from_traces(traces: &CallTraceArena) -> HashMap<Address, String> {
    use alloy_sol_types::SolValue;

    let mut labels = HashMap::new();
    let hevm_address = HEVM_ADDRESS;
    let label_selector: [u8; 4] = [0xc6, 0x57, 0xc7, 0x18];

    for node in traces.nodes() {
        if node.trace.address == hevm_address {
            let data = &node.trace.data;
            if data.len() >= 4 && data[0..4] == label_selector {
                if let Ok((address, label)) = <(Address, String)>::abi_decode(&data[4..]) {
                    labels.insert(address, label);
                }
            }
        }
    }

    labels
}
