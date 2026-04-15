//! Integration with revm-inspectors TracingInspector
//!
//! This module provides Foundry-style trace output using the revm-inspectors crate.
//! It wraps TracingInspector to produce call traces with storage diffs, gas usage,
//! and decoded call data.
//!
//! The integration follows Foundry's pattern:
//! 1. Run transaction with TracingInspector to collect CallTraceArena
//! 2. Use TraceDecoder to populate `decoded` fields on each CallTraceNode
//! 3. Use TraceWriter to render the decoded traces

use alloy_dyn_abi::{JsonAbiExt, FunctionExt};  // For abi_decode_input and abi_decode_output
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_json_abi::Function;
use revm_inspectors::tracing::{
    TracingInspector as RevmTracingInspector, TracingInspectorConfig,
    types::{CallTraceNode, DecodedCallData as RevmDecodedCallData, DecodedCallTrace},
};
use revm_inspectors::ColorChoice;
use std::collections::HashMap;

pub use revm_inspectors::tracing::{
    CallTraceArena, TraceWriter, TraceWriterConfig,
};

const SELECTOR_LEN: usize = 4;

/// Decoder context for resolving addresses and function selectors
/// Follows Foundry's CallTraceDecoder pattern
pub struct TraceDecoder {
    /// Address to contract name mapping (like Foundry's `contracts`)
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
    /// Decompiled ABIs for external contracts (fork mode)
    /// Key: selector, Value: decompiled function info string (e.g., "func_a9059cbb(address,uint256)")
    pub decompiled_functions: HashMap<FixedBytes<4>, String>,
    /// 4byte database signatures (from Sourcify)
    /// Key: selector, Value: list of candidate signatures (e.g., ["transfer(address,uint256)", ...])
    pub fourbyte_signatures: HashMap<FixedBytes<4>, Vec<String>>,
    /// 4byte database event signatures (from Sourcify)
    /// Key: event topic0, Value: human-readable signature (e.g., "Transfer(address,address,uint256)")
    pub fourbyte_events: HashMap<alloy_primitives::B256, String>,
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
            decompiled_functions: HashMap::new(),
            fourbyte_signatures: HashMap::new(),
            fourbyte_events: HashMap::new(),
        };

        // Add well-known addresses
        decoder.add_well_known_labels();
        decoder.add_cheatcode_functions();

        decoder
    }

    /// Add well-known address labels (HEVM, precompiles, etc.)
    fn add_well_known_labels(&mut self) {
        // HEVM cheatcode address
        self.labels.insert(
            crate::cheatcodes::HEVM_ADDRESS,
            "VM".to_string(),
        );

        // Console.log address (0x000000000000000000636F6e736F6c652e6c6f67 = "console.log")
        self.labels.insert(
            Address::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63,
                          0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x6c, 0x6f, 0x67]),
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

    /// Add cheatcode function signatures for decoding
    fn add_cheatcode_functions(&mut self) {
        use alloy_json_abi::{Function, Param, StateMutability};

        // Helper to create simple functions
        let make_func = |name: &str, inputs: Vec<(&str, &str)>| -> Function {
            Function {
                name: name.to_string(),
                inputs: inputs.into_iter().map(|(name, ty)| Param {
                    name: name.to_string(),
                    ty: ty.to_string(),
                    internal_type: None,
                    components: vec![],
                }).collect(),
                outputs: vec![],
                state_mutability: StateMutability::NonPayable,
            }
        };

        // Common cheatcodes
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

        // Add common console.log signatures
        self.add_console_log_functions();
    }

    /// Add console.log function signatures (Foundry/Hardhat compatible)
    fn add_console_log_functions(&mut self) {
        use alloy_json_abi::{Function, Param, StateMutability};

        let make_log = |inputs: Vec<&str>| -> Function {
            Function {
                name: "log".to_string(),
                inputs: inputs.into_iter().enumerate().map(|(i, ty)| Param {
                    name: format!("p{}", i),
                    ty: ty.to_string(),
                    internal_type: None,
                    components: vec![],
                }).collect(),
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

        // Two argument logs (common combinations)
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

        // Three argument logs (common combinations)
        self.push_function(make_log(vec!["string", "string", "string"]));
        self.push_function(make_log(vec!["string", "string", "uint256"]));
        self.push_function(make_log(vec!["string", "uint256", "uint256"]));
        self.push_function(make_log(vec!["string", "address", "uint256"]));
        self.push_function(make_log(vec!["string", "address", "address"]));
        self.push_function(make_log(vec!["string", "bool", "bool"]));
        self.push_function(make_log(vec!["address", "address", "uint256"]));
        self.push_function(make_log(vec!["uint256", "uint256", "uint256"]));

        // Four argument logs (common combinations)
        self.push_function(make_log(vec!["string", "string", "string", "string"]));
        self.push_function(make_log(vec!["string", "string", "string", "uint256"]));
        self.push_function(make_log(vec!["string", "uint256", "uint256", "uint256"]));
        self.push_function(make_log(vec!["string", "address", "address", "uint256"]));
        self.push_function(make_log(vec!["uint256", "uint256", "uint256", "uint256"]));
        self.push_function(make_log(vec!["address", "address", "address", "address"]));
    }

    /// Add a deployed contract to the decoder
    pub fn add_contract(&mut self, address: Address, contract: &crate::foundry::CompiledContract) {
        // Add to contracts map
        self.contracts.insert(address, contract.name.clone());
        // Also add as a label
        self.labels.insert(address, contract.name.clone());

        // Add codehash mapping for resolving unknown addresses with same bytecode
        let codehash = alloy_primitives::keccak256(&contract.deployed_bytecode);
        self.codehash_to_name.insert(codehash, contract.name.clone());

        // Add all functions from the contract's ABI
        for func in contract.abi.functions() {
            self.push_function(func.clone());
        }

        // Add all errors from the contract's ABI
        for error in contract.abi.errors() {
            self.push_error(error.clone());
        }

        // Add all events from the contract's ABI
        for event in contract.abi.events() {
            self.push_event(event.clone());
        }
    }

    /// Add a contract by multiple hash methods for robust identification:
    /// 1. CBOR metadata hash (most accurate - based on source hash)
    /// 2. Selector hash (robust against immutables)
    /// 3. Partial codehash (handles linked libraries)
    pub fn add_contract_by_codehash(&mut self, contract: &crate::foundry::CompiledContract) {
        let partial_hash = compute_partial_codehash(&contract.deployed_bytecode);
        let selector_hash = compute_selector_hash(&contract.deployed_bytecode);
        let cbor_hash = compute_cbor_hash(&contract.deployed_bytecode);

        tracing::debug!(
            "TraceDecoder: adding {} - cbor: {:?}, selector: {:?}, partial: {:?} (len: {})",
            contract.name, cbor_hash, selector_hash, partial_hash, contract.deployed_bytecode.len()
        );

        // Add all hash mappings
        self.codehash_to_name.insert(partial_hash, contract.name.clone());
        self.selector_hash_to_name.insert(selector_hash, contract.name.clone());
        if let Some(cbor) = cbor_hash {
            self.cbor_hash_to_name.insert(cbor, contract.name.clone());
        }

        // Add all functions from the contract's ABI
        for func in contract.abi.functions() {
            self.push_function(func.clone());
        }

        // Add all errors from the contract's ABI
        for error in contract.abi.errors() {
            self.push_error(error.clone());
        }

        // Add all events from the contract's ABI
        for event in contract.abi.events() {
            self.push_event(event.clone());
        }
    }

    /// Populate labels from CREATE traces by matching runtime bytecode against known contracts
    /// This handles linked contracts where the compiled deployed_bytecode differs from runtime
    pub fn populate_labels_from_create_traces(&mut self, traces: &CallTraceArena) {
        let created = extract_created_contracts_with_codehash(traces);

        for (addr, codehash) in created {
            // Check if we already have a label for this address
            if self.labels.contains_key(&addr) {
                continue;
            }

            // Try to find a matching contract by codehash
            if let Some(name) = self.codehash_to_name.get(&codehash) {
                tracing::debug!(
                    "Resolved {} to {} via CREATE trace codehash",
                    addr, name
                );
                self.labels.insert(addr, name.clone());
            } else {
                tracing::debug!(
                    "Unknown contract at {} with runtime codehash {:?}",
                    addr, codehash
                );
            }
        }
    }

    /// Add a function to the decoder (handles selector collisions like Foundry)
    pub fn push_function(&mut self, function: Function) {
        let selector = function.selector();
        self.functions
            .entry(selector)
            .or_insert_with(Vec::new)
            .push(function);
    }

    /// Add an error to the decoder (handles selector collisions)
    pub fn push_error(&mut self, error: alloy_json_abi::Error) {
        let selector = error.selector();
        self.errors
            .entry(selector)
            .or_insert_with(Vec::new)
            .push(error);
    }

    /// Add an event to the decoder (handles topic collisions)
    pub fn push_event(&mut self, event: alloy_json_abi::Event) {
        let selector = event.selector();
        self.events
            .entry(selector)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Add a label for an address
    pub fn add_label(&mut self, address: Address, label: String) {
        self.labels.insert(address, label);
    }

    /// Decompile bytecode and cache function signatures using evmole
    /// This enables decoding calls to unverified fork contracts
    pub fn decompile_and_cache(&mut self, bytecode: &[u8]) {
        if bytecode.is_empty() {
            return;
        }

        let decompiled = crate::fork::decompile_abi(bytecode);
        tracing::debug!("Decompiled {} functions from bytecode", decompiled.functions.len());
        for func in &decompiled.functions {
            let selector: FixedBytes<4> = func.selector.into();
            tracing::debug!("  Decompiled: 0x{} -> args: {}", hex::encode(selector), func.arguments);
            // Store the decompiled argument types (e.g., "(uint256,address)")
            self.decompiled_functions.insert(selector, func.arguments.clone());
        }
    }

    /// Look up function signature from Sourcify 4byte database
    /// Returns the human-readable signature (e.g., "transfer(address,uint256)")
    pub fn lookup_4byte(&mut self, selector: &FixedBytes<4>) -> Option<String> {
        // Check cache first
        if let Some(sigs) = self.fourbyte_signatures.get(selector) {
            return sigs.first().cloned();
        }

        // Single selector lookup
        self.lookup_4byte_batch(&[*selector]);
        self.fourbyte_signatures.get(selector).and_then(|s| s.first().cloned())
    }

    /// Look up all function signature candidates from Sourcify 4byte database
    /// Returns all matching signatures for the selector
    pub fn lookup_4byte_candidates(&mut self, selector: &FixedBytes<4>) -> Option<Vec<String>> {
        // Check cache first
        if let Some(sigs) = self.fourbyte_signatures.get(selector) {
            if !sigs.is_empty() {
                return Some(sigs.clone());
            }
        }

        // Single selector lookup
        self.lookup_4byte_batch(&[*selector]);
        self.fourbyte_signatures.get(selector).cloned().filter(|s| !s.is_empty())
    }

    /// Extract argument types from a function signature like "transfer(address,uint256)"
    fn extract_args_from_signature(sig: &str) -> Option<String> {
        let start = sig.find('(')?;
        let end = sig.rfind(')')?;
        if start < end {
            Some(sig[start..=end].to_string())
        } else {
            None
        }
    }

    /// Check if two argument type strings match (handles slight format differences)
    fn args_match(decompiled_args: &str, fourbyte_args: &str) -> bool {
        // Normalize both: remove spaces, handle empty parens
        let norm_decompiled = decompiled_args.replace(' ', "");
        let norm_fourbyte = fourbyte_args.replace(' ', "");
        norm_decompiled == norm_fourbyte
    }

    /// Batch lookup multiple selectors from Sourcify 4byte database in a single API call
    /// Stores ALL candidate signatures for later decoding attempts
    pub fn lookup_4byte_batch(&mut self, selectors: &[FixedBytes<4>]) {
        if selectors.is_empty() {
            return;
        }

        // Filter out already cached selectors
        let unknown: Vec<_> = selectors.iter()
            .filter(|s| !self.fourbyte_signatures.contains_key(*s))
            .collect();

        if unknown.is_empty() {
            return;
        }

        // Build comma-separated list of selectors for batch API
        let selector_list: String = unknown.iter()
            .map(|s| format!("0x{}", hex::encode(s)))
            .collect::<Vec<_>>()
            .join(",");

        // Use filter=false to get ALL candidates, not just the first one
        let url = format!(
            "https://api.4byte.sourcify.dev/signature-database/v1/lookup?filter=false&function={}",
            selector_list
        );

        tracing::debug!("4byte batch lookup for {} selectors", unknown.len());

        // Use blocking reqwest call
        match reqwest::blocking::get(&url) {
            Ok(response) => {
                if let Ok(json) = response.json::<serde_json::Value>() {
                    // Parse the response: {"result": {"function": {"0xa9059cbb": [{"name": "transfer(address,uint256)", ...}]}}}
                    if let Some(functions) = json.get("result")
                        .and_then(|r| r.get("function"))
                        .and_then(|f| f.as_object())
                    {
                        for (selector_str, sigs) in functions {
                            if let Some(sigs_array) = sigs.as_array() {
                                // Parse selector from "0xabcdef12" format
                                let selector_bytes = match hex::decode(selector_str.trim_start_matches("0x")) {
                                    Ok(b) if b.len() == 4 => b,
                                    _ => continue,
                                };
                                let selector: FixedBytes<4> = selector_bytes.as_slice().try_into().unwrap();

                                // Get ALL candidate signatures
                                let candidates: Vec<String> = sigs_array.iter()
                                    .filter_map(|s| s.get("name").and_then(|n| n.as_str()))
                                    .map(|s| s.to_string())
                                    .collect();

                                if candidates.is_empty() {
                                    continue;
                                }

                                // If we have decompiled args, put the matching candidate first
                                let ordered_candidates = if let Some(decompiled_args) = self.decompiled_functions.get(&selector) {
                                    // Find index of matching candidate
                                    let matching_idx = candidates.iter().position(|sig| {
                                        if let Some(fourbyte_args) = Self::extract_args_from_signature(sig) {
                                            Self::args_match(decompiled_args, &fourbyte_args)
                                        } else {
                                            false
                                        }
                                    });

                                    // If found, reorder to put matching first
                                    if let Some(idx) = matching_idx {
                                        let mut reordered = vec![candidates[idx].clone()];
                                        for (i, c) in candidates.iter().enumerate() {
                                            if i != idx {
                                                reordered.push(c.clone());
                                            }
                                        }
                                        reordered
                                    } else {
                                        candidates
                                    }
                                } else {
                                    candidates
                                };

                                tracing::debug!("4byte: {} -> {} candidates: {:?}",
                                    selector_str, ordered_candidates.len(), ordered_candidates);
                                self.fourbyte_signatures.insert(selector, ordered_candidates);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!("4byte batch lookup failed: {}", e);
            }
        }
    }

    /// Parse a function signature string like "transfer(address,uint256)" into a Function object
    pub fn parse_signature_to_function(sig: &str) -> Option<Function> {
        use alloy_json_abi::{Param, StateMutability};

        // Extract function name and params
        let paren_start = sig.find('(')?;
        let paren_end = sig.rfind(')')?;
        if paren_start >= paren_end {
            return None;
        }

        let name = sig[..paren_start].to_string();
        let params_str = &sig[paren_start + 1..paren_end];

        // Parse params (e.g., "address,uint256,bytes32")
        let inputs: Vec<Param> = if params_str.is_empty() {
            vec![]
        } else {
            params_str.split(',')
                .enumerate()
                .map(|(i, ty)| {
                    let ty = ty.trim().to_string();
                    Param {
                        name: format!("arg{}", i),
                        ty,
                        internal_type: None,
                        components: vec![],
                    }
                })
                .collect()
        };

        Some(Function {
            name,
            inputs,
            outputs: vec![],
            state_mutability: StateMutability::NonPayable,
        })
    }

    /// Resolve an address to a label (contract name or hex)
    pub fn resolve_address(&self, addr: &Address) -> String {
        self.labels
            .get(addr)
            .cloned()
            .unwrap_or_else(|| format!("{}", addr))
    }

    /// Resolve an address by looking up its bytecode in VM state
    /// Uses CBOR hash, selector hash, and partial codehash in order of accuracy
    pub fn resolve_address_with_state<DB: revm::Database>(
        &mut self,
        addr: &Address,
        db: &mut DB,
    ) -> String {
        // First check if we already have a label
        if let Some(label) = self.labels.get(addr) {
            return label.clone();
        }

        // Try to look up bytecode from state and compute hashes
        if let Ok(Some(account)) = db.basic(*addr) {
            if let Some(code) = &account.code {
                let bytecode = code.original_bytes();
                if !bytecode.is_empty() {
                    // 1. Try CBOR hash first (most accurate)
                    if let Some(cbor_hash) = compute_cbor_hash(&bytecode) {
                        if let Some(name) = self.cbor_hash_to_name.get(&cbor_hash) {
                            self.labels.insert(*addr, name.clone());
                            return name.clone();
                        }
                    }

                    // 2. Try selector hash (handles immutables)
                    let selector_hash = compute_selector_hash(&bytecode);
                    if let Some(name) = self.selector_hash_to_name.get(&selector_hash) {
                        self.labels.insert(*addr, name.clone());
                        return name.clone();
                    }

                    // 3. Try partial codehash (handles linked libraries)
                    let partial_hash = compute_partial_codehash(&bytecode);
                    if let Some(name) = self.codehash_to_name.get(&partial_hash) {
                        self.labels.insert(*addr, name.clone());
                        return name.clone();
                    }
                }
            }
        }

        // Fallback to hex address
        format!("{}", addr)
    }

    /// Populate labels for all addresses in traces by looking up their bytecode
    /// Tries multiple matching methods in order of accuracy:
    /// 1. CBOR metadata hash (most accurate)
    /// 2. Selector hash (handles immutables)
    /// 3. Partial codehash (handles linked libraries)
    pub fn populate_labels_from_state<DB: revm::Database>(&mut self, traces: &CallTraceArena, db: &mut DB) {
        for node in traces.nodes() {
            let addr = node.trace.address;
            // Skip if already labeled
            if self.labels.contains_key(&addr) {
                continue;
            }

            // Try to resolve by bytecode hashes
            if let Ok(Some(account)) = db.basic(addr) {
                if let Some(code) = &account.code {
                    let bytecode = code.original_bytes();
                    if !bytecode.is_empty() {
                        // 1. Try CBOR metadata hash first (most accurate)
                        if let Some(cbor_hash) = compute_cbor_hash(&bytecode) {
                            if let Some(name) = self.cbor_hash_to_name.get(&cbor_hash) {
                                tracing::debug!(
                                    "Resolved {:?} to {} via CBOR hash {:?}",
                                    addr, name, cbor_hash
                                );
                                self.labels.insert(addr, name.clone());
                                continue;
                            }
                        }

                        // 2. Try selector hash (handles immutables)
                        let selector_hash = compute_selector_hash(&bytecode);
                        if let Some(name) = self.selector_hash_to_name.get(&selector_hash) {
                            tracing::debug!(
                                "Resolved {:?} to {} via selector hash {:?}",
                                addr, name, selector_hash
                            );
                            self.labels.insert(addr, name.clone());
                            continue;
                        }

                        // 3. Try partial codehash (handles linked libraries)
                        let partial_hash = compute_partial_codehash(&bytecode);
                        if let Some(name) = self.codehash_to_name.get(&partial_hash) {
                            tracing::debug!(
                                "Resolved {:?} to {} via partial hash {:?}",
                                addr, name, partial_hash
                            );
                            self.labels.insert(addr, name.clone());
                            continue;
                        }

                        // 4. Unknown contract - use ABI decompiler for function signatures
                        // This enables decoding calls to unverified fork contracts
                        tracing::debug!(
                            "Unknown contract at {:?} - decompiling with evmole",
                            addr
                        );
                        self.decompile_and_cache(&bytecode);
                    }
                }
            }
        }
    }

    /// Select the appropriate function from a list with the same selector
    /// by checking which one can decode the calldata (Foundry's approach)
    fn select_function<'a>(&self, functions: &'a [Function], data: &[u8]) -> Option<&'a Function> {
        if functions.is_empty() {
            return None;
        }

        if functions.len() == 1 {
            return Some(&functions[0]);
        }

        // Try to decode with each function to find the right one
        if data.len() >= SELECTOR_LEN {
            for func in functions {
                if func.abi_decode_input(&data[SELECTOR_LEN..]).is_ok() {
                    return Some(func);
                }
            }
        }

        // Fallback to first function if none decode
        Some(&functions[0])
    }

    /// Decode calldata into human-readable format (Foundry-style)
    pub fn decode_calldata(&self, data: &[u8]) -> DecodedCallData {
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
                // Try to decode the function arguments
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
                        // Show function name with raw data
                        return DecodedCallData {
                            signature: func.signature(),
                            args: vec![format!("0x{}", hex::encode(input_data))],
                        };
                    }
                }
            }
        }

        // Check 4byte database for human-readable signatures
        // Try each candidate until one successfully decodes
        if let Some(candidates) = self.fourbyte_signatures.get(&selector).cloned() {
            let input_data = &data[SELECTOR_LEN..];

            for sig in &candidates {
                if let Some(func) = Self::parse_signature_to_function(sig) {
                    match func.abi_decode_input(input_data) {
                        Ok(decoded_args) => {
                            let args: Vec<String> = decoded_args
                                .iter()
                                .map(|v| self.format_value(v))
                                .collect();
                            return DecodedCallData {
                                signature: sig.clone(),
                                args,
                            };
                        }
                        Err(_) => {
                            // Try next candidate
                            continue;
                        }
                    }
                }
            }

            // None decoded - return first signature with raw args
            if let Some(first_sig) = candidates.first() {
                return DecodedCallData {
                    signature: first_sig.clone(),
                    args: vec![format!("0x{}", hex::encode(input_data))],
                };
            }
        }

        // Check decompiled functions from evmole (fork mode)
        // These store argument types like "(uint256,address)"
        if let Some(args_types) = self.decompiled_functions.get(&selector) {
            // Show as "0xselector(type1,type2)" format
            let selector_hex = hex::encode(&selector[..]);
            return DecodedCallData {
                signature: format!("0x{}{}", selector_hex, args_types),
                args: vec![format!("0x{}", hex::encode(&data[SELECTOR_LEN..]))],
            };
        }

        // Unknown selector - show raw
        DecodedCallData {
            signature: format!("0x{}", hex::encode(&selector[..])),
            args: vec![format!("0x{}", hex::encode(&data[SELECTOR_LEN..]))],
        }
    }

    /// Format a DynSolValue with address label resolution (Foundry-style)
    pub fn format_value(&self, val: &alloy_dyn_abi::DynSolValue) -> String {
        use alloy_dyn_abi::DynSolValue;

        match val {
            DynSolValue::Address(addr) => {
                // Foundry style: "Label: [0x...]" if labeled
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
            DynSolValue::Uint(u, _bits) => {
                // Always show decimal - matches Foundry behavior for function args
                u.to_string()
            }
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

    /// Populate decoded fields on trace nodes (Foundry's pattern)
    /// This fills in `node.trace.decoded` so TraceWriter can render human-readable output
    /// Collect all unique selectors from traces for batch lookup
    pub fn collect_selectors(&self, traces: &CallTraceArena) -> Vec<FixedBytes<4>> {
        let mut selectors = Vec::new();
        for node in traces.nodes() {
            let data = &node.trace.data;
            if data.len() >= SELECTOR_LEN && !node.trace.kind.is_any_create() {
                let selector: FixedBytes<4> = data[..SELECTOR_LEN].try_into().unwrap_or_default();
                if !self.functions.contains_key(&selector)
                    && !self.fourbyte_signatures.contains_key(&selector)
                    && !selectors.contains(&selector)
                {
                    selectors.push(selector);
                }
            }
        }
        selectors
    }

    /// Collect all unique event topic0 hashes from traces for batch lookup
    pub fn collect_event_topics(&self, traces: &CallTraceArena) -> Vec<alloy_primitives::B256> {
        let mut topics = Vec::new();
        for node in traces.nodes() {
            for log in &node.logs {
                if let Some(topic0) = log.raw_log.topics().first() {
                    if !self.events.contains_key(topic0)
                        && !self.fourbyte_events.contains_key(topic0)
                        && !topics.contains(topic0)
                    {
                        topics.push(*topic0);
                    }
                }
            }
        }
        topics
    }

    /// Batch lookup event signatures from Sourcify 4byte database
    pub fn lookup_4byte_events_batch(&mut self, topics: &[alloy_primitives::B256]) {
        if topics.is_empty() {
            return;
        }

        // Filter out already cached
        let unknown: Vec<_> = topics.iter()
            .filter(|t| !self.fourbyte_events.contains_key(*t))
            .collect();

        if unknown.is_empty() {
            return;
        }

        // Build comma-separated list of topic hashes for batch API
        let topic_list: String = unknown.iter()
            .map(|t| format!("0x{}", hex::encode(t)))
            .collect::<Vec<_>>()
            .join(",");

        let url = format!(
            "https://api.4byte.sourcify.dev/signature-database/v1/lookup?filter=true&event={}",
            topic_list
        );

        tracing::debug!("4byte event batch lookup for {} topics", unknown.len());

        match reqwest::blocking::get(&url) {
            Ok(response) => {
                if let Ok(json) = response.json::<serde_json::Value>() {
                    if let Some(events) = json.get("result")
                        .and_then(|r| r.get("event"))
                        .and_then(|e| e.as_object())
                    {
                        for (topic_str, sigs) in events {
                            if let Some(sigs_array) = sigs.as_array() {
                                // Parse topic from "0x..." format
                                let topic_bytes = match hex::decode(topic_str.trim_start_matches("0x")) {
                                    Ok(b) if b.len() == 32 => b,
                                    _ => continue,
                                };
                                let topic: alloy_primitives::B256 = topic_bytes.as_slice().try_into().unwrap();

                                // Get first signature (filter=true returns best match)
                                if let Some(sig) = sigs_array.first()
                                    .and_then(|s| s.get("name"))
                                    .and_then(|n| n.as_str())
                                {
                                    tracing::debug!("4byte event: {} -> {}", topic_str, sig);
                                    self.fourbyte_events.insert(topic, sig.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!("4byte event batch lookup failed: {}", e);
            }
        }
    }

    /// Populate decoded fields on trace nodes with 4byte lookups
    /// This first collects unknown selectors and batch-queries the 4byte database
    pub fn populate_traces_with_4byte(&mut self, traces: &mut CallTraceArena) {
        // Collect and lookup unknown function selectors
        let unknown_selectors = self.collect_selectors(traces);
        if !unknown_selectors.is_empty() {
            tracing::debug!("Looking up {} unknown selectors from 4byte database", unknown_selectors.len());
            self.lookup_4byte_batch(&unknown_selectors);
        }

        // Collect and lookup unknown event topics
        let unknown_topics = self.collect_event_topics(traces);
        if !unknown_topics.is_empty() {
            tracing::debug!("Looking up {} unknown event topics from 4byte database", unknown_topics.len());
            self.lookup_4byte_events_batch(&unknown_topics);
        }

        // Now populate traces with all known signatures
        for node in traces.nodes_mut() {
            self.populate_trace_node(node);
        }
    }

    pub fn populate_traces(&self, traces: &mut CallTraceArena) {
        for node in traces.nodes_mut() {
            self.populate_trace_node(node);
        }
    }

    /// Populate decoded info on a single trace node
    fn populate_trace_node(&self, node: &mut CallTraceNode) {
        let trace = &node.trace;

        // Get or create decoded struct
        let label = self.labels.get(&trace.address).cloned();

        // Decode call data and return data
        let (call_data, return_data) = if trace.kind.is_any_create() {
            // For create calls, don't decode calldata (it's bytecode)
            (None, None)
        } else {
            let decoded = self.decode_calldata(&trace.data);
            let call_data = Some(RevmDecodedCallData {
                signature: decoded.signature.clone(),
                args: decoded.args,
            });

            // Decode return/revert data based on success
            let return_data = if trace.success && !trace.output.is_empty() {
                self.decode_return_data(&decoded.signature, &trace.output)
            } else if !trace.success && !trace.output.is_empty() {
                // For failed calls, decode the revert reason
                self.decode_error_data(&trace.output)
            } else {
                None
            };

            (call_data, return_data)
        };

        // Set decoded on the trace
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

    /// Decode a log/event using known event signatures
    fn decode_log(&self, log: &revm::primitives::LogData) -> Option<revm_inspectors::tracing::types::DecodedCallLog> {
        use revm_inspectors::tracing::types::DecodedCallLog as RevmDecodedCallLog;

        // Need at least topic0 (event signature)
        let topics = log.topics();
        if topics.is_empty() {
            return None;
        }

        let topic0 = topics[0];

        // Check for known event from ABIs
        if let Some(events) = self.events.get(&topic0) {
            if let Some(event) = events.first() {
                // Try to decode the event
                if let Some(decoded) = self.decode_event(event, log) {
                    return Some(decoded);
                }
                // Fallback: just use event name without decoded params
                return Some(RevmDecodedCallLog {
                    name: Some(event.name.clone()),
                    params: None,
                });
            }
        }

        // Check 4byte database for event name
        if let Some(sig) = self.fourbyte_events.get(&topic0) {
            // Extract just the name from "EventName(type1,type2)"
            let name = sig.split('(').next().unwrap_or(sig).to_string();
            return Some(RevmDecodedCallLog {
                name: Some(name),
                params: None,
            });
        }

        None
    }

    /// Decode an event's parameters
    fn decode_event(&self, event: &alloy_json_abi::Event, log: &revm::primitives::LogData) -> Option<revm_inspectors::tracing::types::DecodedCallLog> {
        use revm_inspectors::tracing::types::DecodedCallLog as RevmDecodedCallLog;
        use alloy_dyn_abi::EventExt;

        // Try to decode using alloy
        match event.decode_log(log) {
            Ok(decoded) => {
                let params: Vec<(String, String)> = event.inputs.iter()
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

                Some(RevmDecodedCallLog {
                    name: Some(event.name.clone()),
                    params: Some(params),
                })
            }
            Err(_) => None,
        }
    }

    /// Decode error/revert data using known errors from ABIs
    fn decode_error_data(&self, data: &[u8]) -> Option<String> {
        if data.len() < SELECTOR_LEN {
            return None;
        }

        // First try standard errors (Error(string) and Panic(uint256))
        if let Some(reason) = decode_revert_reason(data) {
            // Check if it decoded to something meaningful (not just raw selector)
            if !reason.starts_with("0x") {
                return Some(reason);
            }
        }

        // Extract selector
        let selector: FixedBytes<4> = data[..SELECTOR_LEN].try_into().ok()?;

        // Try to find matching custom error in our registry
        if let Some(errors) = self.errors.get(&selector) {
            if let Some(error) = errors.first() {
                return Some(self.format_custom_error(error, data));
            }
        }

        // Unknown error - return None to show raw hex
        None
    }

    /// Format a custom error with decoded parameters
    fn format_custom_error(&self, error: &alloy_json_abi::Error, data: &[u8]) -> String {
        // Always include parentheses to show it's a function-like error call
        if error.inputs.is_empty() {
            return format!("{}()", error.name);
        }

        // Try to decode parameters
        if data.len() > SELECTOR_LEN {
            if let Ok(values) = error.abi_decode_input(&data[SELECTOR_LEN..]) {
                let formatted: Vec<String> = error.inputs.iter()
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

        // Fallback to signature with raw data hint
        let sig: String = error.inputs.iter()
            .map(|i| if i.name.is_empty() { i.ty.clone() } else { format!("{} {}", i.ty, i.name) })
            .collect::<Vec<_>>()
            .join(", ");
        format!("{}({}) <decode failed>", error.name, sig)
    }

    /// Decode return data using the function's output types from ABI
    fn decode_return_data(&self, signature: &str, output: &[u8]) -> Option<String> {
        // Special handling for generateCalls(uint256) -> bytes[]
        // Pretty-print the generated calldatas with resolved function names
        if signature == "generateCalls(uint256)" {
            return self.decode_generate_calls_return(output);
        }

        // Extract selector from signature to find the function
        let selector = alloy_primitives::keccak256(signature.as_bytes());
        let selector_bytes: [u8; 4] = selector[..4].try_into().ok()?;
        let selector = alloy_primitives::FixedBytes::<4>::from(selector_bytes);

        // Find the function in our registry
        let functions = self.functions.get(&selector)?;
        let func = functions.first()?;

        // Decode output using the function's outputs
        if func.outputs.is_empty() {
            return None;
        }

        // Try to decode
        match func.abi_decode_output(output) {
            Ok(values) => {
                if values.is_empty() {
                    None
                } else if values.len() == 1 {
                    Some(self.format_value(&values[0]))
                } else {
                    let formatted: Vec<String> = values.iter()
                        .map(|v| self.format_value(v))
                        .collect();
                    Some(format!("({})", formatted.join(", ")))
                }
            }
            Err(_) => None,
        }
    }

    /// Decode the return value of generateCalls(uint256) -> bytes[]
    /// Pretty-prints the generated calldatas with resolved function names
    fn decode_generate_calls_return(&self, output: &[u8]) -> Option<String> {
        use alloy_dyn_abi::DynSolType;

        // Decode as bytes[]
        let bytes_array_type = DynSolType::Array(Box::new(DynSolType::Bytes));
        let decoded = bytes_array_type.abi_decode(output).ok()?;

        if let alloy_dyn_abi::DynSolValue::Array(items) = decoded {
            if items.is_empty() {
                return Some("[]".to_string());
            }

            let mut call_names = Vec::new();
            for item in &items {
                if let alloy_dyn_abi::DynSolValue::Bytes(calldata) = item {
                    if calldata.len() >= 4 {
                        // Extract selector
                        let selector: FixedBytes<4> = calldata[..4].try_into().ok()?;

                        // Look up function name
                        if let Some(functions) = self.functions.get(&selector) {
                            if let Some(func) = functions.first() {
                                call_names.push(format!("{}()", func.name));
                                continue;
                            }
                        }

                        // Fallback to hex selector
                        call_names.push(format!("0x{}", hex::encode(&selector[..])));
                    } else {
                        call_names.push("<empty>".to_string());
                    }
                }
            }

            Some(format!("[{}]", call_names.join(", ")))
        } else {
            None
        }
    }
}

impl Default for TraceDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoded call data (matches Foundry's DecodedCallData)
#[derive(Debug, Clone)]
pub struct DecodedCallData {
    /// Function signature like "transfer(address,uint256)"
    pub signature: String,
    /// Decoded arguments as strings
    pub args: Vec<String>,
}

impl DecodedCallData {
    /// Format as "function(arg1, arg2, ...)"
    pub fn format(&self) -> String {
        if self.args.is_empty() {
            self.signature.clone()
        } else {
            // Extract function name from signature
            let name = self.signature.split('(').next().unwrap_or(&self.signature);
            format!("{}({})", name, self.args.join(", "))
        }
    }
}

/// Configuration for trace output
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Whether to record state diffs (storage changes)
    pub record_state_diff: bool,
    /// Whether to record logs
    pub record_logs: bool,
    /// Whether to record individual opcode steps
    pub record_steps: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            record_state_diff: true,
            record_logs: true,
            record_steps: false, // Usually too verbose for LLM context
        }
    }
}

impl TraceConfig {
    /// Create config optimized for LLM context (call traces + state diffs, no opcode steps)
    pub fn for_llm() -> Self {
        Self {
            record_state_diff: true,
            record_logs: true,
            record_steps: false,
        }
    }

    /// Create config with full debugging (including opcode steps)
    pub fn full_debug() -> Self {
        Self {
            record_state_diff: true,
            record_logs: true,
            record_steps: true,
        }
    }

    /// Convert to revm-inspectors TracingInspectorConfig
    pub fn to_inspector_config(&self) -> TracingInspectorConfig {
        let mut config = TracingInspectorConfig::default_parity();

        if self.record_state_diff {
            config = config.with_state_diffs();
        }

        if self.record_logs {
            config = config.record_logs();
        }

        if self.record_steps {
            config = config.steps();
        }

        config
    }
}

/// Create a new TracingInspector with the given configuration
pub fn create_tracing_inspector(config: &TraceConfig) -> RevmTracingInspector {
    RevmTracingInspector::new(config.to_inspector_config())
}

/// Format traces to a string using TraceWriter
pub fn format_traces(traces: &CallTraceArena, with_storage: bool) -> String {
    let mut output = Vec::new();

    let mut writer = TraceWriter::new(&mut output)
        .use_colors(ColorChoice::Never) // No ANSI colors for LLM context
        .with_storage_changes(with_storage);

    if let Err(e) = writer.write_arena(traces) {
        return format!("Error formatting traces: {}", e);
    }

    String::from_utf8_lossy(&output).to_string()
}

/// Format traces with decoded addresses and function names (Foundry-style)
/// This populates the decoded fields then uses TraceWriter for proper formatting
pub fn format_traces_decoded(traces: &mut CallTraceArena, decoder: &TraceDecoder, with_storage: bool) -> String {
    // Populate decoded fields on all trace nodes (Foundry's pattern)
    decoder.populate_traces(traces);

    // Use TraceWriter for proper formatting (it reads from decoded fields)
    let mut output = Vec::new();

    let mut writer = TraceWriter::new(&mut output)
        .use_colors(ColorChoice::Never) // No ANSI colors for LLM context
        .with_storage_changes(with_storage);

    if let Err(e) = writer.write_arena(traces) {
        return format!("Error formatting traces: {}", e);
    }

    String::from_utf8_lossy(&output).to_string()
}

/// Format traces with decoded addresses, resolving unknown addresses by codehash from state
/// This is the preferred method as it automatically resolves contracts deployed during setUp
pub fn format_traces_decoded_with_state<DB: revm::Database>(
    traces: &mut CallTraceArena,
    decoder: &mut TraceDecoder,
    db: &mut DB,
    with_storage: bool,
) -> String {
    // First, try to resolve addresses from CREATE traces in the trace itself
    // This handles contracts deployed during setUp by matching their runtime bytecode
    decoder.populate_labels_from_create_traces(traces);

    // Then, resolve any remaining unknown addresses by looking up their codehash in state
    decoder.populate_labels_from_state(traces, db);

    // Populate decoded fields on all trace nodes with 4byte lookups
    decoder.populate_traces_with_4byte(traces);

    // Use TraceWriter for proper formatting (it reads from decoded fields)
    let mut output = Vec::new();

    let mut writer = TraceWriter::new(&mut output)
        .use_colors(ColorChoice::Never) // No ANSI colors for LLM context
        .with_storage_changes(with_storage);

    if let Err(e) = writer.write_arena(traces) {
        return format!("Error formatting traces: {}", e);
    }

    String::from_utf8_lossy(&output).to_string()
}

/// Extract storage changes from execution result state
/// Returns: Vec<(address, slot, old_value, new_value)>
pub fn extract_storage_changes<'a>(
    state: impl Iterator<Item = (&'a Address, &'a revm::state::Account)>,
) -> Vec<(Address, U256, U256, U256)> {
    let mut changes = Vec::new();

    for (addr, account) in state {
        for (slot, value) in &account.storage {
            let old = value.original_value();
            let new = value.present_value();
            if old != new {
                changes.push((*addr, *slot, old, new));
            }
        }
    }

    changes
}

/// Extract created contract addresses from traces (for contracts deployed in setUp)
/// Returns: Vec<Address> of all contracts created via CREATE/CREATE2
pub fn extract_created_contracts(traces: &CallTraceArena) -> Vec<Address> {
    let mut created = Vec::new();

    for node in traces.nodes() {
        // Check if this trace is a CREATE call
        if node.trace.kind.is_any_create() {
            // The address field contains the created contract address
            created.push(node.trace.address);
        }
    }

    created
}

/// Normalize bytecode by replacing library link placeholders with zeros
/// Library placeholders in hex look like: __$<34 hex chars>$__ (40 chars total)
/// In raw bytes after hex decode, these become 20 bytes of the placeholder pattern
/// We replace PUSH20 + 20 bytes patterns that look like addresses with zeros
fn normalize_bytecode_for_hash(bytecode: &[u8]) -> Vec<u8> {
    let mut normalized = bytecode.to_vec();

    // PUSH20 opcode is 0x73, followed by 20 bytes of address
    // Look for patterns that might be library addresses and zero them out
    let mut i = 0;
    while i + 21 <= normalized.len() {
        if normalized[i] == 0x73 {
            // Found PUSH20, zero out the next 20 bytes (the address)
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

/// Extract function selectors from bytecode by looking for PUSH4 patterns
/// Returns sorted list of 4-byte selectors found in the bytecode
fn extract_selectors_from_bytecode(bytecode: &[u8]) -> Vec<[u8; 4]> {
    let mut selectors = Vec::new();

    // PUSH4 opcode is 0x63, followed by 4 bytes
    let mut i = 0;
    while i + 5 <= bytecode.len() {
        if bytecode[i] == 0x63 {
            let selector: [u8; 4] = bytecode[i + 1..i + 5].try_into().unwrap_or_default();
            // Filter out common non-selector values (all zeros, all 0xff, etc.)
            if selector != [0, 0, 0, 0] && selector != [0xff, 0xff, 0xff, 0xff] {
                selectors.push(selector);
            }
            i += 5;
        } else {
            i += 1;
        }
    }

    // Sort and deduplicate
    selectors.sort();
    selectors.dedup();
    selectors
}

/// Compute a hash based on function selectors in the bytecode
/// This is more robust than bytecode hash as it's not affected by immutables
fn compute_selector_hash(bytecode: &[u8]) -> alloy_primitives::B256 {
    use alloy_primitives::keccak256;
    let selectors = extract_selectors_from_bytecode(bytecode);

    // Concatenate all selectors and hash
    let mut data = Vec::with_capacity(selectors.len() * 4);
    for sel in selectors {
        data.extend_from_slice(&sel);
    }

    keccak256(&data)
}

/// Extract CBOR metadata hash from the end of bytecode
/// Solidity appends CBOR-encoded metadata at the end of bytecode:
/// Format: ...bytecode... <cbor_data> <2-byte length>
/// The CBOR contains ipfs/bzzr hash of source + compiler info
/// Returns None if no valid CBOR metadata found
pub fn extract_cbor_metadata(bytecode: &[u8]) -> Option<Vec<u8>> {
    if bytecode.len() < 2 {
        return None;
    }

    // Last 2 bytes are the length of CBOR data (big endian)
    let len_bytes = &bytecode[bytecode.len() - 2..];
    let cbor_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

    // Sanity check: CBOR length should be reasonable (typically 32-100 bytes)
    if cbor_len < 10 || cbor_len > 200 || cbor_len + 2 > bytecode.len() {
        return None;
    }

    // Extract the CBOR data
    let cbor_start = bytecode.len() - 2 - cbor_len;
    let cbor_data = &bytecode[cbor_start..bytecode.len() - 2];

    // Verify it looks like valid CBOR (starts with 0xa2 or 0xa3 for map with 2-3 elements)
    if !cbor_data.is_empty() && (cbor_data[0] == 0xa2 || cbor_data[0] == 0xa3 || cbor_data[0] == 0xa1) {
        Some(cbor_data.to_vec())
    } else {
        None
    }
}

/// Compute hash of CBOR metadata for contract identification
/// This is the most accurate method as it's based on source code hash
pub fn compute_cbor_hash(bytecode: &[u8]) -> Option<alloy_primitives::B256> {
    use alloy_primitives::keccak256;
    extract_cbor_metadata(bytecode).map(|cbor| keccak256(&cbor))
}

/// Compute partial codehash from first half of normalized bytecode
/// Normalizes by zeroing out PUSH20 addresses to handle linked libraries
pub fn compute_partial_codehash(bytecode: &[u8]) -> alloy_primitives::B256 {
    use alloy_primitives::keccak256;
    let normalized = normalize_bytecode_for_hash(bytecode);
    let half = normalized.len() / 2;
    // Use at least 32 bytes, but not more than half
    let len = half.max(32).min(normalized.len());
    keccak256(&normalized[..len])
}

/// Extract created contracts with their partial codehash from traces
/// Returns: Vec<(Address, B256)> - address and partial hash of deployed bytecode
/// Uses first half of bytecode to handle linked contracts
pub fn extract_created_contracts_with_codehash(traces: &CallTraceArena) -> Vec<(Address, alloy_primitives::B256)> {
    let mut created = Vec::new();

    for node in traces.nodes() {
        // Check if this trace is a CREATE call
        if node.trace.kind.is_any_create() && node.trace.success {
            let addr = node.trace.address;
            // The output field contains the runtime bytecode for successful CREATE calls
            let runtime_code = &node.trace.output;
            if !runtime_code.is_empty() {
                let partial_hash = compute_partial_codehash(runtime_code);
                tracing::debug!(
                    "CREATE trace: {:?} deployed with partial hash {:?} (runtime len: {})",
                    addr, partial_hash, runtime_code.len()
                );
                created.push((addr, partial_hash));
            }
        }
    }

    created
}

/// Format storage changes for display
pub fn format_storage_changes(changes: &[(Address, U256, U256, U256)]) -> String {
    format_storage_changes_with_labels(changes, &HashMap::new())
}

/// Format storage changes with address label resolution
pub fn format_storage_changes_with_labels(
    changes: &[(Address, U256, U256, U256)],
    labels: &HashMap<Address, String>,
) -> String {
    if changes.is_empty() {
        return String::new();
    }

    let mut output = String::from("Storage Changes:\n");

    for (addr, slot, old, new) in changes {
        // Resolve address to label or use hex
        let addr_display = labels
            .get(addr)
            .cloned()
            .unwrap_or_else(|| format!("{}", addr));

        // Format values - show decimal for small, hex for large
        let old_str = if *old == U256::ZERO {
            "0".to_string()
        } else if *old < U256::from(10000) {
            old.to_string()
        } else {
            format!("{:#x}", old)
        };

        let new_str = if *new == U256::ZERO {
            "0".to_string()
        } else if *new < U256::from(10000) {
            new.to_string()
        } else {
            format!("{:#x}", new)
        };

        // Format slot - show decimal for small slots (common), hex otherwise
        let slot_str = if *slot < U256::from(100) {
            format!("{}", slot)
        } else {
            format!("{:#x}", slot)
        };

        output.push_str(&format!(
            "  {} [slot {}]: {} → {}\n",
            addr_display, slot_str, old_str, new_str
        ));
    }

    output
}

/// Decode revert reason from output bytes
/// Handles Error(string), Panic(uint256), and custom errors
pub fn decode_revert_reason(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    // Check for Error(string) selector: 0x08c379a0
    if data[0..4] == [0x08, 0xc3, 0x79, 0xa0] && data.len() >= 68 {
        // Skip selector (4) + offset (32) = data starts at 36
        // Next 32 bytes is string length
        let string_len = if data.len() >= 68 {
            let len_bytes = &data[36..68];
            u32::from_be_bytes([len_bytes[28], len_bytes[29], len_bytes[30], len_bytes[31]])
                as usize
        } else {
            return None;
        };

        if data.len() >= 68 + string_len {
            return String::from_utf8(data[68..68 + string_len].to_vec())
                .ok()
                .map(|s| format!("\"{}\"", s));
        }
    }

    // Check for Panic(uint256) selector: 0x4e487b71
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

    // Unknown error - show the selector
    let selector = hex::encode(&data[0..4]);
    Some(format!("0x{}", selector))
}

/// Extract vm.label() calls from traces
/// Parses trace nodes for calls to HEVM_ADDRESS with selector 0xc657c718 (label(address,string))
/// Returns HashMap<Address, String> of labeled addresses
pub fn extract_labels_from_traces(traces: &CallTraceArena) -> HashMap<Address, String> {
    use alloy_sol_types::SolValue;

    let mut labels = HashMap::new();
    let hevm_address = crate::cheatcodes::HEVM_ADDRESS;
    // label(address,string) selector
    let label_selector: [u8; 4] = [0xc6, 0x57, 0xc7, 0x18];

    for node in traces.nodes() {
        // Check if this is a call to HEVM_ADDRESS
        if node.trace.address == hevm_address {
            let data = &node.trace.data;
            // Check for label selector
            if data.len() >= 4 && data[0..4] == label_selector {
                // Decode label(address,string) arguments
                // ABI encoded: address (32 bytes) + string offset (32 bytes) + string length + string data
                if let Ok((address, label)) = <(Address, String)>::abi_decode(&data[4..]) {
                    labels.insert(address, label);
                }
            }
        }
    }

    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_config_default() {
        let config = TraceConfig::default();
        assert!(config.record_state_diff);
        assert!(config.record_logs);
        assert!(!config.record_steps);
    }

    #[test]
    fn test_trace_config_to_inspector_config() {
        let config = TraceConfig::for_llm();
        let inspector_config = config.to_inspector_config();
        // TracingInspectorConfig fields are not public, but we can verify it compiles
        assert!(inspector_config.record_state_diff);
    }

    #[test]
    fn test_format_empty_storage_changes() {
        let changes: Vec<(Address, U256, U256, U256)> = vec![];
        let output = format_storage_changes(&changes);
        assert!(output.is_empty());
    }
}
