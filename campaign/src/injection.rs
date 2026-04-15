//! Sequence injection API for LLM-guided fuzzing
//!
//! Handles parsing LLM-generated transaction sequences and injecting them into the corpus.
//! Supports complex Solidity types including structs, arrays, and nested types.

use alloy_dyn_abi::{DynSolType, DynSolValue, Specifier};
use alloy_json_abi::JsonAbi;
use alloy_primitives::{Address, U256};
use anyhow::{anyhow, Context, Result};
use evm::{
    exec::{CoverageMap, EvmState},
    types::{Tx, TxCall, TxResult},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// JSON representation of a transaction for LLM interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTransaction {
    /// Function signature, e.g., "deposit(uint256)"
    pub function: String,

    /// Arguments as JSON values (will be parsed according to function signature)
    pub args: Vec<serde_json::Value>,

    /// Sender address (hex string)
    #[serde(default)]
    pub sender: Option<String>,

    /// ETH value to send (decimal string)
    #[serde(default)]
    pub value: Option<String>,

    /// Time and block delay as [time_secs, blocks]
    #[serde(default)]
    pub delay: Option<[u64; 2]>,

    /// If true, this is a cheatcode call (warp, roll, prank, etc.)
    #[serde(default)]
    pub cheatcode: bool,
}

/// JSON representation of a sequence from LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSequence {
    /// List of transactions
    pub transactions: Vec<JsonTransaction>,

    /// Optional reasoning from LLM (for debugging)
    #[serde(default)]
    pub reasoning: Option<String>,
}

/// Result of executing an LLM-generated sequence
#[derive(Debug)]
pub struct ExecutionResult {
    /// Whether new coverage was found
    pub found_new_coverage: bool,

    /// Number of new coverage points
    pub new_coverage_points: usize,

    /// Transaction results
    pub tx_results: Vec<TxResult>,
}

/// Registry for parsing function signatures and types
pub struct TypeRegistry {
    /// Function name -> (param_types, return_types)
    functions: HashMap<String, (Vec<DynSolType>, Vec<DynSolType>)>,

    /// Known sender addresses
    senders: Vec<Address>,

    /// Default target address
    default_target: Address,
}

impl TypeRegistry {
    /// Create a new type registry from contract ABIs
    pub fn from_abis(abis: &[(Address, &JsonAbi)], senders: Vec<Address>) -> Self {
        let mut functions = HashMap::new();
        let mut default_target = Address::ZERO;

        for (addr, abi) in abis {
            if default_target == Address::ZERO {
                default_target = *addr;
            }

            for func in abi.functions() {
                let sig = format!(
                    "{}({})",
                    func.name,
                    func.inputs
                        .iter()
                        .map(|p| p.ty.clone())
                        .collect::<Vec<_>>()
                        .join(",")
                );

                let param_types: Vec<DynSolType> = func
                    .inputs
                    .iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();

                let return_types: Vec<DynSolType> = func
                    .outputs
                    .iter()
                    .filter_map(|p| p.resolve().ok())
                    .collect();

                functions.insert(sig.clone(), (param_types.clone(), return_types.clone()));
                // Also register by name only for convenience
                functions.insert(func.name.clone(), (param_types, return_types));
            }
        }

        Self {
            functions,
            senders,
            default_target,
        }
    }

    /// Parse a function signature and return parameter types
    pub fn get_param_types(&self, function: &str) -> Option<&Vec<DynSolType>> {
        self.functions.get(function).map(|(params, _)| params)
    }
}

/// Strip JavaScript-style comments from JSON string
/// LLMs sometimes add `// comment` at end of lines which breaks JSON parsing
fn strip_json_comments(json: &str) -> String {
    let mut result = String::with_capacity(json.len());
    let mut in_string = false;
    let mut escape_next = false;
    let mut chars = json.chars().peekable();

    while let Some(c) = chars.next() {
        if escape_next {
            result.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => {
                result.push(c);
                escape_next = true;
            }
            '"' => {
                in_string = !in_string;
                result.push(c);
            }
            '/' if !in_string => {
                // Check for // comment
                if chars.peek() == Some(&'/') {
                    // Skip until end of line
                    for nc in chars.by_ref() {
                        if nc == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                } else {
                    result.push(c);
                }
            }
            _ => result.push(c),
        }
    }

    result
}

/// Sequence injector for LLM-guided fuzzing
pub struct SequenceInjector {
    /// Type registry for parsing
    type_registry: TypeRegistry,
}

impl SequenceInjector {
    /// Create a new sequence injector
    pub fn new(type_registry: TypeRegistry) -> Self {
        Self { type_registry }
    }

    /// Parse a JSON sequence string into transactions
    pub fn parse_sequence(&self, json: &str) -> Result<Vec<Tx>> {
        // Pre-process: strip JavaScript-style comments (// ...) that LLMs sometimes add
        let cleaned = strip_json_comments(json);

        let seq: JsonSequence = serde_json::from_str(&cleaned).map_err(|e| {
            let err_str = e.to_string();
            // Provide better guidance for common LLM mistakes
            if err_str.contains("duplicate field") {
                anyhow!(
                    "{}. HINT: Don't combine cheatcode and regular call in one object! Use SEPARATE transactions:\n\
                    WRONG: {{\"function\": \"foo\", \"cheatcode\": true, \"function\": \"prank\"}}\n\
                    RIGHT: {{\"cheatcode\": true, \"function\": \"prank(address)\", \"args\": [\"0x...\"]}},\n\
                           {{\"function\": \"foo\", \"args\": [...], \"sender\": \"0x...\"}}",
                    err_str
                )
            } else {
                anyhow!("Failed to parse JSON sequence: {}", err_str)
            }
        })?;

        self.parse_json_sequence(&seq)
    }

    /// Parse a JsonSequence into transactions
    pub fn parse_json_sequence(&self, seq: &JsonSequence) -> Result<Vec<Tx>> {
        let mut txs = Vec::new();

        for (i, jtx) in seq.transactions.iter().enumerate() {
            let tx = self
                .parse_json_tx(jtx)
                .with_context(|| format!("Failed to parse transaction {}", i))?;
            txs.push(tx);
        }

        Ok(txs)
    }

    /// Parse a single JSON transaction
    fn parse_json_tx(&self, jtx: &JsonTransaction) -> Result<Tx> {
        // Parse sender
        let src = if let Some(sender_str) = &jtx.sender {
            sender_str.parse().context("Invalid sender address")?
        } else if !self.type_registry.senders.is_empty() {
            self.type_registry.senders[0]
        } else {
            Address::ZERO
        };

        // Parse value
        let value = if let Some(value_str) = &jtx.value {
            U256::from_str_radix(
                value_str.trim_start_matches("0x"),
                if value_str.starts_with("0x") { 16 } else { 10 },
            )
            .unwrap_or(U256::ZERO)
        } else {
            U256::ZERO
        };

        // Parse delay
        let delay = jtx.delay.unwrap_or([0, 0]);

        // Handle cheatcodes specially
        if jtx.cheatcode {
            return self.parse_cheatcode(jtx, src, delay);
        }

        // Parse function call
        let (name, args) = self.parse_function_call(&jtx.function, &jtx.args)?;

        Ok(Tx {
            call: TxCall::SolCall { name, args },
            src,
            dst: self.type_registry.default_target,
            gas: 30_000_000,
            gasprice: U256::ZERO,
            value,
            delay: (delay[0], delay[1]),
        })
    }

    /// Parse a cheatcode call
    fn parse_cheatcode(&self, jtx: &JsonTransaction, src: Address, delay: [u64; 2]) -> Result<Tx> {
        let hevm_address = Address::from_slice(&[
            0x71, 0x09, 0x70, 0x9E, 0xCf, 0xa9, 0x1a, 0x80, 0x62, 0x6f, 0xF3, 0x98, 0x9D, 0x68,
            0xf6, 0x7F, 0x5b, 0x1D, 0xD1, 0x2D,
        ]);

        // Parse function name from signature
        let func_name = jtx.function.split('(').next().unwrap_or(&jtx.function);

        let args = match func_name {
            "warp" => {
                // warp(uint256 timestamp)
                let ts = self.parse_json_value(
                    &jtx.args.get(0).cloned().unwrap_or_default(),
                    &DynSolType::Uint(256),
                )?;
                vec![ts]
            }
            "roll" => {
                // roll(uint256 blockNumber)
                let bn = self.parse_json_value(
                    &jtx.args.get(0).cloned().unwrap_or_default(),
                    &DynSolType::Uint(256),
                )?;
                vec![bn]
            }
            "prank" => {
                // prank(address sender)
                let addr = self.parse_json_value(
                    &jtx.args.get(0).cloned().unwrap_or_default(),
                    &DynSolType::Address,
                )?;
                vec![addr]
            }
            "deal" => {
                // deal(address who, uint256 newBalance)
                let who = self.parse_json_value(
                    &jtx.args.get(0).cloned().unwrap_or_default(),
                    &DynSolType::Address,
                )?;
                let bal = self.parse_json_value(
                    &jtx.args.get(1).cloned().unwrap_or_default(),
                    &DynSolType::Uint(256),
                )?;
                vec![who, bal]
            }
            _ => {
                return Err(anyhow!("Unknown cheatcode: {}", func_name));
            }
        };

        Ok(Tx {
            call: TxCall::SolCall {
                name: jtx.function.clone(),
                args,
            },
            src,
            dst: hevm_address,
            gas: 30_000_000,
            gasprice: U256::ZERO,
            value: U256::ZERO,
            delay: (delay[0], delay[1]),
        })
    }

    /// Parse a function call with arguments
    fn parse_function_call(
        &self,
        function: &str,
        args: &[serde_json::Value],
    ) -> Result<(String, Vec<DynSolValue>)> {
        // Get parameter types from registry
        let param_types = self
            .type_registry
            .get_param_types(function)
            .ok_or_else(|| anyhow!("Unknown function: {}", function))?;

        if args.len() != param_types.len() {
            return Err(anyhow!(
                "Argument count mismatch for {}: expected {}, got {}",
                function,
                param_types.len(),
                args.len()
            ));
        }

        let mut parsed_args = Vec::new();
        for (arg, ty) in args.iter().zip(param_types.iter()) {
            let value = self
                .parse_json_value(arg, ty)
                .with_context(|| format!("Failed to parse argument for type {:?}", ty))?;
            parsed_args.push(value);
        }

        // Extract function name (without params) for the call
        let name = function.split('(').next().unwrap_or(function).to_string();

        Ok((name, parsed_args))
    }

    /// Parse a JSON value into a DynSolValue according to the expected type
    fn parse_json_value(&self, value: &serde_json::Value, ty: &DynSolType) -> Result<DynSolValue> {
        match ty {
            DynSolType::Uint(bits) => {
                let s = value
                    .as_str()
                    .or_else(|| value.as_u64().map(|_| ""))
                    .ok_or_else(|| anyhow!("Expected string or number for uint"))?;

                let n = if let Some(n) = value.as_u64() {
                    U256::from(n)
                } else if s.starts_with("0x") {
                    U256::from_str_radix(&s[2..], 16)?
                } else {
                    U256::from_str_radix(s, 10)?
                };

                Ok(DynSolValue::Uint(n, *bits))
            }
            DynSolType::Int(bits) => {
                let s = value
                    .as_str()
                    .or_else(|| value.as_i64().map(|_| ""))
                    .ok_or_else(|| anyhow!("Expected string or number for int"))?;

                let n = if let Some(n) = value.as_i64() {
                    alloy_primitives::I256::try_from(n)?
                } else {
                    alloy_primitives::I256::from_dec_str(s)?
                };

                Ok(DynSolValue::Int(n, *bits))
            }
            DynSolType::Address => {
                let s = value
                    .as_str()
                    .ok_or_else(|| anyhow!("Expected string for address"))?;
                let addr: Address = s.parse().map_err(|_| {
                    anyhow!(
                        "Invalid address '{}'. Use hex format: 0x... (40 hex chars)",
                        s
                    )
                })?;
                Ok(DynSolValue::Address(addr))
            }
            DynSolType::Bool => {
                // Accept both JSON boolean and string "true"/"false"
                let b = if let Some(b) = value.as_bool() {
                    b
                } else if let Some(s) = value.as_str() {
                    match s.to_lowercase().as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(anyhow!("Expected boolean, got string: {}", s)),
                    }
                } else {
                    return Err(anyhow!("Expected boolean"));
                };
                Ok(DynSolValue::Bool(b))
            }
            DynSolType::Bytes => {
                let s = value
                    .as_str()
                    .ok_or_else(|| anyhow!("Expected hex string for bytes"))?;
                let hex_str = s.trim_start_matches("0x");
                // Pad odd-length hex strings with leading zero (e.g., "0x0" -> "00")
                let padded = if hex_str.len() % 2 == 1 {
                    format!("0{}", hex_str)
                } else {
                    hex_str.to_string()
                };
                let bytes = hex::decode(&padded)?;
                Ok(DynSolValue::Bytes(bytes.into()))
            }
            DynSolType::String => {
                let s = value.as_str().ok_or_else(|| anyhow!("Expected string"))?;
                Ok(DynSolValue::String(s.to_string()))
            }
            DynSolType::Array(inner) => {
                // Try as JSON array first, then try parsing string as array
                let arr = if let Some(arr) = value.as_array() {
                    arr.clone()
                } else if let Some(s) = value.as_str() {
                    // LLM often sends "[1, 2, 3]" as string - parse it
                    serde_json::from_str(s)
                        .map_err(|_| anyhow!("Expected array, got string: {}", s))?
                } else {
                    return Err(anyhow!("Expected array"));
                };
                let values: Result<Vec<_>> = arr
                    .iter()
                    .map(|v| self.parse_json_value(v, inner))
                    .collect();
                Ok(DynSolValue::Array(values?))
            }
            DynSolType::FixedArray(inner, len) => {
                let arr = value.as_array().ok_or_else(|| anyhow!("Expected array"))?;
                if arr.len() != *len {
                    return Err(anyhow!("Expected {} elements, got {}", len, arr.len()));
                }
                let values: Result<Vec<_>> = arr
                    .iter()
                    .map(|v| self.parse_json_value(v, inner))
                    .collect();
                Ok(DynSolValue::FixedArray(values?))
            }
            DynSolType::Tuple(types) => {
                // Accept both arrays and objects (LLM sometimes uses named fields)
                let arr: Vec<serde_json::Value> = if let Some(arr) = value.as_array() {
                    arr.clone()
                } else if let Some(obj) = value.as_object() {
                    // Convert object to array (values in insertion order)
                    obj.values().cloned().collect()
                } else if let Some(s) = value.as_str() {
                    // LLM might send tuple as string "[...]" or "{...}"
                    serde_json::from_str(s)
                        .map_err(|_| anyhow!("Expected array for tuple, got string: {}", s))?
                } else {
                    return Err(anyhow!("Expected array for tuple"));
                };

                if arr.len() != types.len() {
                    return Err(anyhow!(
                        "Tuple size mismatch: expected {} elements, got {}",
                        types.len(),
                        arr.len()
                    ));
                }
                let values: Result<Vec<_>> = arr
                    .iter()
                    .zip(types.iter())
                    .map(|(v, t)| self.parse_json_value(v, t))
                    .collect();
                Ok(DynSolValue::Tuple(values?))
            }
            DynSolType::FixedBytes(len) => {
                let s = value
                    .as_str()
                    .ok_or_else(|| anyhow!("Expected hex string for fixed bytes"))?;
                let hex_str = s.trim_start_matches("0x");
                // Pad odd-length hex strings with leading zero
                let padded = if hex_str.len() % 2 == 1 {
                    format!("0{}", hex_str)
                } else {
                    hex_str.to_string()
                };
                let bytes = hex::decode(&padded)?;
                if bytes.len() != *len {
                    return Err(anyhow!("Expected {} bytes, got {}", len, bytes.len()));
                }
                // Create appropriate fixed bytes based on size
                match *len {
                    32 => Ok(DynSolValue::FixedBytes(
                        alloy_primitives::FixedBytes::<32>::from_slice(&bytes),
                        32,
                    )),
                    _ => {
                        // For other sizes, pad to 32 bytes
                        let mut padded = [0u8; 32];
                        padded[..bytes.len()].copy_from_slice(&bytes);
                        Ok(DynSolValue::FixedBytes(
                            alloy_primitives::FixedBytes::<32>::from(padded),
                            *len,
                        ))
                    }
                }
            }
            _ => Err(anyhow!("Unsupported type: {:?}", ty)),
        }
    }

    /// Execute a sequence and check for new coverage
    pub fn execute_and_check(
        &self,
        vm: &mut EvmState,
        seq: &[Tx],
        coverage_ref: &Arc<RwLock<CoverageMap>>,
        codehash_map: &Arc<RwLock<evm::coverage::MetadataToCodehash>>,
    ) -> Result<ExecutionResult> {
        let mut tx_results = Vec::new();
        let mut found_new_coverage = false;
        let mut total_new_points = 0;

        for tx in seq {
            let (result, new_cov) = vm.exec_tx_check_new_cov(tx, coverage_ref, codehash_map)?;
            tx_results.push(result);

            if new_cov {
                found_new_coverage = true;
                total_new_points += 1;
            }
        }

        Ok(ExecutionResult {
            found_new_coverage,
            new_coverage_points: total_new_points,
            tx_results,
        })
    }

    /// Inject a sequence into the corpus if it found new coverage
    pub fn inject_if_novel(
        &self,
        seq: Vec<Tx>,
        corpus: &Arc<RwLock<Vec<(usize, Vec<Tx>)>>>,
        corpus_seen: &Arc<RwLock<HashSet<u64>>>,
        ncallseqs: usize,
    ) -> bool {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Compute hash of sequence
        let mut hasher = DefaultHasher::new();
        for tx in &seq {
            // Hash relevant fields
            format!("{:?}", tx.call).hash(&mut hasher);
            tx.src.hash(&mut hasher);
            tx.dst.hash(&mut hasher);
        }
        let seq_hash = hasher.finish();

        // Check if already seen
        {
            let seen = corpus_seen.read();
            if seen.contains(&seq_hash) {
                return false;
            }
        }

        // Add to corpus with priority
        {
            let mut seen = corpus_seen.write();
            seen.insert(seq_hash);
        }

        {
            let mut corpus = corpus.write();
            corpus.push((ncallseqs, seq));
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_sequence() {
        let json = r#"{
            "transactions": [
                {
                    "function": "deposit",
                    "args": ["1000"],
                    "sender": "0x0000000000000000000000000000000000000001"
                }
            ]
        }"#;

        // Would need a proper type registry to fully test
        let seq: JsonSequence = serde_json::from_str(json).unwrap();
        assert_eq!(seq.transactions.len(), 1);
        assert_eq!(seq.transactions[0].function, "deposit");
    }

    #[test]
    fn test_parse_cheatcode_sequence() {
        let json = r#"{
            "transactions": [
                {
                    "function": "warp(uint256)",
                    "args": ["604801"],
                    "cheatcode": true
                }
            ],
            "reasoning": "Advance time past lockup period"
        }"#;

        let seq: JsonSequence = serde_json::from_str(json).unwrap();
        assert!(seq.transactions[0].cheatcode);
        assert_eq!(seq.reasoning.unwrap(), "Advance time past lockup period");
    }
}
