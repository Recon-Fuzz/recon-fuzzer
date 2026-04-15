//! Slither/Recon-Generate Info Parsing
//!
//! Parses the JSON output from `recon-generate info {Contract} --json`
//! which provides the same data as Slither's echidna printer.

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{I256, U256};
use primitives::{INITIAL_BLOCK_NUMBER, INITIAL_TIMESTAMP};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::process::Command;

/// Constant value from source analysis
#[derive(Debug, Clone, Deserialize)]
pub struct ConstantValue {
    pub value: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

/// Assert location in source
#[derive(Debug, Clone, Deserialize)]
pub struct AssertLocation {
    pub start: usize,
    pub length: usize,
    pub filename_relative: String,
    pub filename_absolute: String,
    pub filename_short: String,
    pub is_dependency: bool,
    pub lines: Vec<usize>,
    pub starting_column: usize,
    pub ending_column: usize,
}

/// Function relations (impacts and is_impacted_by)
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionRelations {
    pub impacts: Vec<String>,
    pub is_impacted_by: Vec<String>,
    /// External call target (e.g., "Counter::finalStep()")
    /// Used to trace wrapper functions back to their underlying contract functions
    #[serde(default)]
    pub external: Option<String>,
}

/// Coverage mapping for a function (lines to cover for 100% coverage)
/// Includes lines in the function itself and any called functions (children)
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionCoverageMap {
    /// Line numbers that must be covered (as strings from JSON)
    pub lines: Vec<String>,
    /// Absolute path to the source file
    #[serde(rename = "absolutePath")]
    pub absolute_path: String,
    /// Child function coverage (for internal/external calls)
    #[serde(default)]
    pub children: Vec<FunctionCoverageMap>,
}

impl FunctionCoverageMap {
    /// Get all lines flattened (including children) as usize
    pub fn all_lines(&self) -> Vec<(String, usize)> {
        let mut result = Vec::new();

        // Add own lines
        for line_str in &self.lines {
            if let Ok(line) = line_str.parse::<usize>() {
                result.push((self.absolute_path.clone(), line));
            }
        }

        // Add children's lines recursively
        for child in &self.children {
            result.extend(child.all_lines());
        }

        result
    }

    /// Total line count (including children)
    pub fn total_lines(&self) -> usize {
        self.lines.len() + self.children.iter().map(|c| c.total_lines()).sum::<usize>()
    }
}

/// Slither/Recon-Generate info output
/// Matches the JSON format from `recon-generate info {Contract} --json`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SlitherInfo {
    /// Payable functions by contract
    #[serde(default)]
    pub payable: HashMap<String, Vec<String>>,

    /// Assertion locations by contract and function
    #[serde(default, rename = "assert")]
    pub asserts: HashMap<String, HashMap<String, Vec<AssertLocation>>>,

    /// Constant/pure functions by contract
    #[serde(default)]
    pub constant_functions: HashMap<String, Vec<String>>,

    /// Constants used in each function
    /// Structure: Contract -> Function -> [[ConstantValue]]
    #[serde(
        default,
        alias = "constant_values",
        deserialize_with = "deserialize_constants_used"
    )]
    pub constants_used: HashMap<String, HashMap<String, Vec<ConstantValue>>>,

    /// Function relations (what functions impact what)
    #[serde(default)]
    pub functions_relations: HashMap<String, HashMap<String, FunctionRelations>>,

    /// Contracts with fallback defined
    #[serde(default)]
    pub with_fallback: Vec<String>,

    /// Contracts with receive defined
    #[serde(default)]
    pub with_receive: Vec<String>,

    /// Coverage map: lines that must be covered for each function
    /// Structure: Contract -> Function -> FunctionCoverageMap
    #[serde(default)]
    pub coverage_map: HashMap<String, HashMap<String, FunctionCoverageMap>>,

    /// Inheritance information: Contract -> list of inherited contracts/interfaces
    /// E.g. "SpokeInstance": ["Spoke", "ISpoke", "ISpokeBase", ...]
    /// Useful for interface-to-implementation matching
    #[serde(default)]
    pub inheritances: HashMap<String, Vec<String>>,

    /// Functions to exclude from fuzzing (e.g., callback handlers like "onCallback")
    /// Contains function names WITHOUT parameters (e.g., "onCallback", "onFlashLoan")
    /// These functions should not be called directly by the fuzzer since they are
    /// meant to be triggered by callbacks during reentrancy testing.
    #[serde(default)]
    pub exclude_from_fuzzing: Vec<String>,
}

/// Custom deserializer for constants_used which has nested arrays
fn deserialize_constants_used<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, HashMap<String, Vec<ConstantValue>>>, D::Error>
where
    D: Deserializer<'de>,
{
    // The actual JSON structure is: Contract -> Function -> [[ConstantValue]]
    // We need to flatten the inner array
    let raw: HashMap<String, HashMap<String, Vec<Vec<ConstantValue>>>> =
        HashMap::deserialize(deserializer)?;

    let mut result = HashMap::new();
    for (contract, functions) in raw {
        let mut func_map = HashMap::new();
        for (func_name, nested_constants) in functions {
            // Flatten [[ConstantValue]] to [ConstantValue]
            let flattened: Vec<ConstantValue> = nested_constants.into_iter().flatten().collect();
            func_map.insert(func_name, flattened);
        }
        result.insert(contract, func_map);
    }

    Ok(result)
}

impl SlitherInfo {
    /// Run `recon-generate info {contract} --json` and parse output
    /// Returns Result for better error handling
    pub fn load_from_recon_generate(
        project_path: &str,
        contract_name: &str,
    ) -> anyhow::Result<Self> {
        let output = Command::new("npx")
            .args([
                "-y",
                "recon-generate@latest",
                "info",
                contract_name,
                "--json",
            ])
            .current_dir(project_path)
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run recon-generate: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("recon-generate info failed: {}", stderr);
        }

        let json = String::from_utf8(output.stdout)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in recon-generate output: {}", e))?;

        Self::from_json_str(&json)
    }

    /// Run `recon-generate info {contract} --json` and parse output (Option version)
    pub fn from_recon_generate(project_path: &str, contract_name: &str) -> Option<Self> {
        Self::load_from_recon_generate(project_path, contract_name).ok()
    }

    /// Parse SlitherInfo from JSON string (Result version)
    pub fn from_json_str(json: &str) -> anyhow::Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| anyhow::anyhow!("Failed to parse slither info JSON: {}", e))
    }

    /// Parse SlitherInfo from JSON string (Option version for backwards compatibility)
    pub fn from_json(json: &str) -> Option<Self> {
        Self::from_json_str(json).ok()
    }

    /// Get all constants across all contracts and functions
    pub fn all_constants(&self) -> Vec<&ConstantValue> {
        self.constants_used
            .values()
            .flat_map(|funcs| funcs.values().flatten())
            .collect()
    }

    /// Get functions with assertions for a contract
    pub fn assert_functions(&self, contract: &str) -> Vec<String> {
        self.asserts
            .get(contract)
            .map(|funcs| {
                funcs
                    .iter()
                    .filter(|(_, locs)| !locs.is_empty())
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Resolve wrapper function relations by tracing through external calls
    ///
    /// For wrapper contracts like CryticTester, the wrapper functions (e.g., counter_finalStep)
    /// have empty impacts/is_impacted_by because they just delegate to the underlying contract.
    /// The `external` field tells us which Contract::function() they call.
    ///
    /// This method:
    /// 1. Builds a reverse map: "Contract::function()" -> "wrapper_function()"
    /// 2. For each wrapper function, looks up its external target's relations
    /// 3. Maps those relations back to wrapper function names
    ///
    /// Returns: HashMap<wrapper_function_sig, ResolvedRelations>
    pub fn resolve_wrapper_relations(
        &self,
        wrapper_contract: &str,
    ) -> HashMap<String, ResolvedRelations> {
        let mut result = HashMap::new();

        // Get wrapper contract's function relations
        let Some(wrapper_relations) = self.functions_relations.get(wrapper_contract) else {
            return result;
        };

        // Build reverse map: "Contract::function()" -> "wrapper_function()"
        let mut external_to_wrapper: HashMap<String, String> = HashMap::new();
        for (wrapper_fn, relations) in wrapper_relations {
            if let Some(external) = &relations.external {
                external_to_wrapper.insert(external.clone(), wrapper_fn.clone());
            }
        }

        // For each wrapper function with an external call
        for (wrapper_fn, relations) in wrapper_relations {
            let Some(external) = &relations.external else {
                continue;
            };

            // Parse "Contract::function(args)" into (contract, function_sig)
            let Some((contract, func_sig)) = parse_external_ref(external) else {
                continue;
            };

            // Look up the underlying contract's function relations
            let Some(contract_relations) = self.functions_relations.get(contract) else {
                continue;
            };

            let Some(func_relations) = contract_relations.get(func_sig) else {
                continue;
            };

            // Map impacts back to wrapper functions
            let local_impacts: Vec<String> = func_relations
                .impacts
                .iter()
                .filter_map(|impact| {
                    // impact is like "stepB(uint256)" - need to find wrapper for "Contract::stepB(uint256)"
                    let external_ref = format!("{}::{}", contract, impact);
                    external_to_wrapper.get(&external_ref).cloned()
                })
                .collect();

            // Map is_impacted_by back to wrapper functions
            let local_is_impacted_by: Vec<String> = func_relations
                .is_impacted_by
                .iter()
                .filter_map(|impactor| {
                    let external_ref = format!("{}::{}", contract, impactor);
                    external_to_wrapper.get(&external_ref).cloned()
                })
                .collect();

            result.insert(
                wrapper_fn.clone(),
                ResolvedRelations {
                    impacts: local_impacts,
                    is_impacted_by: local_is_impacted_by,
                    external: Some(external.clone()),
                },
            );
        }

        result
    }

    /// Get all lines that must be covered for a function (including children)
    /// Returns (file_path, line_number) tuples
    pub fn get_function_coverage_lines(
        &self,
        contract: &str,
        function: &str,
    ) -> Vec<(String, usize)> {
        self.coverage_map
            .get(contract)
            .and_then(|funcs| funcs.get(function))
            .map(|cov| cov.all_lines())
            .unwrap_or_default()
    }

    /// Get all available functions for a contract (excluding constructor)
    /// Returns: Vec<(function_signature, Option<external_target>)>
    pub fn get_available_functions(&self, contract: &str) -> Vec<(String, Option<String>)> {
        self.functions_relations
            .get(contract)
            .map(|funcs| {
                funcs
                    .iter()
                    .filter(|(name, _)| !name.starts_with("constructor"))
                    .map(|(name, rel)| (name.clone(), rel.external.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find the first function that is not fully covered
    /// Returns: Option<(function_name, external_target, uncovered_lines)>
    pub fn find_first_uncovered_function(
        &self,
        contract: &str,
        covered_lines: &HashSet<(String, usize)>,
    ) -> Option<(String, Option<String>, Vec<(String, usize)>)> {
        let functions = self.get_available_functions(contract);

        for (func_name, external) in functions {
            let required_lines = self.get_function_coverage_lines(contract, &func_name);

            if required_lines.is_empty() {
                continue; // Skip functions without coverage info
            }

            // Check which lines are not covered
            let uncovered: Vec<_> = required_lines
                .iter()
                .filter(|line| !covered_lines.contains(line))
                .cloned()
                .collect();

            if !uncovered.is_empty() {
                return Some((func_name, external, uncovered));
            }
        }

        None // All functions are fully covered!
    }

    /// Get the is_impacted_by functions for a wrapper function, resolved to wrapper names
    pub fn get_impacting_functions(&self, contract: &str, function: &str) -> Vec<String> {
        let resolved = self.resolve_wrapper_relations(contract);
        resolved
            .get(function)
            .map(|rel| rel.is_impacted_by.clone())
            .unwrap_or_default()
    }

    /// Find all contracts that implement/inherit a given interface
    /// E.g., contracts_implementing("ISpoke") -> ["SpokeInstance", "Spoke", ...]
    pub fn contracts_implementing(&self, interface_name: &str) -> Vec<String> {
        self.inheritances
            .iter()
            .filter(|(_, parents)| parents.contains(&interface_name.to_string()))
            .map(|(contract, _)| contract.clone())
            .collect()
    }

    /// Check if a contract implements/inherits an interface
    pub fn implements(&self, contract: &str, interface_name: &str) -> bool {
        self.inheritances
            .get(contract)
            .map(|parents| parents.contains(&interface_name.to_string()))
            .unwrap_or(false)
    }

    /// Get all interfaces/parent contracts for a contract
    pub fn get_parents(&self, contract: &str) -> Vec<String> {
        self.inheritances.get(contract).cloned().unwrap_or_default()
    }

    /// Build a map from interface name to all implementing contracts
    /// Useful for interface -> implementation resolution
    pub fn build_interface_to_implementations(&self) -> HashMap<String, Vec<String>> {
        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        for (contract, parents) in &self.inheritances {
            for parent in parents {
                result.entry(parent.clone()).or_default().push(contract.clone());
            }
        }

        result
    }

    /// Check if a function should be excluded from fuzzing
    /// The function_name can be with or without parameters (e.g., "onCallback" or "onCallback(uint256)")
    /// Matches against exclude_from_fuzzing which contains names WITHOUT parameters
    pub fn should_exclude_from_fuzzing(&self, function_name: &str) -> bool {
        // Extract function name without parameters
        let name_without_params = function_name
            .split('(')
            .next()
            .unwrap_or(function_name);

        self.exclude_from_fuzzing
            .iter()
            .any(|excluded| excluded == name_without_params)
    }

    /// Get the list of functions to exclude from fuzzing
    pub fn get_excluded_functions(&self) -> &[String] {
        &self.exclude_from_fuzzing
    }
}

/// Resolved function relations for wrapper functions
/// Maps underlying contract relations back to wrapper function names
#[derive(Debug, Clone, Default)]
pub struct ResolvedRelations {
    /// Wrapper functions that this function impacts
    pub impacts: Vec<String>,
    /// Wrapper functions that impact this function
    pub is_impacted_by: Vec<String>,
    /// Original external reference (e.g., "Counter::finalStep()")
    pub external: Option<String>,
}

/// Parse "Contract::function(args)" into (contract, "function(args)")
fn parse_external_ref(external: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = external.splitn(2, "::").collect();
    if parts.len() == 2 {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

/// Minimum value that looks like a timestamp (year 2010 = ~1262304000)
/// Values below this are more likely block numbers
const MIN_TIMESTAMP_LOOKING: u64 = 1_000_000_000;

/// Maximum reasonable timestamp (year 2100 = ~4102444800)
/// Used to filter out large constants that aren't actually timestamps
const MAX_REASONABLE_TIMESTAMP: u64 = 4_102_444_800;

/// Maximum reasonable block number for delay calculation (~100 million blocks)
/// Values above this in the 1B+ range are almost certainly timestamps, not block numbers
const MAX_REASONABLE_BLOCK_NUMBER: u64 = 100_000_000;

/// Check if a value looks like a timestamp (vs a block number)
/// Timestamps are in the range ~1.5B to ~4B (years 2018 to 2100)
fn looks_like_timestamp(val: u64) -> bool {
    val >= MIN_TIMESTAMP_LOOKING && val <= MAX_REASONABLE_TIMESTAMP
}

/// Check if a value looks like a block number (vs a timestamp)
/// Block numbers are typically below 100M for the foreseeable future
fn looks_like_block_number(val: u64) -> bool {
    val >= INITIAL_BLOCK_NUMBER && val < MAX_REASONABLE_BLOCK_NUMBER
}

/// Result of analyzing slither info for required delay settings
#[derive(Debug, Clone, Default)]
pub struct RequiredDelays {
    /// Maximum time delay needed to reach any timestamp constant
    pub max_time_delay: u64,
    /// Maximum block delay needed to reach any block number constant
    pub max_block_delay: u64,
}

/// Calculate the required max_time_delay and max_block_delay to reach all constants
/// Returns (max_time_delay, max_block_delay) that should be used in TxConf
///
/// Note: We use heuristics to distinguish timestamps from block numbers:
/// - Values >= 1B are almost certainly timestamps
/// - Values < 100M and > 4.3M are likely block numbers
pub fn calculate_required_delays(info: &SlitherInfo) -> RequiredDelays {
    let mut result = RequiredDelays::default();

    for constant in info.all_constants() {
        if let Some(val) = parse_constant_to_u256(constant) {
            if let Ok(val_u64) = TryInto::<u64>::try_into(val) {
                // Check if this looks like a timestamp needing a delay
                if val_u64 > INITIAL_TIMESTAMP && looks_like_timestamp(val_u64) {
                    let delta = val_u64 - INITIAL_TIMESTAMP;
                    // Add some buffer (+3) for the variants
                    result.max_time_delay = result.max_time_delay.max(delta.saturating_add(3));
                }

                // Check if this looks like a block number needing a delay
                // Only if it doesn't look like a timestamp (to avoid double-counting)
                if val_u64 > INITIAL_BLOCK_NUMBER
                    && looks_like_block_number(val_u64)
                    && !looks_like_timestamp(val_u64)
                {
                    let delta = val_u64 - INITIAL_BLOCK_NUMBER;
                    // Add some buffer (+3) for the variants
                    result.max_block_delay = result.max_block_delay.max(delta.saturating_add(3));
                }
            }
        }
    }

    result
}

/// Extract dict_values (U256) from SlitherInfo
///
/// Enhanced: For constants that could be timestamps or block numbers,
/// also adds the delta needed to reach that value from the initial state.
/// This allows gen_delay to pick values that reach exact timestamps/blocks.
/// Returns BTreeSet for deterministic iteration order (matches Haskell's Data.Set)
pub fn extract_dict_values(info: &SlitherInfo) -> BTreeSet<U256> {
    let mut values = BTreeSet::new();

    for constant in info.all_constants() {
        if let Some(val) = parse_constant_to_u256(constant) {
            // Add the value and its ±3 variants (Echidna's makeNumAbiValues)
            values.insert(val);
            for offset in 1u64..=3 {
                values.insert(val.saturating_add(U256::from(offset)));
                values.insert(val.saturating_sub(U256::from(offset)));
            }

            // Smart timestamp/block delta enhancement:
            // If this value looks like a target timestamp or block, add the delta
            if let Ok(val_u64) = TryInto::<u64>::try_into(val) {
                // For timestamps: add (x - INITIAL_TIMESTAMP) if it looks like a timestamp
                if val_u64 > INITIAL_TIMESTAMP && looks_like_timestamp(val_u64) {
                    let timestamp_delta = val_u64 - INITIAL_TIMESTAMP;
                    values.insert(U256::from(timestamp_delta));
                    // Also add ±3 variants of the delta
                    for offset in 1u64..=3 {
                        values.insert(U256::from(timestamp_delta.saturating_add(offset)));
                        values.insert(U256::from(timestamp_delta.saturating_sub(offset)));
                    }
                }

                // For block numbers: add (x - INITIAL_BLOCK_NUMBER) if it looks like a block number
                if val_u64 > INITIAL_BLOCK_NUMBER
                    && looks_like_block_number(val_u64)
                    && !looks_like_timestamp(val_u64)
                {
                    let block_delta = val_u64 - INITIAL_BLOCK_NUMBER;
                    values.insert(U256::from(block_delta));
                    // Also add ±3 variants of the delta
                    for offset in 1u64..=3 {
                        values.insert(U256::from(block_delta.saturating_add(offset)));
                        values.insert(U256::from(block_delta.saturating_sub(offset)));
                    }
                }
            }
        }
    }

    values
}

/// Extract signed_dict_values (I256) from SlitherInfo
/// Returns BTreeSet for deterministic iteration order (matches Haskell's Data.Set)
pub fn extract_signed_dict_values(info: &SlitherInfo) -> BTreeSet<I256> {
    let mut values = BTreeSet::new();

    for constant in info.all_constants() {
        if let Some(val) = parse_constant_to_i256(constant) {
            // Add the value and its ±3 variants AND negations (Echidna's makeNumAbiValues)
            values.insert(val);
            for offset in -3i64..=3 {
                let offset_val = I256::try_from(offset).unwrap_or(I256::ZERO);
                values.insert(val.saturating_add(offset_val));
                // Also add negative variant
                values.insert((-val).saturating_add(offset_val));
            }
        }
    }

    values
}

/// Enhance constants from SlitherInfo into DynSolValues
pub fn enhance_constants(info: &SlitherInfo) -> Vec<DynSolValue> {
    let mut values = Vec::new();

    for constant in info.all_constants() {
        if let Some(dyn_val) = parse_constant_to_dyn_sol_value(constant) {
            values.push(dyn_val.clone());

            // For numeric types, generate variants
            match &dyn_val {
                DynSolValue::Uint(u, bits) => {
                    // Generate N±3 variants
                    for offset in 1u64..=3 {
                        let plus = u.saturating_add(U256::from(offset));
                        let minus = u.saturating_sub(U256::from(offset));
                        values.push(DynSolValue::Uint(plus, *bits));
                        values.push(DynSolValue::Uint(minus, *bits));
                    }
                }
                DynSolValue::Int(i, bits) => {
                    // Generate N±3 and -N±3 variants
                    for offset in -3i64..=3 {
                        let offset_val = I256::try_from(offset).unwrap_or(I256::ZERO);
                        let variant = i.saturating_add(offset_val);
                        let neg_variant = (-*i).saturating_add(offset_val);
                        values.push(DynSolValue::Int(variant, *bits));
                        values.push(DynSolValue::Int(neg_variant, *bits));
                    }
                }
                _ => {}
            }
        }
    }

    values
}

/// Parse a constant value to U256
fn parse_constant_to_u256(constant: &ConstantValue) -> Option<U256> {
    match constant.type_name.as_str() {
        t if t.starts_with("uint") || t.starts_with("int") => {
            // For signed integers, only handle positive values
            if t.starts_with("int") && constant.value.starts_with('-') {
                return None;
            }
            // Handle both decimal and hex (0x prefix)
            parse_u256_value(&constant.value)
        }
        _ => None,
    }
}

/// Parse a string value to U256, handling both decimal and hex formats
fn parse_u256_value(value: &str) -> Option<U256> {
    if value.starts_with("0x") || value.starts_with("0X") {
        U256::from_str_radix(&value[2..], 16).ok()
    } else {
        value.parse::<U256>().ok()
    }
}

/// Parse an address string, handling both full (40 hex chars) and short formats (e.g., "0x100")
fn parse_address_value(value: &str) -> Option<alloy_primitives::Address> {
    // First try direct parsing (works for full-length addresses)
    if let Ok(addr) = value.parse() {
        return Some(addr);
    }

    // Handle short format like "0x100" by padding to 40 hex characters
    let hex_str = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X"))?;

    // Pad to 40 hex characters (20 bytes)
    if hex_str.len() < 40 {
        let padded = format!("{:0>40}", hex_str);
        format!("0x{}", padded).parse().ok()
    } else {
        None
    }
}

/// Parse a constant value to I256
fn parse_constant_to_i256(constant: &ConstantValue) -> Option<I256> {
    match constant.type_name.as_str() {
        t if t.starts_with("int") || t.starts_with("uint") => {
            if constant.value.starts_with('-') {
                // Negative number (decimal only, hex doesn't use minus sign)
                constant
                    .value
                    .parse::<i128>()
                    .ok()
                    .and_then(|n| I256::try_from(n).ok())
            } else if constant.value.starts_with("0x") || constant.value.starts_with("0X") {
                // Hex number - parse as unsigned then convert
                U256::from_str_radix(&constant.value[2..], 16)
                    .ok()
                    .and_then(|u| I256::try_from(u).ok())
            } else {
                // Positive decimal number - try as i128 first for larger values
                constant
                    .value
                    .parse::<i128>()
                    .ok()
                    .and_then(|n| I256::try_from(n).ok())
                    .or_else(|| {
                        constant
                            .value
                            .parse::<u128>()
                            .ok()
                            .and_then(|n| I256::try_from(n).ok())
                    })
            }
        }
        _ => None,
    }
}

/// Parse a constant value to DynSolValue
fn parse_constant_to_dyn_sol_value(constant: &ConstantValue) -> Option<DynSolValue> {
    match constant.type_name.as_str() {
        "bool" => {
            let val = constant.value.to_lowercase() == "true";
            Some(DynSolValue::Bool(val))
        }
        t if t.starts_with("uint") => {
            let bits = parse_bits(t, "uint").unwrap_or(256);
            let val = parse_constant_to_u256(constant)?;
            Some(DynSolValue::Uint(val, bits))
        }
        t if t.starts_with("int") => {
            let bits = parse_bits(t, "int").unwrap_or(256);
            let val = parse_constant_to_i256(constant)?;
            Some(DynSolValue::Int(val, bits))
        }
        "address" => {
            // Handle both full addresses and short format (e.g., "0x100")
            let addr = parse_address_value(&constant.value)?;
            Some(DynSolValue::Address(addr))
        }
        _ => None,
    }
}

/// Parse bit size from type name (e.g., "uint256" -> 256, "int128" -> 128)
fn parse_bits(type_name: &str, prefix: &str) -> Option<usize> {
    type_name.strip_prefix(prefix).and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_slither_info() {
        let json = r#"{
            "payable": {},
            "assert": {},
            "constant_functions": {},
            "constants_used": {
                "Counter": {
                    "setNumber(uint256)": [
                        [{"value": "12648430", "type": "uint256"}]
                    ],
                    "func_one(int128)": [
                        [{"value": "-80", "type": "int128"}]
                    ]
                }
            },
            "functions_relations": {},
            "with_fallback": [],
            "with_receive": []
        }"#;

        let info = SlitherInfo::from_json(json).unwrap();
        assert!(info.constants_used.contains_key("Counter"));

        let counter = &info.constants_used["Counter"];
        assert!(counter.contains_key("setNumber(uint256)"));
        assert!(counter.contains_key("func_one(int128)"));

        let set_number_consts = &counter["setNumber(uint256)"];
        assert_eq!(set_number_consts.len(), 1);
        assert_eq!(set_number_consts[0].value, "12648430");
        assert_eq!(set_number_consts[0].type_name, "uint256");

        let func_one_consts = &counter["func_one(int128)"];
        assert_eq!(func_one_consts.len(), 1);
        assert_eq!(func_one_consts[0].value, "-80");
        assert_eq!(func_one_consts[0].type_name, "int128");
    }

    #[test]
    fn test_extract_dict_values() {
        let json = r#"{
            "payable": {},
            "assert": {},
            "constant_functions": {},
            "constants_used": {
                "Counter": {
                    "test": [
                        [{"value": "42", "type": "uint256"}],
                        [{"value": "100", "type": "uint256"}]
                    ]
                }
            },
            "functions_relations": {},
            "with_fallback": [],
            "with_receive": []
        }"#;

        let info = SlitherInfo::from_json(json).unwrap();
        let values = extract_dict_values(&info);

        // Should contain 42 and its variants (39-45)
        assert!(values.contains(&U256::from(42)));
        assert!(values.contains(&U256::from(39)));
        assert!(values.contains(&U256::from(45)));

        // Should contain 100 and its variants (97-103)
        assert!(values.contains(&U256::from(100)));
        assert!(values.contains(&U256::from(97)));
        assert!(values.contains(&U256::from(103)));
    }

    #[test]
    fn test_extract_signed_dict_values() {
        let json = r#"{
            "payable": {},
            "assert": {},
            "constant_functions": {},
            "constants_used": {
                "Counter": {
                    "test": [
                        [{"value": "-80", "type": "int128"}]
                    ]
                }
            },
            "functions_relations": {},
            "with_fallback": [],
            "with_receive": []
        }"#;

        let info = SlitherInfo::from_json(json).unwrap();
        let values = extract_signed_dict_values(&info);

        // Should contain -80 and its variants
        assert!(values.contains(&I256::try_from(-80).unwrap()));
        assert!(values.contains(&I256::try_from(-83).unwrap()));
        assert!(values.contains(&I256::try_from(-77).unwrap()));

        // Should also contain positive counterpart (80) and variants
        assert!(values.contains(&I256::try_from(80).unwrap()));
        assert!(values.contains(&I256::try_from(77).unwrap()));
        assert!(values.contains(&I256::try_from(83).unwrap()));
    }

    #[test]
    fn test_resolve_wrapper_relations() {
        // Simulates CryticTester wrapping Counter with multi-step bug
        let json = r#"{
            "payable": {},
            "assert": {},
            "constant_functions": {},
            "constants_used": {},
            "functions_relations": {
                "CryticTester": {
                    "counter_initSequence(uint256)": {
                        "impacts": [],
                        "is_impacted_by": [],
                        "external": "Counter::initSequence(uint256)"
                    },
                    "counter_stepA()": {
                        "impacts": [],
                        "is_impacted_by": [],
                        "external": "Counter::stepA()"
                    },
                    "counter_stepB(uint256)": {
                        "impacts": [],
                        "is_impacted_by": [],
                        "external": "Counter::stepB(uint256)"
                    },
                    "counter_finalStep()": {
                        "impacts": [],
                        "is_impacted_by": [],
                        "external": "Counter::finalStep()"
                    }
                },
                "Counter": {
                    "initSequence(uint256)": {
                        "impacts": ["stepA()"],
                        "is_impacted_by": []
                    },
                    "stepA()": {
                        "impacts": ["stepB(uint256)"],
                        "is_impacted_by": ["initSequence(uint256)"]
                    },
                    "stepB(uint256)": {
                        "impacts": ["finalStep()"],
                        "is_impacted_by": ["stepA()"]
                    },
                    "finalStep()": {
                        "impacts": [],
                        "is_impacted_by": ["stepB(uint256)"]
                    }
                }
            },
            "with_fallback": [],
            "with_receive": []
        }"#;

        let info = SlitherInfo::from_json(json).unwrap();
        let resolved = info.resolve_wrapper_relations("CryticTester");

        // counter_initSequence impacts counter_stepA
        let init_rel = resolved.get("counter_initSequence(uint256)").unwrap();
        assert!(init_rel.impacts.contains(&"counter_stepA()".to_string()));
        assert!(init_rel.is_impacted_by.is_empty());

        // counter_stepA is impacted by counter_initSequence, impacts counter_stepB
        let step_a_rel = resolved.get("counter_stepA()").unwrap();
        assert!(step_a_rel
            .impacts
            .contains(&"counter_stepB(uint256)".to_string()));
        assert!(step_a_rel
            .is_impacted_by
            .contains(&"counter_initSequence(uint256)".to_string()));

        // counter_stepB is impacted by counter_stepA, impacts counter_finalStep
        let step_b_rel = resolved.get("counter_stepB(uint256)").unwrap();
        assert!(step_b_rel
            .impacts
            .contains(&"counter_finalStep()".to_string()));
        assert!(step_b_rel
            .is_impacted_by
            .contains(&"counter_stepA()".to_string()));

        // counter_finalStep is impacted by counter_stepB
        let final_rel = resolved.get("counter_finalStep()").unwrap();
        assert!(final_rel.impacts.is_empty());
        assert!(final_rel
            .is_impacted_by
            .contains(&"counter_stepB(uint256)".to_string()));
    }

    #[test]
    fn test_parse_external_ref() {
        assert_eq!(
            parse_external_ref("Counter::finalStep()"),
            Some(("Counter", "finalStep()"))
        );
        assert_eq!(
            parse_external_ref("Counter::stepB(uint256)"),
            Some(("Counter", "stepB(uint256)"))
        );
        assert_eq!(parse_external_ref("invalid"), None);
    }

    #[test]
    fn test_parse_hex_constants() {
        // Test hex values like 0xDEAD, 0xBAD from slither info
        let json = r#"{
            "payable": {},
            "assert": {},
            "constant_functions": {},
            "constants_used": {
                "MathLib": {
                    "complexCalc(uint256,uint256,uint256)": [
                        [{"value": "65536", "type": "uint256"}],
                        [{"value": "0xDEAD", "type": "uint256"}]
                    ]
                },
                "StringLib": {
                    "validateStringData(StringLib.StringData)": [
                        [{"value": "0xBAD", "type": "uint256"}],
                        [{"value": "232", "type": "uint256"}]
                    ]
                }
            },
            "functions_relations": {},
            "with_fallback": [],
            "with_receive": []
        }"#;

        let info = SlitherInfo::from_json(json).unwrap();
        let values = extract_dict_values(&info);

        // 0xDEAD = 57005
        assert!(
            values.contains(&U256::from(57005)),
            "Should contain 0xDEAD (57005)"
        );
        // 0xBAD = 2989
        assert!(
            values.contains(&U256::from(2989)),
            "Should contain 0xBAD (2989)"
        );
        // Also decimal values
        assert!(values.contains(&U256::from(65536)));
        assert!(values.contains(&U256::from(232)));

        // Variants should also be present
        assert!(
            values.contains(&U256::from(57002)),
            "Should contain 0xDEAD - 3"
        );
        assert!(
            values.contains(&U256::from(57008)),
            "Should contain 0xDEAD + 3"
        );
    }

    #[test]
    fn test_parse_u256_value_hex() {
        // Direct test for parse_u256_value helper
        assert_eq!(parse_u256_value("0xDEAD"), Some(U256::from(57005)));
        assert_eq!(parse_u256_value("0xBAD"), Some(U256::from(2989)));
        assert_eq!(
            parse_u256_value("0xdeadbeef"),
            Some(U256::from(0xdeadbeef_u64))
        );
        assert_eq!(parse_u256_value("0XDEAD"), Some(U256::from(57005))); // uppercase 0X
        assert_eq!(parse_u256_value("12345"), Some(U256::from(12345)));
        assert_eq!(parse_u256_value("invalid"), None);
    }

    #[test]
    fn test_parse_address_constants() {
        // Test that addresses from slither info are properly parsed
        use alloy_primitives::Address;

        let json = r#"{
            "payable": {},
            "assert": {},
            "constant_functions": {},
            "constants_used": {
                "CryticTester": {
                    "setup()": [
                        [{"value": "0x100", "type": "address"}],
                        [{"value": "0x0000000000000000000000000000000000000200", "type": "address"}]
                    ]
                }
            },
            "functions_relations": {},
            "with_fallback": [],
            "with_receive": []
        }"#;

        let info = SlitherInfo::from_json(json).unwrap();
        let enhanced = enhance_constants(&info);

        // Should contain both addresses
        let addresses: Vec<_> = enhanced
            .iter()
            .filter_map(|v| {
                if let DynSolValue::Address(a) = v {
                    Some(*a)
                } else {
                    None
                }
            })
            .collect();

        assert!(!addresses.is_empty(), "Should have extracted addresses");

        // Check for expected addresses
        let expected_0x100 = "0x0000000000000000000000000000000000000100".parse::<Address>().unwrap();
        let expected_0x200 = "0x0000000000000000000000000000000000000200".parse::<Address>().unwrap();

        assert!(addresses.contains(&expected_0x100), "Should contain 0x100 address");
        assert!(addresses.contains(&expected_0x200), "Should contain 0x200 address");
    }

    #[test]
    fn test_parse_short_address_format() {
        // Test that short address format like "0x100" is properly handled
        use alloy_primitives::Address;

        // Test parse_address_value with short format
        let short_0x100 = parse_address_value("0x100");
        assert!(short_0x100.is_some(), "Should parse short address 0x100");

        let expected = "0x0000000000000000000000000000000000000100".parse::<Address>().unwrap();
        assert_eq!(short_0x100.unwrap(), expected, "0x100 should equal full padded address");

        // Test with 0x200
        let short_0x200 = parse_address_value("0x200");
        assert!(short_0x200.is_some(), "Should parse short address 0x200");

        let expected_200 = "0x0000000000000000000000000000000000000200".parse::<Address>().unwrap();
        assert_eq!(short_0x200.unwrap(), expected_200, "0x200 should equal full padded address");

        // Test full address still works
        let full_addr = parse_address_value("0x0000000000000000000000000000000000000100");
        assert!(full_addr.is_some(), "Should parse full address");
        assert_eq!(full_addr.unwrap(), expected, "Full address should match");
    }

    #[test]
    fn test_slither_addresses_with_short_format() {
        // Test that slither info with short addresses is properly parsed
        use alloy_primitives::Address;

        let json = r#"{
            "payable": {},
            "assert": {},
            "constant_functions": {},
            "constants_used": {
                "CryticTester": {
                    "setup()": [
                        [{"value": "0x100", "type": "address"}],
                        [{"value": "0x200", "type": "address"}]
                    ]
                }
            },
            "functions_relations": {},
            "with_fallback": [],
            "with_receive": []
        }"#;

        let info = SlitherInfo::from_json(json).unwrap();
        let enhanced = enhance_constants(&info);

        // Should contain both addresses
        let addresses: Vec<_> = enhanced
            .iter()
            .filter_map(|v| {
                if let DynSolValue::Address(a) = v {
                    Some(*a)
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(addresses.len(), 2, "Should have extracted 2 addresses");

        let expected_0x100 = "0x0000000000000000000000000000000000000100".parse::<Address>().unwrap();
        let expected_0x200 = "0x0000000000000000000000000000000000000200".parse::<Address>().unwrap();

        assert!(addresses.contains(&expected_0x100), "Should contain 0x100 address");
        assert!(addresses.contains(&expected_0x200), "Should contain 0x200 address");
    }
}
