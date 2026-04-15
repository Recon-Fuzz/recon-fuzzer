//! Foundry artifact loading and library linking for browser-fuzzer
//!
//! Port of evm/src/foundry.rs adapted for WASM (no filesystem, no `forge build`).
//! User uploads artifact JSON files from Foundry's `out/` directory.

use alloy_dyn_abi::{DynSolType, Specifier};
use alloy_json_abi::{Function, JsonAbi, StateMutability};
use alloy_primitives::{Address, Bytes, FixedBytes, keccak256};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

use crate::evm::exec::EvmState;

// =========================================================================
// Serde structs — identical to main fuzzer
// =========================================================================

#[derive(Debug, Deserialize)]
struct FoundryArtifact {
    abi: JsonAbi,
    bytecode: BytecodeObject,
    #[serde(rename = "deployedBytecode")]
    deployed_bytecode: BytecodeObject,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct BytecodeObject {
    object: String,
}

// =========================================================================
// CompiledContract — adapted from main fuzzer (no source_path, no source_map)
// =========================================================================

/// Compiled contract parsed from a Foundry artifact JSON
#[derive(Debug, Clone)]
pub struct CompiledContract {
    /// Contract name (e.g., "Token")
    pub name: String,
    /// Full qualified name (e.g., "src/Token.sol:Token")
    pub qualified_name: String,
    /// Contract ABI
    pub abi: JsonAbi,
    /// Init/creation bytecode (may be unlinked — placeholders zeroed)
    pub bytecode: Bytes,
    /// Runtime bytecode (may be unlinked — placeholders zeroed)
    pub deployed_bytecode: Bytes,
    /// Function selectors mapped to function info
    pub functions: HashMap<FixedBytes<4>, Function>,
    /// Cached resolved parameter types for each function (by selector)
    /// Pre-computed at load time to avoid expensive p.resolve() calls during fuzzing
    pub resolved_param_types: HashMap<FixedBytes<4>, Vec<DynSolType>>,
    /// Functions to exclude from fuzzing
    pub exclude_from_fuzzing: Vec<String>,
}

impl CompiledContract {
    /// Standard Foundry test helper functions that should never be fuzzed
    const FOUNDRY_INTERNAL_FUNCTIONS: &'static [&'static str] = &[
        "IS_TEST",
        "failed",
        "setUp",
        "excludeArtifacts",
        "excludeContracts",
        "excludeSelectors",
        "excludeSenders",
        "targetArtifacts",
        "targetContracts",
        "targetInterfaces",
        "targetSelectors",
        "targetSenders",
    ];

    fn is_foundry_internal(name: &str) -> bool {
        Self::FOUNDRY_INTERNAL_FUNCTIONS.contains(&name)
    }

    /// Get all echidna test functions (prefix: echidna_)
    pub fn echidna_tests(&self) -> Vec<&Function> {
        self.abi
            .functions()
            .filter(|f| f.name.starts_with("echidna_"))
            .collect()
    }

    /// Get all fuzzable functions.
    /// If mutable_only is true, excludes pure/view functions.
    pub fn fuzzable_functions(&self, mutable_only: bool) -> Vec<&Function> {
        self.abi
            .functions()
            .filter(|f| {
                if mutable_only {
                    !matches!(
                        f.state_mutability,
                        StateMutability::View | StateMutability::Pure
                    )
                } else {
                    true
                }
            })
            .filter(|f| !f.name.starts_with("echidna_"))
            .filter(|f| !Self::is_foundry_internal(&f.name))
            .filter(|f| !self.exclude_from_fuzzing.iter().any(|excluded| excluded == &f.name))
            .collect()
    }

    /// Get cached resolved parameter types for a function by selector.
    /// Returns empty slice if function not found.
    #[inline]
    pub fn get_param_types(&self, selector: &FixedBytes<4>) -> &[DynSolType] {
        self.resolved_param_types
            .get(selector)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Check if contract has a setUp function
    pub fn has_setup(&self) -> bool {
        self.abi.functions().any(|f| f.name == "setUp")
    }

    /// Check if bytecode has unlinked library references
    pub fn has_unlinked_libraries(&self) -> bool {
        let hex = hex::encode(&self.bytecode);
        hex.contains("__$")
    }
}

// =========================================================================
// Parse a single Foundry artifact JSON → CompiledContract
// =========================================================================

/// Parse a single Foundry artifact JSON string into a CompiledContract.
/// The `name` is the contract name (e.g., "Token").
pub fn parse_artifact(json: &str) -> Result<CompiledContract, String> {
    let artifact: FoundryArtifact =
        serde_json::from_str(json).map_err(|e| format!("artifact parse error: {e}"))?;

    // Skip if no bytecode
    if artifact.bytecode.object.is_empty() || artifact.bytecode.object == "0x" {
        return Err("no bytecode in artifact".to_string());
    }

    let bytecode = parse_bytecode_with_placeholders(&artifact.bytecode.object)
        .map_err(|e| format!("bytecode parse error: {e}"))?;
    let deployed_bytecode =
        parse_bytecode_with_placeholders(&artifact.deployed_bytecode.object)
            .map_err(|e| format!("deployed bytecode parse error: {e}"))?;

    // Build function selector map
    let mut functions = HashMap::new();
    for func in artifact.abi.functions() {
        functions.insert(func.selector(), func.clone());
    }

    // Extract contract name and qualified name from metadata
    let (name, qualified_name) = extract_names_from_metadata(&artifact.metadata);

    // Pre-compute resolved parameter types (expensive p.resolve() done once)
    let resolved_param_types: HashMap<FixedBytes<4>, Vec<DynSolType>> = functions
        .iter()
        .map(|(selector, func)| {
            let types: Vec<DynSolType> = func
                .inputs
                .iter()
                .filter_map(|p| p.resolve().ok())
                .collect();
            (*selector, types)
        })
        .collect();

    Ok(CompiledContract {
        name,
        qualified_name,
        abi: artifact.abi,
        bytecode,
        deployed_bytecode,
        functions,
        resolved_param_types,
        exclude_from_fuzzing: Vec::new(),
    })
}

/// Extract contract name and qualified name from artifact metadata.
fn extract_names_from_metadata(
    metadata: &Option<serde_json::Value>,
) -> (String, String) {
    if let Some(metadata) = metadata {
        if let Some(compilation_target) = metadata
            .get("settings")
            .and_then(|s| s.get("compilationTarget"))
            .and_then(|c| c.as_object())
        {
            // compilationTarget is { "src/Token.sol": "Token" }
            if let Some((source_path, contract_name)) = compilation_target.iter().next() {
                let name = contract_name
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string();
                let qualified = format!("{}:{}", source_path, name);
                return (name, qualified);
            }
        }
    }
    ("Unknown".to_string(), "Unknown:Unknown".to_string())
}

// =========================================================================
// Library linking structures
// =========================================================================

/// Library information extracted from artifacts
#[derive(Debug, Clone)]
pub struct LibraryInfo {
    pub name: String,
    pub qualified_name: String,
    pub hash: String,
    pub bytecode_hex: String,
    pub address: Option<Address>,
}

/// Browser-side Foundry project for loading artifacts and linking libraries
pub struct FoundryProject {
    pub contracts: Vec<CompiledContract>,
    pub libraries_by_hash: HashMap<String, LibraryInfo>,
    pub deployed_libraries: HashMap<String, Address>,
}

/// Build-info file structure (from `out/build-info/*.json`)
#[derive(Debug, Deserialize)]
struct BuildInfo {
    output: BuildInfoOutput,
}

#[derive(Debug, Deserialize)]
struct BuildInfoOutput {
    /// contracts[filepath][contractName] = BuildInfoContract
    contracts: HashMap<String, HashMap<String, BuildInfoContract>>,
}

#[derive(Debug, Deserialize)]
struct BuildInfoContract {
    abi: JsonAbi,
    #[allow(dead_code)]
    metadata: Option<serde_json::Value>,
    evm: Option<BuildInfoEvm>,
}

#[derive(Debug, Deserialize)]
struct BuildInfoEvm {
    bytecode: Option<BytecodeObject>,
    #[serde(rename = "deployedBytecode")]
    deployed_bytecode: Option<BytecodeObject>,
}

impl FoundryProject {
    /// Load from a build-info JSON string (from `out/build-info/*.json`).
    /// This is the primary loading path — matches the main fuzzer's `parse_artifacts`
    /// which walks `out/` directory, but here we parse the build-info directly.
    pub fn from_build_info(build_info_json: &str) -> Result<Self, String> {
        let build_info: BuildInfo = serde_json::from_str(build_info_json)
            .map_err(|e| format!("build-info parse error: {e}"))?;

        let mut contracts = Vec::new();
        let mut libraries_by_hash = HashMap::new();

        for (file_path, file_contracts) in &build_info.output.contracts {
            for (contract_name, contract_data) in file_contracts {
                let evm = match &contract_data.evm {
                    Some(evm) => evm,
                    None => continue,
                };
                let bytecode_obj = match &evm.bytecode {
                    Some(bc) => bc,
                    None => continue,
                };
                let bytecode_hex = &bytecode_obj.object;
                if bytecode_hex.is_empty() || bytecode_hex == "0x" || bytecode_hex.len() < 10 {
                    continue;
                }

                let qualified_name = format!("{}:{}", file_path, contract_name);
                let hash = compute_library_hash(&qualified_name);

                // Store as library info
                libraries_by_hash.insert(
                    hash.clone(),
                    LibraryInfo {
                        name: contract_name.clone(),
                        qualified_name: qualified_name.clone(),
                        hash: hash.clone(),
                        bytecode_hex: bytecode_hex.clone(),
                        address: None,
                    },
                );

                // Parse bytecodes
                let bytecode = match parse_bytecode_with_placeholders(bytecode_hex) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let deployed_bytecode = evm
                    .deployed_bytecode
                    .as_ref()
                    .and_then(|db| parse_bytecode_with_placeholders(&db.object).ok())
                    .unwrap_or_default();

                // Build function selector map
                let mut functions = HashMap::new();
                for func in contract_data.abi.functions() {
                    functions.insert(func.selector(), func.clone());
                }

                // Pre-compute resolved parameter types
                let resolved_param_types: HashMap<FixedBytes<4>, Vec<DynSolType>> = functions
                    .iter()
                    .map(|(selector, func)| {
                        let types: Vec<DynSolType> = func
                            .inputs
                            .iter()
                            .filter_map(|p| p.resolve().ok())
                            .collect();
                        (*selector, types)
                    })
                    .collect();

                contracts.push(CompiledContract {
                    name: contract_name.clone(),
                    qualified_name,
                    abi: contract_data.abi.clone(),
                    bytecode,
                    deployed_bytecode,
                    functions,
                    resolved_param_types,
                    exclude_from_fuzzing: Vec::new(),
                });
            }
        }

        Ok(Self {
            contracts,
            libraries_by_hash,
            deployed_libraries: HashMap::new(),
        })
    }

    /// Load multiple artifacts from JSON strings.
    /// Each string is the content of an artifact JSON file from Foundry's `out/` directory.
    pub fn from_artifacts(artifacts_json: &[&str]) -> Result<Self, String> {
        let mut contracts = Vec::new();
        let mut libraries_by_hash = HashMap::new();

        for json_str in artifacts_json {
            // Parse as raw JSON to get bytecode string with placeholders
            let json: serde_json::Value = serde_json::from_str(json_str)
                .map_err(|e| format!("JSON parse error: {e}"))?;

            let bytecode_hex = json
                .get("bytecode")
                .and_then(|b| b.get("object"))
                .and_then(|o| o.as_str())
                .unwrap_or("")
                .to_string();

            if bytecode_hex.is_empty() || bytecode_hex == "0x" {
                continue;
            }

            // Get names from metadata
            let metadata = json.get("metadata").cloned();
            let (name, qualified_name) = extract_names_from_metadata(&metadata);
            let hash = compute_library_hash(&qualified_name);

            // Store as library info (every contract could be a library)
            libraries_by_hash.insert(
                hash.clone(),
                LibraryInfo {
                    name: name.clone(),
                    qualified_name: qualified_name.clone(),
                    hash: hash.clone(),
                    bytecode_hex: bytecode_hex.clone(),
                    address: None,
                },
            );

            // Also parse as CompiledContract
            match parse_artifact(json_str) {
                Ok(mut contract) => {
                    // Override name/qualified_name from metadata extraction
                    contract.name = name;
                    contract.qualified_name = qualified_name;
                    contracts.push(contract);
                }
                Err(_) => continue,
            }
        }

        Ok(Self {
            contracts,
            libraries_by_hash,
            deployed_libraries: HashMap::new(),
        })
    }

    /// Get contract by name
    pub fn get_contract(&self, name: &str) -> Option<&CompiledContract> {
        self.contracts.iter().find(|c| {
            c.name == name || c.qualified_name.ends_with(&format!(":{}", name))
        })
    }

    /// Find the contract with echidna_ tests (auto-detect main contract).
    /// Prefers a contract named "CryticTester" if it exists and has tests,
    /// otherwise falls back to the first contract with echidna_ functions.
    pub fn find_test_contract(&self) -> Option<&CompiledContract> {
        // Prefer CryticTester by name (common Echidna convention)
        if let Some(c) = self.contracts.iter().find(|c| {
            c.name == "CryticTester" && !c.echidna_tests().is_empty()
        }) {
            return Some(c);
        }
        self.contracts
            .iter()
            .find(|c| !c.echidna_tests().is_empty())
    }

    /// Find all library dependencies (direct and nested) for a bytecode hex string.
    /// Returns hashes in deployment order (dependencies first).
    pub fn find_all_library_deps(&self, bytecode_hex: &str) -> Vec<String> {
        let mut needed = extract_library_placeholders(bytecode_hex);
        let mut all_deps = Vec::new();
        let mut visited = HashSet::new();

        // BFS to find nested dependencies
        while !needed.is_empty() {
            let mut next_needed = HashSet::new();

            for hash in needed {
                if visited.contains(&hash) {
                    continue;
                }
                visited.insert(hash.clone());

                if let Some(lib) = self.libraries_by_hash.get(&hash) {
                    all_deps.push(hash.clone());

                    // Check if this library has its own dependencies
                    let lib_deps = extract_library_placeholders(&lib.bytecode_hex);
                    for dep in lib_deps {
                        if !visited.contains(&dep) {
                            next_needed.insert(dep);
                        }
                    }
                }
            }

            needed = next_needed;
        }

        // Reverse to get deployment order (dependencies first)
        all_deps.reverse();
        all_deps
    }

    /// Deploy all needed libraries and link them into the contract bytecode.
    /// Returns the fully linked init bytecode ready for deployment.
    pub fn deploy_libraries_and_link(
        &mut self,
        evm: &mut EvmState,
        contract_name: &str,
        deployer: Address,
        reserved_addr: Option<Address>,
    ) -> Result<Bytes, String> {
        // Get the raw bytecode hex for the contract
        let bytecode_hex = self
            .libraries_by_hash
            .values()
            .find(|l| l.name == contract_name || l.qualified_name.ends_with(&format!(":{}", contract_name)))
            .map(|l| l.bytecode_hex.clone())
            .ok_or_else(|| format!("Contract {} not found in libraries_by_hash", contract_name))?;

        // Find all library dependencies
        let deps = self.find_all_library_deps(&bytecode_hex);

        if deps.is_empty() {
            return self.link_bytecode_with_deployed(&bytecode_hex);
        }

        // Deploy libraries in order
        for hash in &deps {
            if self.deployed_libraries.contains_key(hash) {
                continue;
            }

            let lib = self
                .libraries_by_hash
                .get(hash)
                .ok_or_else(|| format!("Library with hash {} not found", hash))?
                .clone();

            // Link the library's own bytecode (it may have dependencies)
            let linked_bytecode = self.link_bytecode_with_deployed(&lib.bytecode_hex)?;

            // Deploy library — avoid reserved address by bumping nonce
            let mut nonce = evm.get_nonce(deployer);
            let mut lib_addr = deployer.create(nonce);

            if let Some(reserved) = reserved_addr {
                while lib_addr == reserved {
                    evm.set_nonce(deployer, nonce + 1);
                    nonce = evm.get_nonce(deployer);
                    lib_addr = deployer.create(nonce);
                }
            }

            // Deploy at computed address (matches main fuzzer's deploy_contract_at for libraries)
            let trace = evm.deploy_contract_at(deployer, lib_addr, linked_bytecode, alloy_primitives::U256::ZERO);
            if !trace.success {
                return Err(format!(
                    "Failed to deploy library {}: {:?}",
                    lib.name, trace.error
                ));
            }

            // Record deployed address
            self.deployed_libraries.insert(hash.clone(), lib_addr);
        }

        // Link the main contract's bytecode
        let linked = self.link_bytecode_with_deployed(&bytecode_hex)?;

        // Verify no unlinked placeholders remain
        let linked_hex = hex::encode(&linked);
        if linked_hex.contains("__$") {
            let remaining = extract_library_placeholders(&linked_hex);
            return Err(format!(
                "Contract {} still has {} unlinked library references: {:?}",
                contract_name,
                remaining.len(),
                remaining
            ));
        }

        Ok(linked)
    }

    /// Link a bytecode hex string using already-deployed libraries
    fn link_bytecode_with_deployed(&self, bytecode_hex: &str) -> Result<Bytes, String> {
        let mut hex_str = bytecode_hex.trim_start_matches("0x").to_string();

        // Replace each placeholder with its deployed address
        for (hash, addr) in &self.deployed_libraries {
            let placeholder = format!("__${}$__", hash);
            let addr_hex = hex::encode(addr.as_slice());
            hex_str = hex_str.replace(&placeholder, &addr_hex);
        }

        // Replace any remaining placeholders with zeros
        while let Some(start) = hex_str.find("__$") {
            if let Some(end_offset) = hex_str[start..].find("$__") {
                let end = start + end_offset + 3;
                let zeros = "0".repeat(40);
                hex_str.replace_range(start..end, &zeros);
            } else {
                break;
            }
        }

        let bytes =
            hex::decode(&hex_str).map_err(|e| format!("hex decode error: {e}"))?;
        Ok(Bytes::from(bytes))
    }

    /// Get all deployed library addresses with their names
    pub fn get_deployed_library_addresses(&self) -> Vec<(Address, String)> {
        self.deployed_libraries
            .iter()
            .filter_map(|(hash, addr)| {
                self.libraries_by_hash
                    .get(hash)
                    .map(|lib| (*addr, lib.name.clone()))
            })
            .collect()
    }
}

// =========================================================================
// Utility functions — identical to main fuzzer
// =========================================================================

/// Parse bytecode string, replacing __$hash$__ placeholders with zeros
fn parse_bytecode_with_placeholders(object: &str) -> Result<Bytes, String> {
    let mut hex_str = object.trim_start_matches("0x").to_string();

    while let Some(start) = hex_str.find("__$") {
        if let Some(end_offset) = hex_str[start..].find("$__") {
            let end = start + end_offset + 3;
            let zeros = "0".repeat(40);
            hex_str.replace_range(start..end, &zeros);
        } else {
            break;
        }
    }

    let bytes =
        hex::decode(&hex_str).map_err(|e| format!("hex decode error: {e}"))?;
    Ok(Bytes::from(bytes))
}

/// Extract all __$hash$__ placeholders from a bytecode hex string
fn extract_library_placeholders(bytecode_hex: &str) -> HashSet<String> {
    let mut placeholders = HashSet::new();
    let hex = bytecode_hex.trim_start_matches("0x");

    let mut pos = 0;
    while let Some(start) = hex[pos..].find("__$") {
        let abs_start = pos + start;
        if let Some(end_offset) = hex[abs_start..].find("$__") {
            let hash = &hex[abs_start + 3..abs_start + end_offset];
            placeholders.insert(hash.to_string());
            pos = abs_start + end_offset + 3;
        } else {
            break;
        }
    }

    placeholders
}

/// Compute the library placeholder hash for a qualified name.
/// The hash is the first 34 chars of keccak256(qualified_name).
fn compute_library_hash(qualified_name: &str) -> String {
    let hash = keccak256(qualified_name.as_bytes());
    hex::encode(&hash.0)[..34].to_string()
}
