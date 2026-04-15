//! Foundry project integration
//!
//! Handles compilation via `forge build` and smart library linking

use alloy_dyn_abi::{DynSolType, Specifier};
use alloy_json_abi::{Function, JsonAbi};
use alloy_primitives::{Address, Bytes, FixedBytes, U256, keccak256};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

use crate::exec::EvmState;

// Keep Libraries type for API compatibility, but we don't use foundry-linking
type Libraries = std::collections::BTreeMap<PathBuf, std::collections::BTreeMap<String, String>>;

/// Compiled contract from Foundry
#[derive(Debug, Clone)]
pub struct CompiledContract {
    /// Contract name (e.g., "Token")
    pub name: String,

    /// Full qualified name (e.g., "src/Token.sol:Token")
    pub qualified_name: String,

    /// Contract ABI
    pub abi: JsonAbi,

    /// Deployed bytecode (may be unlinked)
    pub bytecode: Bytes,

    /// Runtime bytecode (may be unlinked)
    pub deployed_bytecode: Bytes,

    /// Source file path
    pub source_path: PathBuf,

    /// Function selectors mapped to function info
    pub functions: HashMap<FixedBytes<4>, Function>,
    
    /// Deployed bytecode source map (for runtime coverage mapping)
    pub source_map: Option<String>,

    /// Init/creation bytecode source map (for constructor coverage mapping)
    pub init_source_map: Option<String>,

    /// Cached resolved parameter types for each function (by selector)
    /// Pre-computed at load time to avoid expensive p.resolve() calls during fuzzing
    pub resolved_param_types: HashMap<FixedBytes<4>, Vec<DynSolType>>,

    /// Functions to exclude from fuzzing (e.g., callback handlers like "onCallback")
    /// Contains function names WITHOUT parameters
    pub exclude_from_fuzzing: Vec<String>,
}

impl CompiledContract {
    /// Get all echidna test functions (prefix: echidna_)
    pub fn echidna_tests(&self) -> Vec<&Function> {
        self.abi
            .functions()
            .filter(|f| f.name.starts_with("echidna_"))
            .collect()
    }

    /// Standard Foundry test helper functions that should never be fuzzed
    /// These are internal framework functions from forge-std's Test.sol and StdInvariant.sol
    const FOUNDRY_INTERNAL_FUNCTIONS: &'static [&'static str] = &[
        // Test.sol internal state
        "IS_TEST",
        "failed",
        "setUp",
        // StdInvariant.sol - exclude/target functions for invariant testing
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
    
    /// Check if a function is a Foundry internal helper that should not be fuzzed
    fn is_foundry_internal(name: &str) -> bool {
        Self::FOUNDRY_INTERNAL_FUNCTIONS.contains(&name)
    }

    /// Get all fuzzable functions
    /// If mutable_only is true, excludes pure/view functions
    /// If mutable_only is false, includes all functions (pure, view, payable, nonpayable)
    /// Also excludes functions in the exclude_from_fuzzing list
    pub fn fuzzable_functions(&self, mutable_only: bool) -> Vec<&Function> {
        use alloy_json_abi::StateMutability;
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
            // Filter out excluded functions (matched by name without params)
            .filter(|f| !self.exclude_from_fuzzing.iter().any(|excluded| excluded == &f.name))
            .collect()
    }
    
    /// Get fuzzable functions with smart filtering for view/pure functions
    /// 
    /// For view/pure functions, only include them if they have assertions (are in assert_functions).
    /// This avoids wasting fuzzing effort on view functions that can't fail assertions.
    /// 
    /// State-changing functions (nonpayable/payable) are always included as they can affect
    /// state that other assertion functions depend on.
    /// Also excludes functions in the exclude_from_fuzzing list.
    pub fn fuzzable_functions_smart(&self, mutable_only: bool, assert_functions: &std::collections::HashSet<String>) -> Vec<&Function> {
        use alloy_json_abi::StateMutability;
        self.abi
            .functions()
            .filter(|f| {
                if f.name.starts_with("echidna_") {
                    return false;
                }
                
                // Always exclude Foundry internal helper functions
                if Self::is_foundry_internal(&f.name) {
                    return false;
                }

                // Filter out excluded functions (matched by name without params)
                if self.exclude_from_fuzzing.iter().any(|excluded| excluded == &f.name) {
                    return false;
                }

                let is_view_or_pure = matches!(
                    f.state_mutability,
                    StateMutability::View | StateMutability::Pure
                );
                
                if mutable_only {
                    // Exclude all view/pure functions
                    !is_view_or_pure
                } else if is_view_or_pure {
                    // For view/pure: only include if it has assertions
                    // Build the function signature like "funcName(type1,type2)"
                    let sig = format!("{}({})", f.name, f.inputs.iter().map(|p| p.ty.as_str()).collect::<Vec<_>>().join(","));
                    assert_functions.contains(&sig) || assert_functions.contains(&f.name)
                } else {
                    // State-changing functions: always include
                    true
                }
            })
            .collect()
    }

    /// Get cached resolved parameter types for a function by selector
    /// Returns empty slice if function not found
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

/// Foundry artifact structure (simplified)
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
    #[serde(rename = "sourceMap", default)]
    source_map: Option<String>,
}

/// Compile a Foundry project
pub fn compile_project(project_path: &Path) -> Result<Vec<CompiledContract>> {
    info!("Compiling Foundry project at {:?}", project_path);

    // Run forge build
    let output = Command::new("forge")
        .arg("build")
        .arg("--build-info")
        .arg("-o")
        .arg("out")
        .current_dir(project_path)
        .output()
        .context("Failed to run forge build")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("forge build failed: {}", stderr));
    }

    debug!("forge build completed successfully");

    // Parse artifacts from out/ directory
    parse_artifacts(project_path)
}

/// Parse compiled artifacts from Foundry's out/ directory
fn parse_artifacts(project_path: &Path) -> Result<Vec<CompiledContract>> {
    let out_dir = project_path.join("out");
    if !out_dir.exists() {
        return Err(anyhow!(
            "out/ directory not found. Run `forge build` first."
        ));
    }

    let mut contracts = Vec::new();

    // Iterate through all .json files in out/
    for entry in walkdir::WalkDir::new(&out_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "json")
                && !e.path().to_string_lossy().contains(".dbg.")
        })
    {
        let path = entry.path();

        // Skip non-contract files
        let file_name = path.file_stem().unwrap_or_default().to_string_lossy();
        if file_name.starts_with('.') || file_name.contains(".metadata") {
            continue;
        }

        // Try to parse as artifact
        match parse_single_artifact(path, &file_name) {
            Ok(Some(contract)) => {
                debug!("Parsed contract: {}", contract.name);
                contracts.push(contract);
            }
            Ok(None) => continue,
            Err(e) => {
                debug!("Skipping {:?}: {}", path, e);
                continue;
            }
        }
    }

    info!("Loaded {} contracts", contracts.len());
    Ok(contracts)
}

fn parse_single_artifact(path: &Path, name: &str) -> Result<Option<CompiledContract>> {
    let content = std::fs::read_to_string(path)?;
    let artifact: FoundryArtifact = serde_json::from_str(&content)?;

    // Skip if no bytecode (interfaces, libraries, etc.)
    if artifact.bytecode.object.is_empty() || artifact.bytecode.object == "0x" {
        return Ok(None);
    }

    // Parse bytecode - handle unlinked libraries by replacing __$...$__ with zeros
    let bytecode = parse_bytecode_with_placeholders(&artifact.bytecode.object)?;
    let deployed_bytecode = parse_bytecode_with_placeholders(&artifact.deployed_bytecode.object)?;

    // Build function selector map
    let mut functions = HashMap::new();
    for func in artifact.abi.functions() {
        functions.insert(func.selector(), func.clone());
    }

    // Extract source path from metadata.settings.compilationTarget (Foundry metadata)
    // This gives us the exact source file path where the contract is defined
    let (source_path, qualified_source) = if let Some(metadata) = &artifact.metadata {
        // Try to get the source file path from metadata.settings.compilationTarget
        // This is more reliable than metadata.sources as it gives the actual contract location
        if let Some(compilation_target) = metadata
            .get("settings")
            .and_then(|s| s.get("compilationTarget"))
            .and_then(|c| c.as_object())
            .and_then(|o| o.keys().next())
            .map(|k| k.to_string())
        {
            (PathBuf::from(&compilation_target), compilation_target)
        } else if let Some(sources) = metadata.get("sources").and_then(|s| s.as_object()) {
            // Fallback to sources if compilationTarget not available
            // Note: This may include dependencies, so it's less reliable
            let first_source = sources
                .keys()
                .next()
                .map(|k| k.to_string())
                .unwrap_or_default();

            if !first_source.is_empty() {
                (PathBuf::from(&first_source), first_source)
            } else {
                // Fallback to inferring from artifact path
                let sol_file = path.parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                (PathBuf::from(&sol_file), sol_file)
            }
        } else {
            // Fallback if metadata.sources doesn't exist
            let sol_file = path.parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            (PathBuf::from(&sol_file), sol_file)
        }
    } else {
        // No metadata - fallback to inferring from path
        let sol_file = path.parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        (PathBuf::from(&sol_file), sol_file)
    };

    // Pre-compute resolved parameter types for all functions (expensive p.resolve() calls done once)
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

    Ok(Some(CompiledContract {
        name: name.to_string(),
        qualified_name: format!("{}:{}", qualified_source, name),
        abi: artifact.abi,
        bytecode,
        deployed_bytecode,
        source_path,
        functions,
        source_map: artifact.deployed_bytecode.source_map,
        init_source_map: artifact.bytecode.source_map,
        resolved_param_types,
        exclude_from_fuzzing: Vec::new(),
    }))
}

/// Parse bytecode string, replacing __$hash$__ placeholders with zeros
fn parse_bytecode_with_placeholders(object: &str) -> Result<Bytes> {
    let mut hex_str = object.trim_start_matches("0x").to_string();
    
    // Replace __$...$__ placeholders with zeros (40 hex chars = 20 bytes for address)
    while let Some(start) = hex_str.find("__$") {
        if let Some(end_offset) = hex_str[start..].find("$__") {
            let end = start + end_offset + 3;
            let zeros = "0".repeat(40);
            hex_str.replace_range(start..end, &zeros);
        } else {
            break;
        }
    }
    
    let bytes = hex::decode(&hex_str)?;
    Ok(Bytes::from(bytes))
}

/// Extract all __$hash$__ placeholders from a bytecode hex string
/// Returns a set of unique hashes (the 34-char string between __$ and $__)
fn extract_library_placeholders(bytecode_hex: &str) -> HashSet<String> {
    let mut placeholders = HashSet::new();
    let hex = bytecode_hex.trim_start_matches("0x");
    
    let mut pos = 0;
    while let Some(start) = hex[pos..].find("__$") {
        let abs_start = pos + start;
        if let Some(end_offset) = hex[abs_start..].find("$__") {
            let abs_end = abs_start + end_offset + 3;
            // Extract just the hash (between __$ and $__)
            let hash = &hex[abs_start + 3..abs_start + end_offset];
            placeholders.insert(hash.to_string());
            pos = abs_end;
        } else {
            break;
        }
    }
    
    placeholders
}

/// Compute the library placeholder hash for a qualified name
/// The hash is the first 34 chars of keccak256(qualified_name)
fn compute_library_hash(qualified_name: &str) -> String {
    let hash = keccak256(qualified_name.as_bytes());
    hex::encode(&hash.0)[..34].to_string()
}

/// Library information extracted from artifacts
#[derive(Debug, Clone)]
pub struct LibraryInfo {
    /// Library name
    pub name: String,
    /// Qualified name (e.g., "src/Lib.sol:MyLib")
    pub qualified_name: String,
    /// Placeholder hash (34 chars)
    pub hash: String,
    /// Raw init bytecode hex string (may contain nested placeholders)
    pub bytecode_hex: String,
    /// Raw deployed (runtime) bytecode hex string (may contain nested placeholders)
    pub deployed_bytecode_hex: String,
    /// Deployed address (set after deployment)
    pub address: Option<Address>,
}

/// Find a contract by name
pub fn find_contract<'a>(
    contracts: &'a [CompiledContract],
    name: Option<&str>,
) -> Option<&'a CompiledContract> {
    match name {
        Some(n) => contracts
            .iter()
            .find(|c| c.name == n || c.qualified_name.ends_with(&format!(":{}", n))),
        None => contracts.first(),
    }
}

// ============================================================================
// Library Linking Support using foundry-linking
// ============================================================================

/// Foundry project with linking support
pub struct FoundryProject {
    /// Project root
    pub root: PathBuf,
    /// All compiled contracts
    pub contracts: Vec<CompiledContract>,
    /// All libraries found in the project (by hash)
    pub libraries_by_hash: HashMap<String, LibraryInfo>,
    /// Deployed library addresses (hash -> address)
    pub deployed_libraries: HashMap<String, Address>,
    /// Libraries from foundry-linking
    pub libraries: Libraries,
    /// Libraries to deploy (bytecode in order)
    pub libs_to_deploy: Vec<Bytes>,
}

impl FoundryProject {
    /// Compile and prepare for linking
    pub fn compile(project_path: &Path) -> Result<Self> {
        info!("Compiling Foundry project at {:?}", project_path);
        
        // Run forge build first
        let output = Command::new("forge")
            .arg("build")
            .arg("--build-info")
            .arg("-o")
            .arg("out")
            .current_dir(project_path)
            .output()
            .context("Failed to run forge build")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("forge build failed: {}", stderr));
        }
        
        // Parse all artifacts to find contracts and libraries
        let out_dir = project_path.join("out");
        let mut contracts = Vec::new();
        let mut libraries_by_hash = HashMap::new();
        
        for entry in walkdir::WalkDir::new(&out_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().extension().map_or(false, |ext| ext == "json")
                    && !e.path().to_string_lossy().contains(".dbg.")
            })
        {
            let path = entry.path();
            let file_name = path.file_stem().unwrap_or_default().to_string_lossy();
            
            if file_name.starts_with('.') || file_name.contains(".metadata") {
                continue;
            }
            
            // Read raw JSON to get bytecode string with placeholders
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let json: serde_json::Value = match serde_json::from_str(&content) {
                Ok(j) => j,
                Err(_) => continue,
            };
            
            // Get bytecode as raw string (init code)
            let bytecode_hex = json
                .get("bytecode")
                .and_then(|b| b.get("object"))
                .and_then(|o| o.as_str())
                .unwrap_or("")
                .to_string();

            if bytecode_hex.is_empty() || bytecode_hex == "0x" {
                continue;
            }

            // Get deployed (runtime) bytecode
            let deployed_bytecode_hex = json
                .get("deployedBytecode")
                .and_then(|b| b.get("object"))
                .and_then(|o| o.as_str())
                .unwrap_or("")
                .to_string();

            // Get source path from metadata or artifact path
            let source_path = json
                .get("metadata")
                .and_then(|m| m.get("settings"))
                .and_then(|s| s.get("compilationTarget"))
                .and_then(|c| c.as_object())
                .and_then(|o| o.keys().next())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    path.parent()
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default()
                });
            
            // Construct qualified name
            let qualified_name = format!("{}:{}", source_path, file_name);
            let hash = compute_library_hash(&qualified_name);
            
            debug!("Found contract: {} (hash: {})", qualified_name, hash);
            
            // Store as library info
            libraries_by_hash.insert(hash.clone(), LibraryInfo {
                name: file_name.to_string(),
                qualified_name: qualified_name.clone(),
                hash: hash.clone(),
                bytecode_hex: bytecode_hex.clone(),
                deployed_bytecode_hex: deployed_bytecode_hex.clone(),
                address: None,
            });
            
            // Also parse as CompiledContract for the main API
            if let Ok(Some(contract)) = parse_single_artifact(path, &file_name) {
                contracts.push(contract);
            }
        }
        
        info!("Loaded {} contracts, {} potential libraries", 
              contracts.len(), libraries_by_hash.len());
        
        Ok(Self {
            root: project_path.to_path_buf(),
            contracts,
            libraries_by_hash,
            deployed_libraries: HashMap::new(),
            libraries: Libraries::default(),
            libs_to_deploy: Vec::new(),
        })
    }
    
    /// Find all library dependencies (direct and nested) for a contract's bytecode
    pub fn find_all_library_deps(&self, bytecode_hex: &str) -> Vec<String> {
        // Find all placeholders in this bytecode
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
                    // Add to deps list
                    all_deps.push(hash.clone());
                    
                    // Check if this library has its own dependencies
                    let lib_deps = extract_library_placeholders(&lib.bytecode_hex);
                    for dep in lib_deps {
                        if !visited.contains(&dep) {
                            next_needed.insert(dep);
                        }
                    }
                } else {
                    warn!("Unknown library hash: {}", hash);
                }
            }
            
            needed = next_needed;
        }
        
        // Reverse to get deployment order (dependencies first)
        all_deps.reverse();
        all_deps
    }
    
    /// Deploy all needed libraries and link them into the contract bytecode
    /// `reserved_addr` is the address where the main contract will be deployed,
    /// so we must not deploy any libraries there.
    pub fn deploy_libraries_and_link(
        &mut self,
        vm: &mut EvmState,
        contract_name: &str,
        deployer: Address,
        reserved_addr: Option<Address>,
        coverage_ref: &std::sync::Arc<parking_lot::RwLock<crate::exec::CoverageMap>>,
        codehash_map: &std::sync::Arc<parking_lot::RwLock<crate::coverage::MetadataToCodehash>>,
    ) -> Result<Bytes> {
        // Get the raw bytecode hex for the contract
        let bytecode_hex = if let Some(lib) = self.libraries_by_hash.values().find(|l| l.name == contract_name) {
            lib.bytecode_hex.clone()
        } else {
            // Not found by simple name, try qualified name match
            if let Some(lib) = self.libraries_by_hash.values().find(|l| l.qualified_name.ends_with(&format!(":{}", contract_name))) {
                lib.bytecode_hex.clone()
            } else {
                return Err(anyhow!("Contract {} not found in libraries_by_hash", contract_name));
            }
        };

        // Find all library dependencies
        let deps = self.find_all_library_deps(&bytecode_hex);
        
        if deps.is_empty() {
            return self.link_bytecode_with_deployed(&bytecode_hex);
        }
        
        info!("Deploying {} library dependencies for {}", deps.len(), contract_name);
        
        // Deploy libraries in order
        for hash in &deps {
            if self.deployed_libraries.contains_key(hash) {
                continue; // Already deployed
            }
            
            let lib = self.libraries_by_hash
                .get(hash)
                .ok_or_else(|| anyhow!("Library with hash {} not found", hash))?
                .clone();
            
            // Link the library's own bytecode (it may have dependencies)
            let linked_bytecode = self.link_bytecode_with_deployed(&lib.bytecode_hex)?;
            
            // Deploy library - avoid reserved address by bumping nonce if needed
            let mut nonce = vm.get_nonce(deployer);
            let mut lib_addr = deployer.create(nonce);
            
            // If this would conflict with the reserved address (where main contract goes),
            // perform a dummy deployment to bump the nonce and get a different address
            if let Some(reserved) = reserved_addr {
                while lib_addr == reserved {
                    warn!(
                        "Library {} would be deployed at reserved address {:?}, bumping nonce",
                        lib.name, reserved
                    );
                    // Increment nonce by doing a self-transfer (or we can just set the nonce)
                    vm.set_nonce(deployer, nonce + 1);
                    nonce = vm.get_nonce(deployer);
                    lib_addr = deployer.create(nonce);
                }
            }
            
            info!("Deploying library {} at {:?}", lib.name, lib_addr);

            vm.deploy_contract_at(deployer, lib_addr, linked_bytecode, U256::ZERO, coverage_ref, codehash_map)
                .map_err(|e| anyhow!("Failed to deploy library {}: {}", lib.name, e))?;
            
            // Record deployed address
            self.deployed_libraries.insert(hash.clone(), lib_addr);
        }
        
        // Now link the main contract's bytecode
        let linked = self.link_bytecode_with_deployed(&bytecode_hex)?;
        
        // Verify no unlinked placeholders remain
        let linked_hex = hex::encode(&linked);
        if linked_hex.contains("__$") {
            let remaining = extract_library_placeholders(&linked_hex);
            return Err(anyhow!(
                "Contract {} still has {} unlinked library references: {:?}",
                contract_name, remaining.len(), remaining
            ));
        }
        
        Ok(linked)
    }
    
    /// Link a bytecode hex string using already-deployed libraries
    fn link_bytecode_with_deployed(&self, bytecode_hex: &str) -> Result<Bytes> {
        let mut hex = bytecode_hex.trim_start_matches("0x").to_string();
        
        // Replace each placeholder with its deployed address
        for (hash, addr) in &self.deployed_libraries {
            let placeholder = format!("__${}$__", hash);
            let addr_hex = hex::encode(addr.as_slice());
            hex = hex.replace(&placeholder, &addr_hex);
        }
        
        // Replace any remaining placeholders with zeros (should not happen if deps are correct)
        while let Some(start) = hex.find("__$") {
            if let Some(end_offset) = hex[start..].find("$__") {
                let end = start + end_offset + 3;
                let zeros = "0".repeat(40);
                warn!("Replacing unlinked placeholder with zeros: {}", &hex[start..end]);
                hex.replace_range(start..end, &zeros);
            } else {
                break;
            }
        }
        
        let bytes = hex::decode(&hex)?;
        Ok(Bytes::from(bytes))
    }
    
    /// Get all deployed library addresses with their names
    /// Returns Vec<(address, library_name)>
    pub fn get_deployed_library_addresses(&self) -> Vec<(Address, String)> {
        self.deployed_libraries.iter()
            .filter_map(|(hash, addr)| {
                self.libraries_by_hash.get(hash).map(|lib| (*addr, lib.name.clone()))
            })
            .collect()
    }
    
    /// Get contract info (ABI, etc)
    pub fn get_contract(&self, name: &str) -> Option<&CompiledContract> {
        // First try qualified name match (e.g. "path/to/File.sol:Contract")
        if name.contains(':') {
            if let Some(c) = self.contracts.iter().find(|c| c.qualified_name == name) {
                return Some(c);
            }
        }
        // Collect all matches by simple name
        let matches: Vec<_> = self.contracts.iter()
            .filter(|c| c.name == name || c.qualified_name.ends_with(&format!(":{}", name)))
            .collect();
        if matches.len() > 1 {
            tracing::warn!("Multiple contracts named '{}' found:", name);
            for m in &matches {
                tracing::warn!("  - {} ({} bytes)", m.qualified_name, m.bytecode.len());
            }
            tracing::warn!("Using first match: {}. Use qualified name to disambiguate.", matches[0].qualified_name);
        }
        matches.into_iter().next()
    }
}

/// Deploy contract with automatic library linking
///
/// This function:
/// 1. Scans the contract bytecode for ALL __$hash$__ placeholders (including nested)
/// 2. Deploys required libraries in dependency order
/// 3. Links all bytecodes with deployed addresses
/// 4. Deploys the main contract
/// 5. Returns (deployed_address, constructor_traces) for dictionary extraction
pub fn deploy_with_linking(
    vm: &mut EvmState,
    project: &mut FoundryProject,
    contract_name: &str,
    deployer: Address,
    target_addr: Address,
    coverage_ref: &std::sync::Arc<parking_lot::RwLock<crate::exec::CoverageMap>>,
    codehash_map: &std::sync::Arc<parking_lot::RwLock<crate::coverage::MetadataToCodehash>>,
) -> Result<(Address, revm_inspectors::tracing::CallTraceArena)> {
    deploy_with_linking_and_value(vm, project, contract_name, deployer, target_addr, U256::ZERO, coverage_ref, codehash_map)
}

/// Deploy contract with automatic library linking and optional constructor value
/// Returns (deployed_address, constructor_traces) for dictionary extraction
pub fn deploy_with_linking_and_value(
    vm: &mut EvmState,
    project: &mut FoundryProject,
    contract_name: &str,
    deployer: Address,
    target_addr: Address,
    value: U256,
    coverage_ref: &std::sync::Arc<parking_lot::RwLock<crate::exec::CoverageMap>>,
    codehash_map: &std::sync::Arc<parking_lot::RwLock<crate::coverage::MetadataToCodehash>>,
) -> Result<(Address, revm_inspectors::tracing::CallTraceArena)> {
    // Deploy libraries and get linked bytecode
    // Pass target_addr as reserved to avoid deploying libraries at that address
    let linked_bytecode = project.deploy_libraries_and_link(vm, contract_name, deployer, Some(target_addr), coverage_ref, codehash_map)?;

    // Deploy at target address
    info!("Deploying {} at {:?}", contract_name, target_addr);
    let (deployed_addr, traces) = vm.deploy_contract_at(deployer, target_addr, linked_bytecode.clone(), value, coverage_ref, codehash_map)
        .map_err(|e| anyhow!("Failed to deploy {}: {}", contract_name, e))?;

    Ok((deployed_addr, traces))
}

// Simple directory walker
mod walkdir {
    use std::fs;
    use std::path::{Path, PathBuf};

    pub struct WalkDir {
        stack: Vec<PathBuf>,
    }

    impl WalkDir {
        pub fn new(path: &Path) -> Self {
            Self {
                stack: vec![path.to_path_buf()],
            }
        }
    }

    pub struct DirEntry {
        path: PathBuf,
    }

    impl DirEntry {
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Iterator for WalkDir {
        type Item = Result<DirEntry, std::io::Error>;

        fn next(&mut self) -> Option<Self::Item> {
            while let Some(path) = self.stack.pop() {
                if path.is_dir() {
                    match fs::read_dir(&path) {
                        Ok(entries) => {
                            for entry in entries.flatten() {
                                self.stack.push(entry.path());
                            }
                        }
                        Err(e) => return Some(Err(e)),
                    }
                } else if path.is_file() {
                    return Some(Ok(DirEntry { path }));
                }
            }
            None
        }
    }
}
