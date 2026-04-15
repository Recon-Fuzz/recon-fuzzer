//! Dynamic Interface-to-Implementation Linking
//!
//! During fuzzing, we observe which codehash is called from interface variables.
//! This module uses that runtime information to dynamically generate the correct
//! `--link` mappings for the CFG expander.
//!
//! Example:
//! - At runtime, we observe: iHub (interface) at address 0x123 calls codehash 0xabc
//! - We know codehash 0xabc corresponds to contract "Hub" from compile-time mapping
//! - We can now tell the expander: --link "iHub:Hub"
//!
//! This handles cases where:
//! - iSpoke might point to SpokeV1 or SpokeV2 depending on deployment
//! - Interfaces are used polymorphically
//! - Diamond proxies route to different facets

use alloy_primitives::{Address, FixedBytes, B256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

/// Information about an interface - its selectors
#[derive(Debug, Clone, Default)]
pub struct InterfaceInfo {
    /// Function selectors defined by this interface
    pub selectors: HashSet<FixedBytes<4>>,
}

/// Information about a contract implementation
#[derive(Debug, Clone, Default)]
pub struct ContractImplInfo {
    /// Contract name
    pub name: String,
    /// Function selectors this contract implements
    pub selectors: HashSet<FixedBytes<4>>,
    /// Interfaces this contract explicitly inherits (from AST)
    pub inherited_interfaces: HashSet<String>,
}

/// Tracks observed interface → implementation relationships from execution traces
#[derive(Debug, Clone, Default)]
pub struct InterfaceLinkTracker {
    /// Map from interface variable name to observed implementation codehash
    /// e.g., "iHub" -> codehash of Hub contract
    interface_to_codehash: HashMap<String, HashSet<B256>>,

    /// Map from codehash to contract name (from compilation)
    pub codehash_to_name: HashMap<B256, String>,

    /// Map from address to the interface variable that holds it
    /// This is populated when we see storage reads like `iHub` loading an address
    address_to_interface: HashMap<Address, String>,

    /// Observed call relationships: caller codehash -> callee codehash
    /// Used to infer which implementation an interface calls
    call_graph: HashMap<B256, HashSet<B256>>,

    /// Interface info: interface type name -> selectors
    interface_info: HashMap<String, InterfaceInfo>,

    /// Contract implementations: contract name -> impl info  
    contract_impls: HashMap<String, ContractImplInfo>,
}

impl InterfaceLinkTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize with codehash → contract name mapping from compilation
    pub fn with_codehash_map(codehash_to_name: HashMap<B256, String>) -> Self {
        Self {
            codehash_to_name,
            ..Default::default()
        }
    }

    /// Record that an interface variable holds a specific address
    pub fn record_interface_address(&mut self, interface_name: &str, address: Address) {
        self.address_to_interface
            .insert(address, interface_name.to_string());
    }

    /// Record a call from one codehash to another
    pub fn record_call(&mut self, caller_codehash: B256, callee_codehash: B256) {
        self.call_graph
            .entry(caller_codehash)
            .or_default()
            .insert(callee_codehash);
    }

    /// Record that we observed an interface calling a specific codehash
    pub fn record_interface_implementation(&mut self, interface_name: &str, impl_codehash: B256) {
        self.interface_to_codehash
            .entry(interface_name.to_string())
            .or_default()
            .insert(impl_codehash);
    }

    /// Get the contract name for a codehash
    pub fn get_contract_name(&self, codehash: &B256) -> Option<&String> {
        self.codehash_to_name.get(codehash)
    }

    /// Get all observed implementations for an interface
    pub fn get_implementations(&self, interface_name: &str) -> Vec<String> {
        self.interface_to_codehash
            .get(interface_name)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| self.codehash_to_name.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Generate --link string for expander
    /// Format: "iHub:Hub,iSpoke:SpokeV1,iOracle:AaveOracle"
    pub fn generate_link_string(&self) -> String {
        let mut links = Vec::new();

        for (interface, codehashes) in &self.interface_to_codehash {
            // If multiple implementations observed, use the most recent one
            // In practice, we might want to generate CFGs for all variants
            if let Some(impl_name) = codehashes
                .iter()
                .filter_map(|h| self.codehash_to_name.get(h))
                .next()
            {
                links.push(format!("{}:{}", interface, impl_name));
            }
        }

        links.join(",")
    }

    /// Generate multiple link strings if an interface has multiple implementations
    /// Useful for generating CFGs for all possible paths
    pub fn generate_all_link_variants(&self) -> Vec<String> {
        // This is a more complex combinatorial problem
        // For now, just return the primary link string
        vec![self.generate_link_string()]
    }

    /// Check if we have enough link information to generate CFGs
    pub fn has_link_info(&self) -> bool {
        !self.interface_to_codehash.is_empty()
    }

    /// Get interfaces that don't have known implementations yet
    pub fn unresolved_interfaces(&self, known_interfaces: &[&str]) -> Vec<String> {
        known_interfaces
            .iter()
            .filter(|iface| !self.interface_to_codehash.contains_key(**iface))
            .map(|s| s.to_string())
            .collect()
    }

    /// Register an interface with its function selectors
    pub fn register_interface(&mut self, interface_name: &str, selectors: HashSet<FixedBytes<4>>) {
        self.interface_info
            .insert(interface_name.to_string(), InterfaceInfo { selectors });
    }

    /// Register a contract implementation with its selectors and inherited interfaces
    pub fn register_contract(
        &mut self,
        name: &str,
        selectors: HashSet<FixedBytes<4>>,
        inherited_interfaces: HashSet<String>,
    ) {
        self.contract_impls.insert(
            name.to_string(),
            ContractImplInfo {
                name: name.to_string(),
                selectors,
                inherited_interfaces,
            },
        );
    }

    /// Find contracts that implement a given interface
    /// Priority:
    /// 1. Explicit inheritance (from AST, if available)
    /// 2. Name pattern match (IHub -> Hub, HubImpl, etc.)
    /// 3. Selector subset match (contract has all interface selectors)
    ///
    /// When multiple implementations match, we prefer:
    /// - Exact name match (IHub -> Hub) over partial (IHub -> SomeHub)
    /// - Fewer extra functions (closer match) over more
    pub fn find_implementations(&self, interface_name: &str) -> Vec<String> {
        let mut scored_implementations: Vec<(String, u32)> = Vec::new();

        // First: Check explicit inheritance (highest priority, score 1000)
        for (contract_name, impl_info) in &self.contract_impls {
            if impl_info.inherited_interfaces.contains(interface_name) {
                scored_implementations.push((contract_name.clone(), 1000));
            }
        }

        // If we found explicit implementations, return them (sorted by score)
        if !scored_implementations.is_empty() {
            scored_implementations.sort_by(|a, b| b.1.cmp(&a.1));
            return scored_implementations
                .into_iter()
                .map(|(name, _)| name)
                .collect();
        }

        // Get expected implementation name from interface (strip leading 'I')
        let expected_impl_name = if interface_name.starts_with('I')
            && interface_name.len() > 1
            && interface_name
                .chars()
                .nth(1)
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
        {
            &interface_name[1..]
        } else {
            interface_name
        };

        // Check name patterns
        for (contract_name, impl_info) in &self.contract_impls {
            let mut score = 0u32;

            // Exact match: IHub -> Hub (score 500)
            if contract_name == expected_impl_name {
                score = 500;
            }
            // Contract ends with expected name: IHub -> MyHub, SomeHub (score 200)
            else if contract_name.ends_with(expected_impl_name) {
                score = 200;
            }
            // Contract contains expected name: IHub -> HubWrapper (score 100)
            else if contract_name.contains(expected_impl_name) {
                score = 100;
            }

            if score > 0 {
                // Bonus: if interface selectors exist and are subset, add 50
                if let Some(interface_info) = self.interface_info.get(interface_name) {
                    if !interface_info.selectors.is_empty()
                        && interface_info.selectors.is_subset(&impl_info.selectors)
                    {
                        score += 50;
                    }
                }
                scored_implementations.push((contract_name.clone(), score));
            }
        }

        // Fallback: Pure selector matching (score based on selector ratio)
        if scored_implementations.is_empty() {
            if let Some(interface_info) = self.interface_info.get(interface_name) {
                if !interface_info.selectors.is_empty() {
                    for (contract_name, impl_info) in &self.contract_impls {
                        // Contract implements interface if it has ALL the interface's selectors
                        if interface_info.selectors.is_subset(&impl_info.selectors) {
                            // Score based on how close the match is (fewer extra functions = better)
                            let extra_selectors =
                                impl_info.selectors.len() - interface_info.selectors.len();
                            let score = 50u32.saturating_sub(extra_selectors as u32 / 2);
                            scored_implementations.push((contract_name.clone(), score));
                        }
                    }
                }
            }
        }

        // Sort by score (descending) and return names
        scored_implementations.sort_by(|a, b| b.1.cmp(&a.1));
        scored_implementations
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    /// Infer links for all known interfaces using selector/inheritance matching
    pub fn infer_all_links(&mut self) {
        let interface_names: Vec<String> = self.interface_info.keys().cloned().collect();

        for interface_name in interface_names {
            let implementations = self.find_implementations(&interface_name);

            // If exactly one implementation found, record it
            if implementations.len() == 1 {
                // We don't have codehash here, so just store the name mapping
                // This will be used by generate_link_string_from_names
                tracing::debug!(
                    "Inferred link: {} -> {}",
                    interface_name,
                    implementations[0]
                );
            } else if implementations.len() > 1 {
                tracing::debug!(
                    "Multiple implementations for {}: {:?}",
                    interface_name,
                    implementations
                );
            }
        }
    }

    /// Generate link string using name-based inference (no runtime codehash needed)
    pub fn generate_link_string_from_inference(&self) -> String {
        let mut links = Vec::new();

        for (interface_name, _) in &self.interface_info {
            let implementations = self.find_implementations(interface_name);
            if let Some(impl_name) = implementations.first() {
                links.push(format!("{}:{}", interface_name, impl_name));
            }
        }

        links.join(",")
    }
}

/// Result of regenerating CFGs with new link information
#[derive(Debug)]
pub struct CfgRegenerationResult {
    pub success: bool,
    pub link_string: String,
    pub output_dir: String,
    pub contracts_generated: Vec<String>,
    pub error: Option<String>,
}

/// Regenerate CFGs with discovered interface links
pub fn regenerate_cfgs_with_links(
    project_dir: &Path,
    _contract_name: &str, // kept for API compatibility
    link_tracker: &InterfaceLinkTracker,
    output_dir: &Path,
) -> CfgRegenerationResult {
    let link_string = link_tracker.generate_link_string();

    if link_string.is_empty() {
        return CfgRegenerationResult {
            success: false,
            link_string: String::new(),
            output_dir: output_dir.to_string_lossy().to_string(),
            contracts_generated: vec![],
            error: Some("No interface links discovered".to_string()),
        };
    }

    // Run recon-generate (no args - auto-detects project)
    // Note: link_string is tracked but not used by simplified CLI
    let result = Command::new("npx")
        .args(["-y", "recon-generate@latest", "sourcemap"])
        .current_dir(project_dir)
        .output();

    match result {
        Ok(output) => {
            if output.status.success() {
                // Parse output to find generated contracts
                let stdout = String::from_utf8_lossy(&output.stdout);
                let contracts: Vec<String> = stdout
                    .lines()
                    .filter(|l| l.contains("✅ CFG written"))
                    .filter_map(|l| {
                        l.split('/')
                            .last()
                            .map(|s| s.trim_end_matches(".cfg.sexp").to_string())
                    })
                    .collect();

                CfgRegenerationResult {
                    success: true,
                    link_string,
                    output_dir: output_dir.to_string_lossy().to_string(),
                    contracts_generated: contracts,
                    error: None,
                }
            } else {
                CfgRegenerationResult {
                    success: false,
                    link_string,
                    output_dir: output_dir.to_string_lossy().to_string(),
                    contracts_generated: vec![],
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                }
            }
        }
        Err(e) => CfgRegenerationResult {
            success: false,
            link_string,
            output_dir: output_dir.to_string_lossy().to_string(),
            contracts_generated: vec![],
            error: Some(format!("Failed to run recon-generate: {}", e)),
        },
    }
}

/// Extract interface names from contract source/AST
/// These are typically variables named iXxx or IXxx
pub fn detect_interface_variables(contract_source: &str) -> Vec<String> {
    let mut interfaces = Vec::new();

    // Simple heuristic: find variable declarations like `IHub iHub` or `ISpoke public spoke`
    // More robust would be to use AST analysis
    for line in contract_source.lines() {
        let line = line.trim();

        // Pattern: IInterface varname or IInterface public/private/internal varname
        if line.starts_with('I') && line.contains(' ') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let type_name = parts[0];
                // Skip if it's not an interface type (starts with I and is CamelCase)
                if type_name.starts_with('I')
                    && type_name
                        .chars()
                        .nth(1)
                        .map(|c| c.is_uppercase())
                        .unwrap_or(false)
                {
                    // The variable name is typically the last identifier before ; or =
                    for part in parts.iter().rev() {
                        let clean = part.trim_end_matches(';').trim_end_matches('=');
                        if !clean.is_empty()
                            && !["public", "private", "internal", "immutable", "constant"]
                                .contains(&clean)
                        {
                            // Check if it looks like a variable name (lowercase first char or starts with i/I)
                            if clean
                                .chars()
                                .next()
                                .map(|c| c.is_lowercase() || c == 'i')
                                .unwrap_or(false)
                            {
                                interfaces.push(clean.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    interfaces
}

/// Infer interface links from the manifest's dependency information
/// Returns a map of (contract_name, interface_name) -> implementation_name
///
/// NOTE: This uses simple name pattern matching (IHub -> Hub).
/// For proper resolution using selector matching or inherited interfaces,
/// use `infer_links_from_contracts()` instead, which examines the actual
/// compiled contract ABIs.
pub fn infer_links_from_manifest(manifest_path: &Path) -> HashMap<String, HashMap<String, String>> {
    let mut contract_links: HashMap<String, HashMap<String, String>> = HashMap::new();

    if let Ok(content) = std::fs::read_to_string(manifest_path) {
        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(deps) = manifest.get("dependencies").and_then(|d| d.as_object()) {
                for (contract, info) in deps {
                    let mut links = HashMap::new();
                    if let Some(calls) = info.get("calls").and_then(|c| c.as_array()) {
                        for call in calls {
                            if let Some(call_str) = call.as_str() {
                                // Look for interface patterns: iXxx or IXxx
                                if (call_str.starts_with('i') || call_str.starts_with('I'))
                                    && call_str.len() > 1
                                    && call_str
                                        .chars()
                                        .nth(1)
                                        .map(|c| c.is_uppercase())
                                        .unwrap_or(false)
                                {
                                    // Try to find matching implementation
                                    // e.g., iHub -> Hub, ISpoke -> Spoke
                                    let impl_name = call_str[1..].to_string();
                                    links.insert(call_str.to_string(), impl_name);
                                }
                            }
                        }
                    }
                    if !links.is_empty() {
                        contract_links.insert(contract.clone(), links);
                    }
                }
            }
        }
    }

    contract_links
}

/// Infer interface->implementation links using compiled contract ABIs
/// This is the proper way to resolve interfaces - by matching function selectors
///
/// For each interface type (IHub, ISpoke, etc.), find contracts that:
/// 1. Explicitly inherit the interface (if AST info available), OR
/// 2. Implement all the interface's function selectors
pub fn infer_links_from_contracts(
    contracts: &[evm::foundry::CompiledContract],
) -> InterfaceLinkTracker {
    let mut tracker = InterfaceLinkTracker::new();

    // Separate interfaces from implementations
    // Interfaces typically have no bytecode or very minimal bytecode
    let mut interfaces: Vec<&evm::foundry::CompiledContract> = Vec::new();
    let mut implementations: Vec<&evm::foundry::CompiledContract> = Vec::new();

    for contract in contracts {
        // Heuristic: interfaces start with 'I' and have uppercase second char
        let is_interface = contract.name.starts_with('I')
            && contract
                .name
                .chars()
                .nth(1)
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
            && contract.deployed_bytecode.len() < 100; // Interfaces have minimal or no bytecode

        if is_interface {
            interfaces.push(contract);
        } else {
            implementations.push(contract);
        }
    }

    // Register all interfaces with their selectors
    for iface in &interfaces {
        let selectors: HashSet<FixedBytes<4>> = iface.functions.keys().copied().collect();
        tracker.register_interface(&iface.name, selectors);
    }

    // Register all implementations with their selectors
    for impl_contract in &implementations {
        let selectors: HashSet<FixedBytes<4>> = impl_contract.functions.keys().copied().collect();

        // Try to infer inherited interfaces from name patterns
        // e.g., "Hub" might implement "IHub"
        let mut inherited = HashSet::new();
        for iface in &interfaces {
            // Check if interface name matches pattern
            // IHub -> Hub, ISpoke -> Spoke
            let expected_impl_name = &iface.name[1..];
            if impl_contract.name == expected_impl_name
                || impl_contract.name.ends_with(expected_impl_name)
            {
                inherited.insert(iface.name.clone());
            }
        }

        tracker.register_contract(&impl_contract.name, selectors, inherited);
    }

    tracker
}

/// Build link string directly from compiled contracts
/// Returns links in format "IHub:Hub,ISpoke:SpokeInstance"
pub fn build_links_from_contracts(contracts: &[evm::foundry::CompiledContract]) -> String {
    let tracker = infer_links_from_contracts(contracts);
    tracker.generate_link_string_from_inference()
}

/// Build interface->implementation links using SlitherInfo inheritance data
/// This is the most accurate method - uses compile-time inheritance info from AST
///
/// For each interface (IHub, ISpoke), finds contracts that explicitly inherit it
/// according to the `inheritances` field in recon-info JSON.
///
/// Example:
///   inheritances: { "SpokeInstance": ["ISpoke", "ISpokeBase", ...] }
///   => ISpoke -> SpokeInstance
pub fn build_links_from_slither_info(
    slither_info: &analysis::slither::SlitherInfo,
    contracts: &[evm::foundry::CompiledContract],
) -> InterfaceLinkTracker {
    use std::collections::HashSet;

    let mut tracker = InterfaceLinkTracker::new();

    // Build interface -> implementations map from inheritance data
    let iface_to_impls = slither_info.build_interface_to_implementations();

    // Get all contract names we have compiled (useful for filtering valid implementations)
    let _compiled_contracts: HashSet<&str> = contracts.iter().map(|c| c.name.as_str()).collect();

    // Separate interfaces from implementations based on name pattern AND inheritance
    // Interfaces: start with 'I', minimal bytecode, have implementing contracts
    for contract in contracts {
        let is_interface = contract.name.starts_with('I')
            && contract
                .name
                .chars()
                .nth(1)
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
            && (contract.deployed_bytecode.len() < 100
                || iface_to_impls.contains_key(&contract.name));

        if is_interface {
            // Register interface with its selectors
            let selectors: HashSet<FixedBytes<4>> = contract.functions.keys().copied().collect();
            tracker.register_interface(&contract.name, selectors);
        }
    }

    // Register all non-interface contracts as implementations
    for contract in contracts {
        let is_interface = contract.name.starts_with('I')
            && contract
                .name
                .chars()
                .nth(1)
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
            && contract.deployed_bytecode.len() < 100;

        if !is_interface {
            let selectors: HashSet<FixedBytes<4>> = contract.functions.keys().copied().collect();

            // Get inherited interfaces from SlitherInfo
            let inherited_interfaces: HashSet<String> = slither_info
                .get_parents(&contract.name)
                .into_iter()
                .filter(|parent| {
                    // Only include parents that look like interfaces
                    parent.starts_with('I')
                        && parent
                            .chars()
                            .nth(1)
                            .map(|c| c.is_uppercase())
                            .unwrap_or(false)
                })
                .collect();

            tracker.register_contract(&contract.name, selectors, inherited_interfaces);
        }
    }

    tracker
}

/// Generate link string from SlitherInfo inheritance data
/// Returns links in format "IHub:Hub,ISpoke:SpokeInstance"
///
/// This prefers:
/// 1. Explicit inheritance matches from SlitherInfo
/// 2. Falls back to selector matching if no inheritance info
pub fn build_links_string_from_slither_info(
    slither_info: &analysis::slither::SlitherInfo,
    contracts: &[evm::foundry::CompiledContract],
) -> String {
    let tracker = build_links_from_slither_info(slither_info, contracts);
    tracker.generate_link_string_from_inference()
}

/// Find the best implementation for an interface using SlitherInfo
/// Returns None if no match found, Some(impl_name) if found
pub fn find_implementation_for_interface(
    interface_name: &str,
    slither_info: &analysis::slither::SlitherInfo,
    available_contracts: &[&str],
) -> Option<String> {
    // First: check explicit inheritance from SlitherInfo
    let implementors = slither_info.contracts_implementing(interface_name);

    for impl_name in &implementors {
        if available_contracts.contains(&impl_name.as_str()) {
            return Some(impl_name.clone());
        }
    }

    // Fallback: Name pattern matching
    // IHub -> Hub, ISpoke -> Spoke
    if interface_name.starts_with('I') && interface_name.len() > 1 {
        let expected_impl = &interface_name[1..];

        // Exact match
        if available_contracts.contains(&expected_impl) {
            return Some(expected_impl.to_string());
        }

        // Suffix match (e.g., ISpoke -> SpokeInstance)
        for contract in available_contracts {
            if contract.ends_with(expected_impl) {
                return Some(contract.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_tracker() {
        let mut tracker = InterfaceLinkTracker::new();

        let hub_hash = B256::repeat_byte(0x01);
        let spoke_hash = B256::repeat_byte(0x02);

        tracker.codehash_to_name.insert(hub_hash, "Hub".to_string());
        tracker
            .codehash_to_name
            .insert(spoke_hash, "SpokeV1".to_string());

        tracker.record_interface_implementation("iHub", hub_hash);
        tracker.record_interface_implementation("iSpoke", spoke_hash);

        let link_string = tracker.generate_link_string();
        assert!(link_string.contains("iHub:Hub"));
        assert!(link_string.contains("iSpoke:SpokeV1"));
    }

    #[test]
    fn test_detect_interface_variables() {
        let source = r#"
            contract Test {
                IHub public iHub;
                ISpoke internal spoke;
                IERC20 token; // not interface pattern
                uint256 value;
            }
        "#;

        let interfaces = detect_interface_variables(source);
        assert!(interfaces.contains(&"iHub".to_string()));
        assert!(interfaces.contains(&"spoke".to_string()));
    }

    #[test]
    fn test_infer_links_from_manifest() {
        // Test with a mock manifest structure
        let manifest = r#"{
            "dependencies": {
                "CryticTester": {
                    "calls": ["iHub", "iSpoke", "iOracle", "EnumerableSet"]
                }
            }
        }"#;

        let temp_dir = std::env::temp_dir();
        let manifest_path = temp_dir.join("test_manifest.json");
        std::fs::write(&manifest_path, manifest).unwrap();

        let contract_links = infer_links_from_manifest(&manifest_path);

        // Get links for CryticTester
        let links = contract_links
            .get("CryticTester")
            .expect("Should have CryticTester");

        assert_eq!(links.get("iHub"), Some(&"Hub".to_string()));
        assert_eq!(links.get("iSpoke"), Some(&"Spoke".to_string()));
        assert_eq!(links.get("iOracle"), Some(&"Oracle".to_string()));
        // EnumerableSet should not be linked (not an interface pattern)
        assert!(!links.contains_key("EnumerableSet"));

        std::fs::remove_file(manifest_path).ok();
    }
}
