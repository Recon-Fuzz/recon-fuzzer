//! Unified CFG-based coverage tracking
//!
//! Single source of truth for branch/edge coverage using coverage-map.json
//! Maps: (codehash, pc, taken) → edge_id with rich metadata for LLM/solver

use alloy_primitives::B256;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use parking_lot::RwLock;

// ============================================================================
// Unified Coverage Types (from coverage-map.json)
// ============================================================================

/// Unified branch info combining PC and edge metadata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnifiedBranch {
    /// PC of the JUMPI instruction
    pub pc: usize,
    /// AST node ID
    #[serde(rename = "astId")]
    pub ast_id: Option<u32>,
    /// All AST IDs at this source location
    #[serde(rename = "allAstIds", default)]
    pub all_ast_ids: Vec<u32>,
    /// Source byte offset
    pub offset: usize,
    /// Source byte length
    pub length: usize,
    /// Source file index
    #[serde(rename = "fileIndex")]
    pub file_index: usize,
    /// Line number of the branch condition (1-based)
    #[serde(rename = "conditionLine")]
    pub condition_line: Option<usize>,

    // === Edge info ===
    /// Edge ID when branch is taken (true)
    #[serde(rename = "trueEdge")]
    pub true_edge: Option<String>,
    /// Edge ID when branch is not taken (false)
    #[serde(rename = "falseEdge")]
    pub false_edge: Option<String>,
    /// Function name containing this branch
    pub function: Option<String>,
    /// Block ID in CFG
    pub block: Option<String>,

    // Body info
    /// Line number of the first statement in true branch
    #[serde(rename = "trueBodyLine")]
    pub true_body_line: Option<usize>,
    /// Line number of the first statement in false branch
    #[serde(rename = "falseBodyLine")]
    pub false_body_line: Option<usize>,
    /// First PC of the true branch body
    #[serde(rename = "trueBodyPc")]
    pub true_body_pc: Option<usize>,
    /// First PC of the false branch body
    #[serde(rename = "falseBodyPc")]
    pub false_body_pc: Option<usize>,

    // Metadata
    /// Whether this is an assertion (require/assert) - FALSE branch is the bug-finding path
    #[serde(rename = "isAssertion", default)]
    pub is_assertion: bool,
}

/// Per-contract unified coverage data
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnifiedContractCoverage {
    /// Contract name
    pub name: String,
    /// Source file path
    #[serde(rename = "sourceFile")]
    pub source_file: String,
    /// Total edges (2 per branch: true + false)
    #[serde(rename = "totalEdges")]
    pub total_edges: usize,
    /// All branches with unified info
    pub branches: Vec<UnifiedBranch>,
}

/// Unified coverage manifest from coverage-map.json
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnifiedCoverageManifest {
    /// Generation timestamp
    pub generated: String,
    /// Schema version
    pub version: String,
    /// Total contracts
    #[serde(rename = "totalContracts")]
    pub total_contracts: usize,
    /// Total branch points
    #[serde(rename = "totalBranches")]
    pub total_branches: usize,
    /// Total edges (branch directions)
    #[serde(rename = "totalEdges")]
    pub total_edges: usize,
    /// Per-contract coverage data
    pub contracts: HashMap<String, UnifiedContractCoverage>,
}

// ============================================================================
// Runtime Coverage Tracking
// ============================================================================

/// Compact branch coverage key for runtime tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BranchCoverageKey {
    /// Contract index (for compact storage)
    pub contract_idx: u16,
    /// Program counter
    pub pc: u32,
    /// Branch direction: true = taken, false = not taken
    pub taken: bool,
}

/// Uncovered branch info for LLM context
#[derive(Debug, Clone)]
pub struct UncoveredBranchInfo {
    pub contract: String,
    pub function: String,
    pub edge_id: String,
    pub is_true_branch: bool,
    pub condition_line: Option<usize>,
    pub body_line: Option<usize>,
    pub body_pc: Option<usize>,
    pub branch_pc: usize,
}

/// Unified coverage tracker - single source of truth for all coverage
///
/// Uses compact BranchCoverageKey for fast runtime tracking while
/// providing rich metadata (edge IDs, function names, line numbers) for LLM/solver
#[derive(Debug)]
pub struct UnifiedCoverage {
    /// The loaded manifest
    pub manifest: UnifiedCoverageManifest,
    /// Contract name → index mapping (for compact keys)
    contract_to_idx: HashMap<String, u16>,
    /// Index → contract name
    idx_to_contract: Vec<String>,
    /// Per-contract branch lookup: contract_idx → (pc → branch index)
    branch_lookup: Vec<HashMap<usize, usize>>,
    /// Edge ID → (contract_idx, branch_idx, is_true_branch) for reverse lookup
    edge_id_to_branch: HashMap<String, (u16, usize, bool)>,
    /// Total branch directions (for statistics)
    total_edges: usize,

    // === LIVE DATA (shared across workers) ===
    /// Covered branches using compact keys
    covered: Arc<RwLock<HashSet<BranchCoverageKey>>>,
    /// Codehash → contract_idx (built at runtime from deployed contracts)
    codehash_to_contract: Arc<RwLock<HashMap<B256, u16>>>,
}

impl UnifiedCoverage {
    /// Load from .recon/coverage-map.json
    pub fn load(recon_dir: &Path) -> Result<Self> {
        let coverage_map_path = recon_dir.join("coverage-map.json");

        if !coverage_map_path.exists() {
            anyhow::bail!(
                "coverage-map.json not found in {:?}. Run `recon-generate sourcemap` first.",
                recon_dir
            );
        }

        let content = fs::read_to_string(&coverage_map_path)
            .with_context(|| format!("Failed to read {:?}", coverage_map_path))?;

        let manifest: UnifiedCoverageManifest = serde_json::from_str(&content)
            .with_context(|| "Failed to parse coverage-map.json")?;

        Self::from_manifest(manifest)
    }

    /// Create from a parsed manifest
    pub fn from_manifest(manifest: UnifiedCoverageManifest) -> Result<Self> {
        let mut contract_to_idx = HashMap::new();
        let mut idx_to_contract = Vec::new();
        let mut branch_lookup = Vec::new();
        let mut edge_id_to_branch = HashMap::new();
        let mut total_edges = 0;

        for (idx, (contract_name, contract_data)) in manifest.contracts.iter().enumerate() {
            let contract_idx = idx as u16;
            contract_to_idx.insert(contract_name.clone(), contract_idx);
            idx_to_contract.push(contract_name.clone());

            let mut pc_to_branch_idx = HashMap::new();

            for (branch_idx, branch) in contract_data.branches.iter().enumerate() {
                pc_to_branch_idx.insert(branch.pc, branch_idx);

                // Build edge ID → branch lookup
                if let Some(ref true_edge) = branch.true_edge {
                    edge_id_to_branch.insert(true_edge.clone(), (contract_idx, branch_idx, true));
                    total_edges += 1;
                }
                if let Some(ref false_edge) = branch.false_edge {
                    edge_id_to_branch.insert(false_edge.clone(), (contract_idx, branch_idx, false));
                    total_edges += 1;
                }
            }

            branch_lookup.push(pc_to_branch_idx);
        }

        tracing::info!(
            "Loaded unified coverage: {} contracts, {} branches, {} edges",
            manifest.total_contracts,
            manifest.total_branches,
            total_edges
        );

        Ok(Self {
            manifest,
            contract_to_idx,
            idx_to_contract,
            branch_lookup,
            edge_id_to_branch,
            total_edges,
            covered: Arc::new(RwLock::new(HashSet::new())),
            codehash_to_contract: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Register all compiled contracts at once
    pub fn register_contracts(&self, contracts: &[crate::foundry::CompiledContract]) {
        let mut map = self.codehash_to_contract.write();
        let mut registered = 0;

        for contract in contracts {
            if contract.deployed_bytecode.is_empty() {
                continue;
            }

            let compile_time_codehash = alloy_primitives::keccak256(&contract.deployed_bytecode);

            if let Some(&idx) = self.contract_to_idx.get(&contract.name) {
                map.insert(compile_time_codehash, idx);
                registered += 1;
            }
        }

        tracing::info!("UnifiedCoverage: Registered {} contracts", registered);
    }

    /// Get number of registered contracts
    pub fn num_registered_contracts(&self) -> usize {
        self.codehash_to_contract.read().len()
    }

    /// Record a branch hit and return the edge ID if this is a new edge
    pub fn record_branch(&self, codehash: B256, pc: usize, taken: bool) -> Option<String> {
        // Look up contract from codehash
        let contract_idx = {
            let map = self.codehash_to_contract.read();
            *map.get(&codehash)?
        };

        // Check if this PC is a known branch
        if (contract_idx as usize) >= self.branch_lookup.len() {
            return None;
        }

        // The coverage-map.json records branch PCs at the PUSH instruction before JUMPI,
        // but the inspector records at the JUMPI instruction itself. Try both:
        // - Direct match (PC is exactly as in coverage map)
        // - Adjusted match (PC is JUMPI, coverage map has PUSH2 at PC-3 or PUSH1 at PC-2)
        let branch_lookup = &self.branch_lookup[contract_idx as usize];
        let effective_pc = if branch_lookup.contains_key(&pc) {
            pc
        } else if pc >= 3 && branch_lookup.contains_key(&(pc - 3)) {
            // PUSH2+JUMPI: PUSH2 is 3 bytes, so JUMPI PC = PUSH2 PC + 3
            pc - 3
        } else if pc >= 2 && branch_lookup.contains_key(&(pc - 2)) {
            // PUSH1+JUMPI: PUSH1 is 2 bytes, so JUMPI PC = PUSH1 PC + 2
            pc - 2
        } else {
            // No match found
            return None;
        };

        // Record coverage using the effective PC (the one in the coverage map)
        let key = BranchCoverageKey {
            contract_idx,
            pc: effective_pc as u32,
            taken,
        };

        let mut covered = self.covered.write();
        if covered.insert(key) {
            // Return edge ID for newly covered edge
            let contract_name = &self.idx_to_contract[contract_idx as usize];
            let contract_data = self.manifest.contracts.get(contract_name)?;

            for branch in &contract_data.branches {
                if branch.pc == effective_pc {
                    return if taken {
                        branch.true_edge.clone()
                    } else {
                        branch.false_edge.clone()
                    };
                }
            }
            None
        } else {
            None
        }
    }

    /// Check if a specific edge is covered (by edge ID)
    pub fn is_edge_covered(&self, edge_id: &str) -> bool {
        if let Some(&(contract_idx, branch_idx, is_true)) = self.edge_id_to_branch.get(edge_id) {
            if let Some(contract_name) = self.idx_to_contract.get(contract_idx as usize) {
                if let Some(contract_data) = self.manifest.contracts.get(contract_name) {
                    if let Some(branch) = contract_data.branches.get(branch_idx) {
                        let key = BranchCoverageKey {
                            contract_idx,
                            pc: branch.pc as u32,
                            taken: is_true,
                        };
                        return self.covered.read().contains(&key);
                    }
                }
            }
        }
        false
    }

    /// Get uncovered edge IDs for a contract (for solver coordination)
    pub fn uncovered_edge_ids(&self, contract_name: &str) -> Vec<String> {
        let covered = self.covered.read();
        let mut result = Vec::new();

        if let Some(&contract_idx) = self.contract_to_idx.get(contract_name) {
            if let Some(contract_data) = self.manifest.contracts.get(contract_name) {
                for branch in &contract_data.branches {
                    // Check true edge
                    let true_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: true,
                    };
                    if !covered.contains(&true_key) {
                        if let Some(ref edge_id) = branch.true_edge {
                            result.push(edge_id.clone());
                        }
                    }

                    // Check false edge
                    let false_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: false,
                    };
                    if !covered.contains(&false_key) {
                        if let Some(ref edge_id) = branch.false_edge {
                            result.push(edge_id.clone());
                        }
                    }
                }
            }
        }

        result
    }

    /// Get all uncovered edge IDs
    pub fn all_uncovered_edge_ids(&self) -> Vec<String> {
        let covered = self.covered.read();
        let mut result = Vec::new();

        for (contract_name, contract_data) in &self.manifest.contracts {
            if let Some(&contract_idx) = self.contract_to_idx.get(contract_name) {
                for branch in &contract_data.branches {
                    let true_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: true,
                    };
                    if !covered.contains(&true_key) {
                        if let Some(ref edge_id) = branch.true_edge {
                            result.push(edge_id.clone());
                        }
                    }

                    let false_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: false,
                    };
                    if !covered.contains(&false_key) {
                        if let Some(ref edge_id) = branch.false_edge {
                            result.push(edge_id.clone());
                        }
                    }
                }
            }
        }

        result
    }

    /// Get uncovered branches with full metadata (for LLM context)
    pub fn uncovered_branches_with_info(&self, contract_name: &str) -> Vec<UncoveredBranchInfo> {
        let covered = self.covered.read();
        let mut result = Vec::new();

        if let Some(&contract_idx) = self.contract_to_idx.get(contract_name) {
            if let Some(contract_data) = self.manifest.contracts.get(contract_name) {
                for branch in &contract_data.branches {
                    let function = branch.function.clone().unwrap_or_default();

                    // Check true edge
                    let true_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: true,
                    };
                    if !covered.contains(&true_key) {
                        if let Some(ref edge_id) = branch.true_edge {
                            result.push(UncoveredBranchInfo {
                                contract: contract_name.to_string(),
                                function: function.clone(),
                                edge_id: edge_id.clone(),
                                is_true_branch: true,
                                condition_line: branch.condition_line,
                                body_line: branch.true_body_line,
                                body_pc: branch.true_body_pc,
                                branch_pc: branch.pc,
                            });
                        }
                    }

                    // Check false edge
                    let false_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: false,
                    };
                    if !covered.contains(&false_key) {
                        if let Some(ref edge_id) = branch.false_edge {
                            result.push(UncoveredBranchInfo {
                                contract: contract_name.to_string(),
                                function: function.clone(),
                                edge_id: edge_id.clone(),
                                is_true_branch: false,
                                condition_line: branch.condition_line,
                                body_line: branch.false_body_line,
                                body_pc: branch.false_body_pc,
                                branch_pc: branch.pc,
                            });
                        }
                    }
                }
            }
        }

        result
    }

    /// Get uncovered branches from ALL contracts (for when target contract has no branches)
    /// This is useful when the target is a test harness (CryticTester) that doesn't have its own branches
    pub fn all_uncovered_branches_with_info(&self) -> Vec<UncoveredBranchInfo> {
        let covered = self.covered.read();
        let mut result = Vec::new();

        for (contract_name, contract_data) in &self.manifest.contracts {
            if let Some(&contract_idx) = self.contract_to_idx.get(contract_name) {
                for branch in &contract_data.branches {
                    let function = branch.function.clone().unwrap_or_default();

                    // Skip branches without function/edge info (not useful for LLM)
                    if function.is_empty() || branch.true_edge.is_none() {
                        continue;
                    }

                    // Check true edge
                    let true_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: true,
                    };
                    if !covered.contains(&true_key) {
                        if let Some(ref edge_id) = branch.true_edge {
                            result.push(UncoveredBranchInfo {
                                contract: contract_name.to_string(),
                                function: function.clone(),
                                edge_id: edge_id.clone(),
                                is_true_branch: true,
                                condition_line: branch.condition_line,
                                body_line: branch.true_body_line,
                                body_pc: branch.true_body_pc,
                                branch_pc: branch.pc,
                            });
                        }
                    }

                    // Check false edge
                    let false_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: false,
                    };
                    if !covered.contains(&false_key) {
                        if let Some(ref edge_id) = branch.false_edge {
                            result.push(UncoveredBranchInfo {
                                contract: contract_name.to_string(),
                                function: function.clone(),
                                edge_id: edge_id.clone(),
                                is_true_branch: false,
                                condition_line: branch.condition_line,
                                body_line: branch.false_body_line,
                                body_pc: branch.false_body_pc,
                                branch_pc: branch.pc,
                            });
                        }
                    }
                }
            }
        }

        result
    }

    /// Get edge ID for a branch point (without recording)
    ///
    /// Note: Handles PC offset between JUMPI (runtime) and PUSH (coverage-map.json)
    pub fn get_edge_id(&self, codehash: B256, pc: usize, taken: bool) -> Option<String> {
        let contract_idx = {
            let map = self.codehash_to_contract.read();
            *map.get(&codehash)?
        };

        let contract_name = self.idx_to_contract.get(contract_idx as usize)?;
        let contract_data = self.manifest.contracts.get(contract_name)?;

        // Try direct PC match first, then with offsets for PUSH+JUMPI patterns
        let pcs_to_try = [pc, pc.saturating_sub(3), pc.saturating_sub(2)];

        for try_pc in pcs_to_try {
            for branch in &contract_data.branches {
                if branch.pc == try_pc {
                    return if taken {
                        branch.true_edge.clone()
                    } else {
                        branch.false_edge.clone()
                    };
                }
            }
        }

        None
    }

    /// Get coverage statistics
    pub fn stats(&self) -> UnifiedCoverageStats {
        let covered = self.covered.read();

        let mut contract_stats: HashMap<String, (usize, usize)> = HashMap::new();
        let mut total_covered_edges = 0;

        for (name, contract_data) in &self.manifest.contracts {
            let contract_idx = self.contract_to_idx[name];

            let mut covered_for_contract = 0;
            let mut total_for_contract = 0;

            for branch in &contract_data.branches {
                // Only count edges that have edge IDs (matching how total_edges is computed)
                if branch.true_edge.is_some() {
                    total_for_contract += 1;
                    let true_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: true,
                    };
                    if covered.contains(&true_key) {
                        covered_for_contract += 1;
                        total_covered_edges += 1;
                    }
                }
                if branch.false_edge.is_some() {
                    total_for_contract += 1;
                    let false_key = BranchCoverageKey {
                        contract_idx,
                        pc: branch.pc as u32,
                        taken: false,
                    };
                    if covered.contains(&false_key) {
                        covered_for_contract += 1;
                        total_covered_edges += 1;
                    }
                }
            }

            contract_stats.insert(name.clone(), (covered_for_contract, total_for_contract));
        }

        UnifiedCoverageStats {
            total_edges: self.total_edges,
            covered_edges: total_covered_edges,
            coverage_pct: if self.total_edges > 0 {
                (total_covered_edges as f64 / self.total_edges as f64) * 100.0
            } else {
                0.0
            },
            contract_stats,
        }
    }

    /// Clone the covered set (for worker threads)
    pub fn clone_covered(&self) -> HashSet<BranchCoverageKey> {
        self.covered.read().clone()
    }

    /// Merge coverage from another set
    pub fn merge_covered(&self, other: &HashSet<BranchCoverageKey>) -> usize {
        let mut covered = self.covered.write();
        let before = covered.len();
        covered.extend(other.iter().cloned());
        covered.len() - before
    }

    /// Get total number of edges
    pub fn total_edges(&self) -> usize {
        self.total_edges
    }

    /// Get codehash to contract index map (for corpus analysis)
    pub fn codehash_to_contract_map(&self) -> HashMap<B256, u16> {
        self.codehash_to_contract.read().clone()
    }

    /// Get contract name for a given index
    pub fn contract_name_for_idx(&self, idx: u16) -> Option<&str> {
        self.idx_to_contract.get(idx as usize).map(|s| s.as_str())
    }

    /// Get branch PC for an edge ID
    pub fn get_branch_pc(&self, edge_id: &str) -> Option<usize> {
        if let Some(&(contract_idx, branch_idx, _)) = self.edge_id_to_branch.get(edge_id) {
            if let Some(contract_name) = self.idx_to_contract.get(contract_idx as usize) {
                if let Some(contract_data) = self.manifest.contracts.get(contract_name) {
                    if let Some(branch) = contract_data.branches.get(branch_idx) {
                        return Some(branch.pc);
                    }
                }
            }
        }
        None
    }

    /// Check if a branch direction is covered by codehash, pc, and direction
    ///
    /// This is used by the concolic solver to check if a branch target is already
    /// covered before attempting to solve for it.
    ///
    /// Note: Handles PC offset between JUMPI (runtime) and PUSH (coverage-map.json)
    pub fn is_branch_direction_covered(&self, codehash: B256, pc: usize, taken: bool) -> bool {
        // Look up contract index from codehash
        let contract_idx = match self.codehash_to_contract.read().get(&codehash) {
            Some(&idx) => idx,
            None => return false, // Unknown contract, consider not covered
        };

        // Try the same PC offset logic as record_branch:
        // The caller might pass a JUMPI PC, but coverage is recorded with PUSH PC
        let branch_lookup = if (contract_idx as usize) < self.branch_lookup.len() {
            &self.branch_lookup[contract_idx as usize]
        } else {
            return false;
        };

        let effective_pc = if branch_lookup.contains_key(&pc) {
            pc
        } else if pc >= 3 && branch_lookup.contains_key(&(pc - 3)) {
            pc - 3
        } else if pc >= 2 && branch_lookup.contains_key(&(pc - 2)) {
            pc - 2
        } else {
            pc // Use original PC even if not found - it won't match anyway
        };

        let key = BranchCoverageKey {
            contract_idx,
            pc: effective_pc as u32,
            taken,
        };

        self.covered.read().contains(&key)
    }
}

/// Unified coverage statistics
#[derive(Debug, Clone)]
pub struct UnifiedCoverageStats {
    pub total_edges: usize,
    pub covered_edges: usize,
    pub coverage_pct: f64,
    /// Contract name → (covered, total)
    pub contract_stats: HashMap<String, (usize, usize)>,
}

impl UnifiedCoverageStats {
    /// Format as human-readable string
    pub fn format(&self) -> String {
        let mut lines = vec![
            format!("Coverage: {}/{} ({:.1}%)",
                self.covered_edges, self.total_edges, self.coverage_pct)
        ];

        let mut contracts: Vec<_> = self.contract_stats.iter()
            .map(|(name, &(covered, total))| {
                let pct = if total > 0 { (covered as f64 / total as f64) * 100.0 } else { 0.0 };
                (name.clone(), covered, total, pct)
            })
            .collect();
        contracts.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));

        for (name, covered, total, pct) in contracts.iter().take(10) {
            lines.push(format!("  {}: {}/{} ({:.1}%)", name, covered, total, pct));
        }

        if contracts.len() > 10 {
            lines.push(format!("  ... and {} more", contracts.len() - 10));
        }

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_coverage_parse() {
        let json = r#"{
            "generated": "2026-01-01T00:00:00Z",
            "version": "1.0",
            "totalContracts": 1,
            "totalBranches": 2,
            "totalEdges": 4,
            "contracts": {
                "Test": {
                    "name": "Test",
                    "sourceFile": "src/Test.sol",
                    "totalEdges": 4,
                    "branches": [
                        {
                            "pc": 100,
                            "astId": 123,
                            "allAstIds": [123],
                            "offset": 50,
                            "length": 10,
                            "fileIndex": 0,
                            "conditionLine": 10,
                            "trueEdge": "transfer_B0_T",
                            "falseEdge": "transfer_B0_F",
                            "function": "transfer",
                            "block": "B0"
                        }
                    ]
                }
            }
        }"#;

        let manifest: UnifiedCoverageManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.total_contracts, 1);
        assert_eq!(manifest.total_edges, 4);

        let test_contract = manifest.contracts.get("Test").unwrap();
        assert_eq!(test_contract.branches.len(), 1);
        assert_eq!(test_contract.branches[0].true_edge, Some("transfer_B0_T".to_string()));
    }
}
