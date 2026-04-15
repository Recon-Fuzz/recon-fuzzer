//! Coverage tracking module
//!
//! Provides PC-level coverage tracking with inspectors for runtime collection during EVM execution.

mod inspector;

// Re-export all public items from inspector
pub use inspector::{
    build_codehash_map, compute_metadata_hash, coverage_points, coverage_stats, num_codehashes,
    lookup_codehash, CombinedInspector, CoverageInspector, CoverageMap, CoverageMode,
    DeploymentPcCounter, MetadataToCodehash, TracingWithCheatcodes, TOUCHED_INITIAL_CAPACITY,
};

use alloy_primitives::B256;

/// Transaction result for coverage tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxResult {
    Success,
    Revert,
    Halt,
}

/// Merge deployment coverage from DeploymentPcCounter into init_coverage map.
/// Used after deploy_contract / deploy_contract_at.
/// Matches main fuzzer: depth_bit=1, result_bit=1 for all deployment PCs.
pub fn merge_deployment_coverage(
    coverage: &mut CoverageMap,
    touched: &[(B256, usize, usize)],
) {
    for &(codehash, pc, _depth) in touched {
        let entry = coverage
            .entry(codehash)
            .or_default()
            .entry(pc)
            .or_insert((0u64, 0u64));
        entry.0 |= 1; // depth bit
        entry.1 |= 1; // result bit (success for deployment)
    }
}

/// Merge setUp coverage from TracingWithCheatcodes pcs_hit into init_coverage.
/// Uses keccak256(bytecode) for codehash (NOT metadata-based).
/// Matches cli/main.rs:1145-1150: depth_bit=1, result_bit=1.
pub fn merge_setup_coverage(
    coverage: &mut CoverageMap,
    pcs_hit: &[(B256, usize)],
) {
    for &(codehash, pc) in pcs_hit {
        let entry = coverage
            .entry(codehash)
            .or_default()
            .entry(pc)
            .or_insert((0u64, 0u64));
        entry.0 |= 1; // depth bit
        entry.1 |= 1; // result bit
    }
}

/// Check if touched PCs produce new coverage and merge into runtime coverage map.
/// Returns true if any new coverage was found.
/// Used by exec_tx_check_new_cov during fuzzing.
///
/// Coverage bits encode:
/// - depth_bits: 1 << min(call_depth, 63)
/// - result_bits: 1 for success, 2 for revert, 4 for halt
/// Check if touched PCs produce new coverage and merge into runtime coverage map.
/// Returns true if any new coverage was found.
/// Used by exec_tx_check_new_cov during fuzzing.
///
/// Result bit is ONLY applied to the LAST PC touched.
/// This is where execution actually ended (success, revert, etc.)
///
/// Coverage bits encode:
/// - depth_bits: 1 << min(call_depth, 63)
/// - result_bits: 1 for success, 2 for revert, 4 for halt (only on last PC)
pub fn check_and_merge_coverage(
    coverage: &mut CoverageMap,
    touched: &[(B256, usize, usize)],
    tx_result: TxResult,
) -> bool {
    let result_bit: u64 = match tx_result {
        TxResult::Success => 1,
        TxResult::Revert => 2,
        TxResult::Halt => 4,
    };

    let mut has_new = false;
    let len = touched.len();

    for (idx, &(codehash, pc, depth)) in touched.iter().enumerate() {
        let depth_bit = if depth < 64 { 1u64 << depth } else { 1u64 << 63 };

        // Result bit ONLY checked/applied for last PC 
        let is_last_pc = idx == len - 1;

        let pcs = coverage.entry(codehash).or_default();
        let entry = pcs.entry(pc).or_insert((0u64, 0u64));

        let new_depth = (entry.0 & depth_bit) == 0;
        let new_result = is_last_pc && (entry.1 & result_bit) == 0;

        if new_depth || new_result {
            has_new = true;
        }

        // Always update depth bit for all PCs
        entry.0 |= depth_bit;
        // Result bit ONLY for last PC
        if is_last_pc {
            entry.1 |= result_bit;
        }
    }

    has_new
}
