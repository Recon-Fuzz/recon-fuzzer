//! Coverage tracking module
//!
//! Provides PC-level, CFG-based branch, and source-level coverage tracking.
//! Contains inspectors for runtime coverage collection during EVM execution.

mod inspector;
mod source;
mod unified;

// Re-export all public items from inspector
pub use inspector::{
    build_codehash_map, compute_metadata_hash, coverage_points, coverage_stats, num_codehashes,
    lookup_codehash, CombinedInspector, CoverageInspector, CoverageMap, CoverageMode, DeploymentPcCounter,
    MetadataToCodehash, TracingWithCheatcodes, TOUCHED_INITIAL_CAPACITY,
};

// Re-export all public items from unified (CFG-based coverage)
pub use unified::{
    BranchCoverageKey, UncoveredBranchInfo, UnifiedBranch, UnifiedContractCoverage,
    UnifiedCoverage, UnifiedCoverageManifest, UnifiedCoverageStats,
};

// Re-export all public items from source (source-level LCOV and HTML reports)
pub use source::{
    build_codehash_to_source_info, build_init_codehash_to_source_info, build_pc_to_index,
    generate_source_coverage, generate_source_coverage_covered_only, generate_source_coverage_multi,
    load_contract_source_info, load_source_info, parse_source_map, save_html_report, save_lcov_report,
    CodehashToSourceInfo, ContractSourceInfo, FileCoverage, SourceCoverage, SourceFile, SourceMap,
    SrcLocation,
};
