//! Observable and Commandable traits for web UI integration
//!
//! These traits define the interface between the fuzzer core and the web UI.
//! Implement these traits for your fuzzer state to enable web UI support.

use crate::protocol::*;
use alloy_primitives::U256;

/// Trait for state that can be observed by the web UI
///
/// Implementations should provide read-only access to fuzzer state
/// in a format suitable for the web UI.
pub trait Observable: Send + Sync + 'static {
    /// Get the initial payload sent when a client connects
    fn get_init_payload(&self) -> InitPayload;

    /// Get the current coverage snapshot
    fn get_coverage_snapshot(&self) -> CoverageSnapshot;

    /// Get coverage changes since a previous snapshot
    fn get_coverage_delta(&self, since: &CoverageSnapshot) -> CoverageDelta;

    /// Get current worker states
    fn get_worker_snapshots(&self) -> Vec<WorkerSnapshot>;

    /// Get all corpus entries
    fn get_corpus_entries(&self) -> Vec<CorpusEntryPayload>;

    /// Get corpus size (lightweight - doesn't build full payloads)
    fn get_corpus_size(&self) -> usize {
        // Default implementation uses get_corpus_entries, but implementors
        // should override this for efficiency
        self.get_corpus_entries().len()
    }

    /// Get all test states
    fn get_test_states(&self) -> Vec<TestInfo>;

    /// Get the top N revert hotspots (locations that frequently revert)
    fn get_revert_hotspots(&self, top_n: usize) -> Vec<RevertHotspot>;

    /// Get basic statistics: (total_calls, total_sequences, total_gas, elapsed_ms)
    fn get_stats(&self) -> (u64, u64, u64, u64);

    /// Get contract summaries (lightweight, for listing)
    fn get_contract_summaries(&self) -> Vec<ContractSummary>;

    /// Get full contract details by name (lazy load)
    fn get_contract_details(&self, name: &str) -> Option<ContractInfo>;

    /// Get source file summaries (lightweight, for listing)
    fn get_source_file_summaries(&self) -> Vec<SourceFileSummary>;

    /// Get source file content by path (lazy load)
    fn get_source_file_content(&self, path: &str) -> Option<SourceFile>;

    /// Get current campaign state
    fn get_campaign_state(&self) -> CampaignState;

    /// Get source-level line coverage (LCOV-style)
    /// Computed from PC coverage using source maps
    fn get_source_line_coverage(&self) -> Vec<SourceLineCoverage>;

    /// Get PC to source mappings for all contracts
    /// Used for bytecode -> source navigation in the UI
    fn get_pc_mappings(&self) -> Vec<ContractPcMapping>;
}

/// Trait for state that can receive commands from the web UI
///
/// Implementations should handle commands from the interactive worker
/// and other UI-triggered actions.
pub trait Commandable: Send + Sync + 'static {
    /// Inject values into the fuzzer dictionary
    ///
    /// # Arguments
    /// * `values` - U256 values to add to the dictionary
    /// * `broadcast` - If true, add to all workers. If false, only interactive worker.
    fn inject_dictionary(&self, values: Vec<U256>, broadcast: bool) -> Result<(), String>;

    /// Inject a transaction sequence into the corpus
    fn inject_sequence(&self, sequence: Vec<TxRequest>) -> Result<(), String>;

    /// Clamp a function argument to a specific value (interactive worker only)
    ///
    /// # Arguments
    /// * `function` - Function name or signature
    /// * `param_idx` - Parameter index (0-based)
    /// * `value` - JSON-encoded value
    fn clamp_argument(
        &self,
        function: &str,
        param_idx: usize,
        value: &str,
    ) -> Result<(), String>;

    /// Remove a clamp from a function argument
    fn unclamp_argument(&self, function: &str, param_idx: usize) -> Result<(), String>;

    /// Clear all argument clamps
    fn clear_clamps(&self) -> Result<(), String>;

    /// Set target functions for the interactive worker
    ///
    /// # Arguments
    /// * `functions` - List of function names. Empty means all functions.
    fn set_target_functions(&self, functions: Vec<String>) -> Result<(), String>;

    /// Inject fuzz transaction templates with wildcards
    ///
    /// Templates use `?` for wildcard (fuzzed) and concrete values for fixed.
    /// Example: "f(1,?,?) ; g(?,2,5)" - f with first arg fixed to 1, g with 2nd and 3rd fixed.
    ///
    /// # Arguments
    /// * `template` - Template string like "f(1,?,?) ; g(?,2,5)"
    /// * `priority` - Higher priority templates are selected more often
    fn inject_fuzz_transactions(&self, template: &str, priority: usize) -> Result<(), String>;

    /// Clear all fuzz transaction templates
    fn clear_fuzz_templates(&self) -> Result<(), String>;

    /// Replay a transaction sequence and return execution traces
    ///
    /// # Arguments
    /// * `sequence_json` - Raw JSON serialized sequence (same format as corpus files)
    ///
    /// # Returns
    /// Vector of trace results for each transaction
    fn replay_sequence(&self, sequence_json: &str) -> Result<Vec<TxTraceResult>, String>;
}

/// Combined trait for both observable and commandable state
pub trait WebState: Observable + Commandable {}

impl<T: Observable + Commandable> WebState for T {}

/// A wrapper that provides a no-op implementation of Commandable
/// Useful when you only want to observe state without commands
pub struct ReadOnlyState<T: Observable> {
    inner: T,
}

impl<T: Observable> ReadOnlyState<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: Observable> Observable for ReadOnlyState<T> {
    fn get_init_payload(&self) -> InitPayload {
        self.inner.get_init_payload()
    }

    fn get_coverage_snapshot(&self) -> CoverageSnapshot {
        self.inner.get_coverage_snapshot()
    }

    fn get_coverage_delta(&self, since: &CoverageSnapshot) -> CoverageDelta {
        self.inner.get_coverage_delta(since)
    }

    fn get_worker_snapshots(&self) -> Vec<WorkerSnapshot> {
        self.inner.get_worker_snapshots()
    }

    fn get_corpus_entries(&self) -> Vec<CorpusEntryPayload> {
        self.inner.get_corpus_entries()
    }

    fn get_corpus_size(&self) -> usize {
        self.inner.get_corpus_size()
    }

    fn get_test_states(&self) -> Vec<TestInfo> {
        self.inner.get_test_states()
    }

    fn get_revert_hotspots(&self, top_n: usize) -> Vec<RevertHotspot> {
        self.inner.get_revert_hotspots(top_n)
    }

    fn get_stats(&self) -> (u64, u64, u64, u64) {
        self.inner.get_stats()
    }

    fn get_contract_summaries(&self) -> Vec<ContractSummary> {
        self.inner.get_contract_summaries()
    }

    fn get_contract_details(&self, name: &str) -> Option<ContractInfo> {
        self.inner.get_contract_details(name)
    }

    fn get_source_file_summaries(&self) -> Vec<SourceFileSummary> {
        self.inner.get_source_file_summaries()
    }

    fn get_source_file_content(&self, path: &str) -> Option<SourceFile> {
        self.inner.get_source_file_content(path)
    }

    fn get_campaign_state(&self) -> CampaignState {
        self.inner.get_campaign_state()
    }

    fn get_source_line_coverage(&self) -> Vec<SourceLineCoverage> {
        self.inner.get_source_line_coverage()
    }

    fn get_pc_mappings(&self) -> Vec<ContractPcMapping> {
        self.inner.get_pc_mappings()
    }
}

impl<T: Observable> Commandable for ReadOnlyState<T> {
    fn inject_dictionary(&self, _values: Vec<U256>, _broadcast: bool) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn inject_sequence(&self, _sequence: Vec<TxRequest>) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn clamp_argument(
        &self,
        _function: &str,
        _param_idx: usize,
        _value: &str,
    ) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn unclamp_argument(&self, _function: &str, _param_idx: usize) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn clear_clamps(&self) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn set_target_functions(&self, _functions: Vec<String>) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn inject_fuzz_transactions(&self, _template: &str, _priority: usize) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn clear_fuzz_templates(&self) -> Result<(), String> {
        Err("Read-only mode: commands not supported".to_string())
    }

    fn replay_sequence(&self, _sequence_json: &str) -> Result<Vec<TxTraceResult>, String> {
        Err("Read-only mode: commands not supported".to_string())
    }
}
