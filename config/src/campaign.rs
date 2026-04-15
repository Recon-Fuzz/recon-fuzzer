//! Campaign configuration
//!

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Campaign configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CampaignConf {
    /// Maximum number of function calls to execute
    pub test_limit: usize,

    /// Stop immediately if any test fails
    pub stop_on_fail: bool,

    /// Number of calls per sequence before resetting
    pub seq_len: usize,

    /// Maximum shrink attempts
    pub shrink_limit: usize,

    /// Random seed
    pub seed: Option<u64>,

    /// Dictionary usage frequency (0.0-1.0)
    pub dict_freq: f32,

    /// Directory for corpus storage
    pub corpus_dir: Option<PathBuf>,

    /// Directory for exporting corpus in Echidna-compatible format
    pub export_dir: Option<PathBuf>,

    /// Directory for coverage reports
    pub coverage_dir: Option<PathBuf>,

    /// Number of workers
    pub workers: u8,

    /// Timeout in seconds
    pub timeout: Option<u64>,

    // =========================================================================
    // Optimization Mode Configuration
    // =========================================================================

    /// Enable intermediate state checkpointing for optimization tests
    #[serde(default = "default_checkpoint_enable")]
    pub checkpoint_enable: bool,

    /// Number of checkpoints to keep
    #[serde(default = "default_checkpoint_count")]
    pub checkpoint_count: usize,

    /// Probability to start from a checkpoint instead of initial state (0.0-1.0)
    #[serde(default = "default_checkpoint_probability")]
    pub checkpoint_probability: f32,

    /// Enable adaptive check interval for optimization tests
    #[serde(default = "default_adaptive_check")]
    pub adaptive_check: bool,

    /// Hot function weight multiplier for optimization
    #[serde(default = "default_hot_function_weight")]
    pub hot_function_weight: usize,

    /// Path to a file with external values to seed
    pub seed_file: Option<PathBuf>,

    // =========================================================================
    // Performance Configuration
    // =========================================================================

    /// Enable LCOV coverage report writing during fuzzing
    /// Disabled by default for performance (can be enabled with --lcov)
    #[serde(default)]
    pub lcov_enable: bool,

    /// LCOV write interval in seconds (only used if lcov_enable is true)
    #[serde(default = "default_lcov_interval")]
    pub lcov_interval: u64,

    /// Coverage tracking mode: "full" (every opcode) or "branch" (only JUMPI/JUMPDEST)
    /// Branch mode is faster but tracks less granular coverage
    #[serde(default = "default_coverage_mode")]
    pub coverage_mode: String,

    // =========================================================================
    // Shortcuts Hoisting Configuration (Experimental)
    // =========================================================================

    /// Enable shortcuts hoisting - run shortcut_* functions at startup and capture
    /// external calls to bootstrap the corpus
    #[serde(default)]
    pub shortcuts_enable: bool,

    /// Shrink-only mode: skip fuzzing, load existing reproducers, and shrink them
    #[serde(default)]
    pub shrink_only: bool,
}

// Default functions
fn default_checkpoint_enable() -> bool { true }
fn default_checkpoint_count() -> usize { 10 }
fn default_checkpoint_probability() -> f32 { 0.1 }
fn default_adaptive_check() -> bool { true }
fn default_hot_function_weight() -> usize { 3 }
fn default_lcov_interval() -> u64 { 30 }
fn default_coverage_mode() -> String { "full".to_string() }

impl Default for CampaignConf {
    fn default() -> Self {
        Self {
            test_limit: 50_000,
            stop_on_fail: false,
            seq_len: 100,
            shrink_limit: 5_000,
            seed: None,
            dict_freq: 0.40, // Echidna default: dictFreq ..!= 0.40
            corpus_dir: None,
            export_dir: None,
            coverage_dir: None,
            workers: std::cmp::min(4, num_cpus()) as u8, // cap at 4 for deeper exploration
            timeout: None,
            // Optimization
            checkpoint_enable: default_checkpoint_enable(),
            checkpoint_count: default_checkpoint_count(),
            checkpoint_probability: default_checkpoint_probability(),
            adaptive_check: default_adaptive_check(),
            hot_function_weight: default_hot_function_weight(),
            seed_file: None,
            // Performance
            lcov_enable: false,
            lcov_interval: default_lcov_interval(),
            coverage_mode: default_coverage_mode(),
            // Shortcuts hoisting
            shortcuts_enable: false,
            shrink_only: false,
        }
    }
}

/// Get number of CPUs
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

/// Default constants
pub const DEFAULT_TEST_LIMIT: usize = 50_000;
pub const DEFAULT_SEQ_LEN: usize = 100;
pub const DEFAULT_SHRINK_LIMIT: usize = 5_000;
