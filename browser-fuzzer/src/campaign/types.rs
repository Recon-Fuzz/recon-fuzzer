//! Status and data types for coordinator <-> worker protocol
//!
//! Extracted from campaign.rs lines 60-239.

use serde::{Deserialize, Serialize};

use super::config::EConfig;
use super::testing::{EchidnaTest, TestState, TestValue};
use super::transaction::Tx;

// =========================================================================
// Fuzzer status (returned to JS)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignStatus {
    pub call_count: u64,
    pub corpus_size: usize,
    pub coverage_points: usize,
    pub tests: Vec<TestStatus>,
    /// Event log messages (Echidna-style progress messages)
    pub events: Vec<String>,
    pub running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStatus {
    pub name: String,
    pub state: String,
    pub value: Option<String>,
    pub reproducer_len: usize,
}

// =========================================================================
// Multi-worker data types (coordinator <-> worker protocol)
// =========================================================================

/// Serializable EVM state for cloning to workers.
/// Contains all account state + coverage from deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedState {
    /// Serialized CacheDB accounts: addr -> (balance_hex, nonce, code_hex, storage)
    pub accounts: Vec<ExportedAccount>,
    pub block_number: u64,
    pub timestamp: u64,
    /// Coverage map from deployment
    pub coverage: Vec<CoverageEntry>,
    /// Contract info needed by workers
    pub contract_name: String,
    pub contract_addr: String,
    pub fuzzable_funcs_json: String,
    pub config: EConfig,
    /// Tests created from setup_tests
    pub tests_json: String,
    /// ABI JSON for decoder setup
    pub abi_json: String,
    /// Metadata-to-codehash map (for coverage codehash resolution)
    pub codehash_map: Vec<CodehashMapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedAccount {
    pub address: String,
    pub balance: String,
    pub nonce: u64,
    pub code: String, // hex-encoded bytecode
    pub storage: Vec<(String, String)>, // (slot_hex, value_hex)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub codehash: String,
    pub pc: usize,
    pub depth_bits: u64,
    pub result_bits: u64,
}

/// Serializable codehash map entry for sending metadata-to-codehash map to workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodehashMapEntry {
    pub metadata_hash: String,
    pub bytecode_len: usize,
    pub compile_codehash: String,
}

/// Delta sent from worker to coordinator after a batch.
/// Matches main fuzzer's WorkerEnv pattern of sending deltas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerDelta {
    pub worker_id: usize,
    /// New corpus entries found during this batch
    pub new_corpus: Vec<Vec<Tx>>,
    /// Coverage deltas: new (codehash, pc, depth_bits, result_bits) found
    pub coverage_delta: Vec<CoverageEntry>,
    /// Test updates: (test_idx, new_state, new_value, new_reproducer)
    pub test_updates: Vec<TestUpdate>,
    /// Calls executed in this batch
    pub call_count_delta: u64,
    /// New dictionary values found
    pub dict_values: Vec<String>,
    /// Events generated during this batch (for display)
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestUpdate {
    pub test_idx: usize,
    /// State as TestStatus-format string: "open", "passed", "FAILED", "shrinking(N)", "error: msg"
    pub state: String,
    pub value: TestValue,
    pub reproducer: Vec<Tx>,
}

/// State sync from coordinator to workers.
/// Matches main fuzzer's periodic broadcast pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSync {
    /// New corpus entries since last sync
    pub new_corpus: Vec<Vec<Tx>>,
    /// Total coverage points (for display)
    pub coverage_points: usize,
    /// Coverage delta from other workers (merged by coordinator)
    pub coverage_delta: Vec<CoverageEntry>,
    /// Current test states
    pub tests: Vec<TestSyncEntry>,
    /// Total calls across all workers
    pub total_calls: u64,
    /// New dictionary values from other workers
    pub dict_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSyncEntry {
    pub test_idx: usize,
    /// State as TestStatus-format string
    pub state: String,
    pub value: TestValue,
    pub reproducer: Vec<Tx>,
}

// =========================================================================
// Test state <-> string conversion helpers (TestStatus format)
// =========================================================================

pub fn test_state_to_status_string(state: &TestState) -> String {
    match state {
        TestState::Open => "open".to_string(),
        TestState::Large(n) => format!("shrinking({n})"),
        TestState::Passed => "passed".to_string(),
        TestState::Solved => "FAILED".to_string(),
        TestState::Failed(e) => format!("error: {e}"),
    }
}

pub fn parse_status_string_to_state(s: &str) -> TestState {
    match s {
        "open" => TestState::Open,
        "passed" => TestState::Passed,
        "FAILED" => TestState::Solved,
        s if s.starts_with("shrinking(") => {
            let n = s.trim_start_matches("shrinking(")
                .trim_end_matches(')')
                .parse()
                .unwrap_or(0);
            TestState::Large(n)
        }
        s if s.starts_with("error: ") => {
            TestState::Failed(s.trim_start_matches("error: ").to_string())
        }
        _ => TestState::Open,
    }
}

impl From<&EchidnaTest> for TestStatus {
    fn from(t: &EchidnaTest) -> Self {
        TestStatus {
            name: t.test_type.name().to_string(),
            state: match &t.state {
                TestState::Open => "open".to_string(),
                TestState::Large(n) => format!("shrinking({n})"),
                TestState::Passed => "passed".to_string(),
                TestState::Solved => "FAILED".to_string(),
                TestState::Failed(e) => format!("error: {e}"),
            },
            value: match &t.value {
                TestValue::IntValue(v) => Some(format!("{v}")),
                TestValue::BoolValue(b) => Some(format!("{b}")),
                TestValue::NoValue => None,
            },
            reproducer_len: t.reproducer.len(),
        }
    }
}
