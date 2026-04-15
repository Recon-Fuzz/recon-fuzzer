//! Test types for recon-fuzzer

use alloy_primitives::{Address, I256, U256};
use evm::exec::EvmState;
use evm::types::{Tx, TxCall, TxResult};
use serde::{Deserialize, Serialize};

/// Shrinking mode - whether to focus on sequence length or value reduction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShrinkMode {
    /// Focus on reducing sequence length (default)
    #[default]
    Sequence,
    /// Focus on reducing argument values
    ValueOnly,
}

/// Context for tracking shrinking progress and mode switches
#[derive(Debug, Clone, Default)]
pub struct ShrinkContext {
    /// Current shrinking mode
    pub mode: ShrinkMode,
    /// Last sequence length (to detect if stuck)
    pub last_seq_len: usize,
    /// How many iterations the sequence length has been stuck
    pub seq_stuck_count: i32,
    /// Last value complexity (to detect if values are stuck)
    pub last_value_complexity: U256,
    /// How many iterations values have been stuck
    pub value_stuck_count: i32,
}

/// Threshold for switching modes (iterations without progress)
pub const SHRINK_MODE_SWITCH_THRESHOLD: i32 = 50;

impl ShrinkContext {
    /// Update context after a shrink iteration, potentially switching modes
    pub fn update(&mut self, new_seq_len: usize, new_value_complexity: U256) {
        match self.mode {
            ShrinkMode::Sequence => {
                if new_seq_len < self.last_seq_len {
                    // Progress! Reset stuck counter
                    self.seq_stuck_count = 0;
                } else {
                    self.seq_stuck_count += 1;
                }
                self.last_seq_len = new_seq_len;

                // Switch to ValueOnly if stuck on sequence length
                if self.seq_stuck_count >= SHRINK_MODE_SWITCH_THRESHOLD {
                    self.mode = ShrinkMode::ValueOnly;
                    self.value_stuck_count = 0;
                    self.last_value_complexity = new_value_complexity;
                }
            }
            ShrinkMode::ValueOnly => {
                if new_value_complexity < self.last_value_complexity {
                    // Progress! Reset stuck counter
                    self.value_stuck_count = 0;
                } else {
                    self.value_stuck_count += 1;
                }
                self.last_value_complexity = new_value_complexity;

                // Switch back to Sequence if stuck on values
                if self.value_stuck_count >= SHRINK_MODE_SWITCH_THRESHOLD {
                    self.mode = ShrinkMode::Sequence;
                    self.seq_stuck_count = 0;
                    self.last_seq_len = new_seq_len;
                }
            }
        }
    }
}

/// Calculate the "value complexity" of a transaction sequence
/// This is a rough measure of how much the values can be shrunk
/// Uses sum of argument magnitudes (capped to prevent overflow)
pub fn calculate_value_complexity(txs: &[Tx]) -> U256 {
    let mut complexity = U256::ZERO;
    for tx in txs {
        // Add delay complexity
        complexity = complexity.saturating_add(U256::from(tx.delay.0));
        complexity = complexity.saturating_add(U256::from(tx.delay.1));

        // Add argument complexity
        if let TxCall::SolCall { args, .. } = &tx.call {
            for arg in args {
                complexity = complexity.saturating_add(arg_complexity(arg));
            }
        }
    }
    complexity
}

/// Calculate the total delay complexity of a transaction sequence
/// Used for tie-breaking in shrink candidate selection: prefer smaller total delays
pub fn calculate_delay_complexity(txs: &[Tx]) -> u128 {
    let mut total: u128 = 0;
    for tx in txs {
        total = total.saturating_add(tx.delay.0 as u128);
        total = total.saturating_add(tx.delay.1 as u128);
    }
    total
}

/// Calculate complexity of a single argument value
fn arg_complexity(value: &alloy_dyn_abi::DynSolValue) -> U256 {
    use alloy_dyn_abi::DynSolValue;
    match value {
        DynSolValue::Uint(n, _) => *n,
        DynSolValue::Int(n, _) => {
            // Use absolute value
            if *n >= I256::ZERO {
                n.into_raw()
            } else {
                (-*n).into_raw()
            }
        }
        DynSolValue::Bool(b) => {
            if *b {
                U256::from(1)
            } else {
                U256::ZERO
            }
        }
        DynSolValue::Address(a) => U256::from_be_bytes(a.into_word().0),
        DynSolValue::Bytes(b) => U256::from(b.len()),
        DynSolValue::String(s) => U256::from(s.len()),
        DynSolValue::FixedBytes(b, size) => {
            // Count non-zero bytes
            let non_zero = b.iter().take(*size).filter(|&&x| x != 0).count();
            U256::from(non_zero)
        }
        DynSolValue::Array(elements)
        | DynSolValue::FixedArray(elements)
        | DynSolValue::Tuple(elements) => elements
            .iter()
            .map(arg_complexity)
            .fold(U256::ZERO, |a, b| a.saturating_add(b)),
        _ => U256::ZERO,
    }
}

// Note: TestMode enum is now in crate::config (re-exported from config crate)

/// State of an Echidna test
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestState {
    /// Test is still being fuzzed
    Open,

    /// Test failed, shrinking in progress (tracking shrink attempts)
    Large(i32),

    /// Test passed (no counterexample found within limit)
    Passed,

    /// Test failed and shrinking complete
    Solved,

    /// Test execution failed with an error
    Failed(String),
}

impl TestState {
    pub fn is_open(&self) -> bool {
        matches!(self, TestState::Open)
    }

    pub fn is_solved(&self) -> bool {
        matches!(self, TestState::Solved)
    }

    pub fn is_shrinking(&self) -> bool {
        matches!(self, TestState::Large(_))
    }

    pub fn did_fail(&self) -> bool {
        matches!(self, TestState::Large(_) | TestState::Solved)
    }
}

/// Test value (for property and optimization tests)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestValue {
    /// Boolean result from property test
    BoolValue(bool),

    /// Integer value from optimization test
    IntValue(I256),

    /// No value
    NoValue,
}

impl TestValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            TestValue::BoolValue(b) => Some(*b),
            _ => None,
        }
    }
}

/// Type of test
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestType {
    /// Property test: function starting with "echidna_" that returns bool
    PropertyTest { name: String, addr: Address },

    /// Assertion test: function containing assert() calls
    AssertionTest {
        /// If true, auto-detected from bytecode analysis
        auto_detect: bool,
        /// Function signature
        signature: (String, Vec<String>),
        addr: Address,
    },

    /// Optimization test: maximizing a return value
    OptimizationTest { name: String, addr: Address },

    /// Call test: checks a predicate on VM state after each call
    /// Used for AssertionFailed(..), SelfDestruct checks, etc.
    CallTest {
        name: String,
        /// Type of call test predicate
        predicate: CallTestPredicate,
    },

    /// Coverage exploration (no specific test)
    Exploration,
}

/// Predicate types for CallTest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallTestPredicate {
    /// Check for AssertionFailed events
    AssertionFailed,
    /// Check target contract is not self-destructed
    SelfDestructTarget(Address),
    /// Check no contract is self-destructed
    AnySelfDestruct,
}

impl TestType {
    pub fn name(&self) -> &str {
        match self {
            TestType::PropertyTest { name, .. } => name,
            TestType::AssertionTest { signature, .. } => &signature.0,
            TestType::OptimizationTest { name, .. } => name,
            TestType::CallTest { name, .. } => name,
            TestType::Exploration => "exploration",
        }
    }

    pub fn is_property(&self) -> bool {
        matches!(self, TestType::PropertyTest { .. })
    }

    pub fn is_assertion(&self) -> bool {
        matches!(self, TestType::AssertionTest { .. })
    }

    pub fn is_call_test(&self) -> bool {
        matches!(self, TestType::CallTest { .. })
    }
}

/// An Echidna test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchidnaTest {
    /// Current state
    pub state: TestState,

    /// Type of test
    pub test_type: TestType,

    /// Value (for optimization tests)
    pub value: TestValue,

    /// Transaction sequence that triggers the failure
    pub reproducer: Vec<Tx>,

    /// Result of the last execution
    pub result: TxResult,

    /// Worker ID that found/is shrinking this test
    pub worker_id: Option<usize>,

    /// VM state before the failure sequence (for shrinking)
    #[serde(skip)]
    pub vm: Option<EvmState>,

    /// Shrinking context for tracking mode and stuck detection
    #[serde(skip)]
    pub shrink_context: ShrinkContext,
}

impl EchidnaTest {
    /// Create a new open property test
    pub fn property(name: impl Into<String>, addr: Address) -> Self {
        Self {
            state: TestState::Open,
            test_type: TestType::PropertyTest {
                name: name.into(),
                addr,
            },
            value: TestValue::NoValue,
            reproducer: Vec::new(),
            result: TxResult::Stop,
            worker_id: None,
            vm: None,
            shrink_context: ShrinkContext::default(),
        }
    }

    /// Create a new assertion test
    pub fn assertion(signature: (String, Vec<String>), addr: Address, auto_detect: bool) -> Self {
        Self {
            state: TestState::Open,
            test_type: TestType::AssertionTest {
                auto_detect,
                signature,
                addr,
            },
            value: TestValue::NoValue,
            reproducer: Vec::new(),
            result: TxResult::Stop,
            worker_id: None,
            vm: None,
            shrink_context: ShrinkContext::default(),
        }
    }

    /// Check if test is still open
    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    /// Check if test needs shrinking
    pub fn is_shrinkable(&self) -> bool {
        self.state.is_shrinking()
    }

    /// Mark test as failed with reproducer
    pub fn fail(&mut self, reproducer: Vec<Tx>, result: TxResult, worker_id: usize) {
        self.state = TestState::Large(0);
        self.reproducer = reproducer;
        self.result = result;
        self.worker_id = Some(worker_id);
    }

    /// Mark test as passed
    pub fn pass(&mut self) {
        self.state = TestState::Passed;
    }

    /// Increment shrink counter
    pub fn shrink_attempt(&mut self) {
        if let TestState::Large(n) = self.state {
            self.state = TestState::Large(n + 1);
        }
    }

    /// Mark shrinking as complete
    pub fn shrink_complete(&mut self) {
        self.state = TestState::Solved;
    }
}

/// Check if all tests have completed
pub fn is_successful(tests: &[EchidnaTest]) -> bool {
    tests
        .iter()
        .all(|t| matches!(t.state, TestState::Passed))
}

/// Create tests from a contract based on test mode
pub fn create_tests(
    mode: &config::solidity::TestMode,
    contract_addr: Address,
    echidna_tests: &[&alloy_json_abi::Function],
    fuzzable_sigs: &[(String, Vec<String>)],
) -> Vec<EchidnaTest> {
    use config::solidity::TestMode;
    match mode {
        TestMode::Exploration => {
            vec![EchidnaTest {
                state: TestState::Open,
                test_type: TestType::Exploration,
                value: TestValue::NoValue,
                reproducer: vec![],
                result: TxResult::Stop,
                worker_id: None,
                vm: None,
                shrink_context: ShrinkContext::default(),
            }]
        }

        TestMode::Property => echidna_tests
            .iter()
            .map(|f| EchidnaTest::property(&f.name, contract_addr))
            .collect(),

        TestMode::Optimization => echidna_tests
            .iter()
            .map(|f| EchidnaTest {
                state: TestState::Open,
                test_type: TestType::OptimizationTest {
                    name: f.name.clone(),
                    addr: contract_addr,
                },
                value: TestValue::IntValue(I256::MIN),
                reproducer: vec![],
                result: TxResult::Stop,
                worker_id: None,
                vm: None,
                shrink_context: ShrinkContext::default(),
            })
            .collect(),

        TestMode::Assertion => {
            // creates AssertionTest for each fuzzable function PLUS
            // a CallTest for "AssertionFailed(string)" events
            let mut tests: Vec<EchidnaTest> = fuzzable_sigs
                .iter()
                .filter(|(name, _)| !name.is_empty()) // Filter out fallback
                .map(|(name, params)| {
                    EchidnaTest::assertion((name.clone(), params.clone()), contract_addr, false)
                })
                .collect();

            // Add the CallTest for AssertionFailed events 
            tests.push(EchidnaTest {
                state: TestState::Open,
                test_type: TestType::CallTest {
                    name: "AssertionFailed(..)".to_string(),
                    predicate: CallTestPredicate::AssertionFailed,
                },
                value: TestValue::NoValue,
                reproducer: vec![],
                result: TxResult::Stop,
                worker_id: None,
                vm: None,
                shrink_context: ShrinkContext::default(),
            });

            tests
        }
    }
}
