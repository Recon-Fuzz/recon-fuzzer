//! Test types for browser-fuzzer
//!
//! Port of campaign/src/testing/types.rs adapted for browser-fuzzer.
//! Supports Property, Assertion, Optimization, and Exploration test modes.

use alloy_primitives::{Address, I256, U256};
use serde::{Deserialize, Serialize};

use crate::campaign::transaction::Tx;

// =========================================================================
// Shrink context (from campaign/src/testing/types.rs)
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShrinkMode {
    #[default]
    Sequence,
    ValueOnly,
}

#[derive(Debug, Clone, Default)]
pub struct ShrinkContext {
    pub mode: ShrinkMode,
    pub last_seq_len: usize,
    pub seq_stuck_count: i32,
    pub last_value_complexity: U256,
    pub value_stuck_count: i32,
}

pub const SHRINK_MODE_SWITCH_THRESHOLD: i32 = 50;

impl ShrinkContext {
    pub fn update(&mut self, new_seq_len: usize, new_value_complexity: U256) {
        match self.mode {
            ShrinkMode::Sequence => {
                if new_seq_len < self.last_seq_len {
                    self.seq_stuck_count = 0;
                } else {
                    self.seq_stuck_count += 1;
                }
                self.last_seq_len = new_seq_len;
                if self.seq_stuck_count >= SHRINK_MODE_SWITCH_THRESHOLD {
                    self.mode = ShrinkMode::ValueOnly;
                    self.value_stuck_count = 0;
                    self.last_value_complexity = new_value_complexity;
                }
            }
            ShrinkMode::ValueOnly => {
                if new_value_complexity < self.last_value_complexity {
                    self.value_stuck_count = 0;
                } else {
                    self.value_stuck_count += 1;
                }
                self.last_value_complexity = new_value_complexity;
                if self.value_stuck_count >= SHRINK_MODE_SWITCH_THRESHOLD {
                    self.mode = ShrinkMode::Sequence;
                    self.seq_stuck_count = 0;
                    self.last_seq_len = new_seq_len;
                }
            }
        }
    }
}

// =========================================================================
// Value complexity (from campaign/src/testing/types.rs)
// =========================================================================

pub fn calculate_value_complexity(txs: &[Tx]) -> U256 {
    let mut complexity = U256::ZERO;
    for tx in txs {
        complexity = complexity.saturating_add(U256::from(tx.delay.0));
        complexity = complexity.saturating_add(U256::from(tx.delay.1));
        // Add calldata length as a proxy for argument complexity
        complexity = complexity.saturating_add(U256::from(tx.calldata.len()));
        complexity = complexity.saturating_add(tx.value);
    }
    complexity
}

// =========================================================================
// Test types (from campaign/src/testing/types.rs)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestState {
    Open,
    Large(i32),
    Passed,
    Solved,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestValue {
    BoolValue(bool),
    IntValue(I256),
    NoValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestType {
    PropertyTest { name: String, addr: Address },
    AssertionTest {
        signature: (String, Vec<String>),
        addr: Address,
    },
    OptimizationTest { name: String, addr: Address },
    CallTest {
        name: String,
        predicate: CallTestPredicate,
    },
    Exploration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallTestPredicate {
    AssertionFailed,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchidnaTest {
    pub state: TestState,
    pub test_type: TestType,
    pub value: TestValue,
    pub reproducer: Vec<Tx>,
    pub worker_id: Option<usize>,
    #[serde(skip)]
    pub shrink_context: ShrinkContext,
}

impl EchidnaTest {
    pub fn property(name: impl Into<String>, addr: Address) -> Self {
        Self {
            state: TestState::Open,
            test_type: TestType::PropertyTest {
                name: name.into(),
                addr,
            },
            value: TestValue::NoValue,
            reproducer: Vec::new(),
            worker_id: None,
            shrink_context: ShrinkContext::default(),
        }
    }

    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    pub fn is_shrinkable(&self) -> bool {
        self.state.is_shrinking()
    }
}

/// Test mode selector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestMode {
    Property,
    Assertion,
    Optimization,
    Exploration,
}

/// Create tests from ABI based on test mode
pub fn create_tests(
    mode: TestMode,
    contract_addr: Address,
    echidna_fns: &[&alloy_json_abi::Function],
    fuzzable_sigs: &[(String, Vec<String>)],
) -> Vec<EchidnaTest> {
    match mode {
        TestMode::Exploration => {
            vec![EchidnaTest {
                state: TestState::Open,
                test_type: TestType::Exploration,
                value: TestValue::NoValue,
                reproducer: vec![],
                worker_id: None,
                shrink_context: ShrinkContext::default(),
            }]
        }
        TestMode::Property => echidna_fns
            .iter()
            .map(|f| EchidnaTest::property(&f.name, contract_addr))
            .collect(),
        TestMode::Optimization => echidna_fns
            .iter()
            .map(|f| EchidnaTest {
                state: TestState::Open,
                test_type: TestType::OptimizationTest {
                    name: f.name.clone(),
                    addr: contract_addr,
                },
                value: TestValue::IntValue(I256::MIN),
                reproducer: vec![],
                worker_id: None,
                shrink_context: ShrinkContext::default(),
            })
            .collect(),
        TestMode::Assertion => {
            let mut tests: Vec<EchidnaTest> = fuzzable_sigs
                .iter()
                .filter(|(name, _)| !name.is_empty())
                .map(|(name, params)| EchidnaTest {
                    state: TestState::Open,
                    test_type: TestType::AssertionTest {
                        signature: (name.clone(), params.clone()),
                        addr: contract_addr,
                    },
                    value: TestValue::NoValue,
                    reproducer: vec![],
                    worker_id: None,
                    shrink_context: ShrinkContext::default(),
                })
                .collect();

            // Add CallTest for AssertionFailed events
            tests.push(EchidnaTest {
                state: TestState::Open,
                test_type: TestType::CallTest {
                    name: "AssertionFailed(..)".to_string(),
                    predicate: CallTestPredicate::AssertionFailed,
                },
                value: TestValue::NoValue,
                reproducer: vec![],
                worker_id: None,
                shrink_context: ShrinkContext::default(),
            });

            tests
        }
    }
}
