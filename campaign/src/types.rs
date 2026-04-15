//! Runtime types for recon-fuzzer campaign
//!
//! Configuration types are in the `config` crate.
//! This module contains runtime state types: WorkerState, checkpoints, etc.

use abi::types::GenDict;
use evm::exec::EvmState;

/// Default constants (matching echidna)
pub const DEFAULT_TEST_LIMIT: usize = 50_000;
pub const DEFAULT_SEQ_LEN: usize = 100;
pub const DEFAULT_SHRINK_LIMIT: usize = 5_000;

/// State of a fuzzing worker
#[derive(Debug, Clone)]
pub struct WorkerState {
    /// Worker ID (0-indexed)
    pub worker_id: usize,

    /// Generation dictionary
    pub gen_dict: GenDict,

    /// Flag indicating new coverage found
    pub new_coverage: bool,

    /// Number of call sequences executed
    pub ncallseqs: usize,

    /// Total number of calls executed
    pub ncalls: usize,

    /// Total gas consumed
    pub total_gas: u64,
}

impl WorkerState {
    pub fn new(worker_id: usize, seed: u64) -> Self {
        Self {
            worker_id,
            gen_dict: GenDict::new(seed),
            new_coverage: false,
            ncallseqs: 0,
            ncalls: 0,
            total_gas: 0,
        }
    }
}

/// A checkpoint capturing a VM state at a good optimization value
/// Used to restart fuzzing from promising states instead of initial state
///
/// MULTI-OBJECTIVE OPTIMIZATION: Checkpoints track secondary objectives:
/// - Gas used (lower is better for same optimization value)
/// - Sequence length (shorter is better for same optimization value)
/// - Coverage count (higher is better for same optimization value)
#[derive(Clone)]
pub struct OptimizationCheckpoint {
    /// The VM state at this checkpoint
    pub vm_state: EvmState,
    /// The optimization value achieved at this point (PRIMARY objective)
    pub optimization_value: alloy_primitives::I256,
    /// The sequence that led to this state
    pub sequence: Vec<evm::types::Tx>,
    /// When this checkpoint was created (for LRU eviction)
    pub created_at: std::time::Instant,
    /// SECONDARY OBJECTIVE: Total gas used (lower is better)
    pub gas_used: u64,
    /// SECONDARY OBJECTIVE: Coverage count at this point (higher is better)
    pub coverage_count: usize,
}

impl OptimizationCheckpoint {
    pub fn new(
        vm_state: EvmState,
        optimization_value: alloy_primitives::I256,
        sequence: Vec<evm::types::Tx>,
    ) -> Self {
        Self {
            vm_state,
            optimization_value,
            sequence,
            created_at: std::time::Instant::now(),
            gas_used: 0,
            coverage_count: 0,
        }
    }

    /// Create a checkpoint with secondary objectives
    pub fn with_secondary_objectives(
        vm_state: EvmState,
        optimization_value: alloy_primitives::I256,
        sequence: Vec<evm::types::Tx>,
        gas_used: u64,
        coverage_count: usize,
    ) -> Self {
        Self {
            vm_state,
            optimization_value,
            sequence,
            created_at: std::time::Instant::now(),
            gas_used,
            coverage_count,
        }
    }

    /// Compare two checkpoints using multi-objective comparison
    /// Returns true if self is "better" than other
    /// Primary: higher optimization value wins
    /// If equal: lower gas wins, then shorter sequence, then higher coverage
    pub fn is_better_than(&self, other: &Self) -> bool {
        if self.optimization_value != other.optimization_value {
            return self.optimization_value > other.optimization_value;
        }
        // Same optimization value - use secondary objectives
        if self.gas_used != other.gas_used {
            return self.gas_used < other.gas_used; // Lower gas is better
        }
        if self.sequence.len() != other.sequence.len() {
            return self.sequence.len() < other.sequence.len(); // Shorter is better
        }
        self.coverage_count > other.coverage_count // Higher coverage is better
    }
}

/// Checkpoint manager for optimization mode
/// Keeps track of promising VM states for restart
///
/// MULTI-OBJECTIVE OPTIMIZATION: Uses Pareto-like dominance for checkpoint selection.
/// A checkpoint dominates another if it's better in all objectives (or equal in some, better in others).
pub struct CheckpointManager {
    /// Sorted list of checkpoints (best value first, then by secondary objectives)
    checkpoints: Vec<OptimizationCheckpoint>,
    /// Maximum number of checkpoints to keep
    max_checkpoints: usize,
}

impl CheckpointManager {
    pub fn new(max_checkpoints: usize) -> Self {
        Self {
            checkpoints: Vec::new(),
            max_checkpoints,
        }
    }

    /// Add a checkpoint using multi-objective comparison
    /// Keeps diverse checkpoints to explore different trade-offs
    pub fn add_checkpoint(&mut self, checkpoint: OptimizationCheckpoint) {
        // Find insertion position using multi-objective comparison
        let insert_pos = self.checkpoints
            .iter()
            .position(|c| checkpoint.is_better_than(c))
            .unwrap_or(self.checkpoints.len());

        self.checkpoints.insert(insert_pos, checkpoint);

        // Remove dominated checkpoints (keep diversity)
        self.prune_dominated();

        // Trim to max size
        while self.checkpoints.len() > self.max_checkpoints {
            self.checkpoints.pop();
        }
    }

    /// Remove checkpoints that are dominated by others
    /// A checkpoint is dominated if another checkpoint is better in ALL objectives
    fn prune_dominated(&mut self) {
        let mut to_remove = Vec::new();

        for i in 0..self.checkpoints.len() {
            for j in 0..self.checkpoints.len() {
                if i != j && self.checkpoints[j].is_better_than(&self.checkpoints[i]) {
                    // Check if j dominates i completely
                    let j_dominates = self.checkpoints[j].optimization_value >= self.checkpoints[i].optimization_value
                        && self.checkpoints[j].gas_used <= self.checkpoints[i].gas_used
                        && self.checkpoints[j].sequence.len() <= self.checkpoints[i].sequence.len()
                        && self.checkpoints[j].coverage_count >= self.checkpoints[i].coverage_count;

                    if j_dominates && !to_remove.contains(&i) {
                        to_remove.push(i);
                    }
                }
            }
        }

        // Remove dominated in reverse order to preserve indices
        to_remove.sort_by(|a, b| b.cmp(a));
        for idx in to_remove {
            self.checkpoints.remove(idx);
        }
    }

    /// Get a random checkpoint weighted by value (better = more likely)
    pub fn get_random_checkpoint<R: rand::Rng>(&self, rng: &mut R) -> Option<&OptimizationCheckpoint> {
        if self.checkpoints.is_empty() {
            return None;
        }

        // Weight by position (first = best = highest weight)
        let total_weight: usize = (1..=self.checkpoints.len()).sum();
        let mut n = rng.gen_range(0..total_weight);

        for (i, checkpoint) in self.checkpoints.iter().enumerate() {
            let weight = self.checkpoints.len() - i;
            if n < weight {
                return Some(checkpoint);
            }
            n -= weight;
        }

        self.checkpoints.first()
    }

    /// Get the best checkpoint (highest optimization value)
    pub fn best(&self) -> Option<&OptimizationCheckpoint> {
        self.checkpoints.first()
    }

    /// Check if we have any checkpoints
    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }

    /// Number of checkpoints
    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }
}

/// Worker stop reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerStopReason {
    /// Reached test limit
    TestLimit,

    /// Test failed and stop_on_fail is true
    TestFailed,

    /// Timeout
    Timeout,

    /// All tests passed or solved
    AllTestsComplete,

    /// Worker was stopped externally
    Stopped,
}
