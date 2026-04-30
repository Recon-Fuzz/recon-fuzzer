//! Core EVM transaction types
//!

use alloy::dyn_abi::DynSolValue;
use alloy_primitives::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};

// Re-export constants from primitives for backwards compatibility
pub use primitives::{
    DEFAULT_BLOCK_DELAY, DEFAULT_TIME_DELAY, EXTENDED_BLOCK_DELAY, EXTENDED_TIME_DELAY,
    INITIAL_BLOCK_NUMBER, INITIAL_TIMESTAMP, MAX_GAS_PER_BLOCK,
};

/// A transaction call type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxCall {
    /// Contract creation with bytecode
    SolCreate(Bytes),

    /// Solidity function call with name and arguments
    SolCall {
        name: String,
        #[serde(with = "crate::serde_utils::vec_dyn_sol_value")]
        args: Vec<DynSolValue>,
    },

    /// Raw calldata
    SolCalldata(Bytes),

    /// No call (delay-only transaction)
    NoCall,
}

impl TxCall {
    pub fn is_no_call(&self) -> bool {
        matches!(self, TxCall::NoCall)
    }
}

/// One record per `vm.generateCalls(uint256)` invocation made during a tx.
///
/// During fuzz, the cheatcode produces calls deterministically from
/// `(rng_seed, call_count)`. To reproduce a failing run during shrink we
/// pin both the per-tx seed (on `Tx.generate_calls_seed`) and the per-
/// invocation parameters captured here. `keep_mask` lets the inner-batch
/// shrinker keep an arbitrary subset of the originally-generated calls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GenerateCallRecord {
    /// `count` argument the contract passed to `vm.generateCalls`. The
    /// cheatcode generates this many calls deterministically; `keep_mask`
    /// then filters which ones are returned.
    pub n: usize,
    /// Replay-time filter: when `Some(mask)`, only indices `i` with
    /// `mask[i] == true` are returned to the harness; the rest are
    /// generated (to keep the RNG stream consistent) but dropped. `None`
    /// means "return all" (no inner-batch shrink applied yet).
    pub keep_mask: Option<Vec<bool>>,
}

impl GenerateCallRecord {
    /// Number of calls that will actually be returned to the harness.
    pub fn returned_count(&self) -> usize {
        match &self.keep_mask {
            Some(m) => m.iter().filter(|b| **b).count(),
            None => self.n,
        }
    }
}

/// A transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx {
    /// The call to make
    pub call: TxCall,

    /// Sender address
    pub src: Address,

    /// Destination address
    pub dst: Address,

    /// Gas limit
    pub gas: u64,

    /// Gas price
    pub gasprice: U256,

    /// ETH value to send
    pub value: U256,

    /// Delay: (time in seconds, block count)
    pub delay: (u64, u64),

    /// Seed used by `vm.generateCalls()` during this tx's run. `None` means
    /// the cheatcode wasn't invoked (or this tx hasn't run yet). Restored
    /// verbatim during shrink replay so the same calls are generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate_calls_seed: Option<u64>,

    /// One record per `vm.generateCalls()` invocation made during this tx,
    /// in call order. Empty if the cheatcode wasn't invoked. Carried with
    /// the tx through shrinking; the inner-batch shrinker prunes
    /// `keep_mask` per-invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generate_calls: Vec<GenerateCallRecord>,
}

impl Tx {
    /// Create a basic function call transaction
    pub fn call(
        name: impl Into<String>,
        args: Vec<DynSolValue>,
        src: Address,
        dst: Address,
        delay: (u64, u64),
    ) -> Self {
        Self {
            call: TxCall::SolCall {
                name: name.into(),
                args,
            },
            src,
            dst,
            gas: MAX_GAS_PER_BLOCK,
            gasprice: U256::ZERO,
            value: U256::ZERO,
            delay,
            generate_calls_seed: None,
            generate_calls: Vec::new(),
        }
    }

    /// Create a payable function call
    pub fn call_with_value(
        name: impl Into<String>,
        args: Vec<DynSolValue>,
        src: Address,
        dst: Address,
        value: U256,
        delay: (u64, u64),
    ) -> Self {
        Self {
            call: TxCall::SolCall {
                name: name.into(),
                args,
            },
            src,
            dst,
            gas: MAX_GAS_PER_BLOCK,
            gasprice: U256::ZERO,
            value,
            delay,
            generate_calls_seed: None,
            generate_calls: Vec::new(),
        }
    }

    /// Create a no-call transaction (just time/block delay)
    pub fn no_call(src: Address, dst: Address, delay: (u64, u64)) -> Self {
        Self {
            call: TxCall::NoCall,
            src,
            dst,
            gas: 0,
            gasprice: U256::ZERO,
            value: U256::ZERO,
            delay,
            generate_calls_seed: None,
            generate_calls: Vec::new(),
        }
    }

    /// Check if this is a useless no-call (no delay)
    pub fn is_useless_no_call(&self) -> bool {
        self.call.is_no_call() && self.delay == (0, 0)
    }
}

/// Transaction execution result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxResult {
    /// Returned true (for property tests)
    ReturnTrue,
    /// Returned false (property test failed)
    ReturnFalse,
    /// Execution stopped normally
    Stop,
    /// Reverted
    ErrorRevert,
    /// Out of gas
    ErrorOutOfGas,
    /// Balance too low
    ErrorBalanceTooLow,
    /// Stack underrun
    ErrorStackUnderrun,
    /// Bad jump destination
    ErrorBadJumpDestination,
    /// Invalid opcode
    ErrorInvalidOpcode,
    /// Stack limit exceeded
    ErrorStackLimitExceeded,
    /// State change while static
    ErrorStateChangeWhileStatic,
    /// Call depth limit
    ErrorCallDepthLimitReached,
    /// Assertion failed (for assertion tests)
    ErrorAssertionFailed,
    /// Other error
    ErrorOther,
}

impl TxResult {
    /// Check if this result indicates an error
    pub fn is_error(&self) -> bool {
        !matches!(
            self,
            TxResult::ReturnTrue | TxResult::ReturnFalse | TxResult::Stop
        )
    }

    /// Check if this is a revert
    pub fn is_revert(&self) -> bool {
        matches!(self, TxResult::ErrorRevert)
    }

    /// Convert to a bit index for coverage tracking
    pub fn to_bit_index(&self) -> u8 {
        match self {
            TxResult::ReturnTrue => 0,
            TxResult::ReturnFalse => 1,
            TxResult::Stop => 2,
            TxResult::ErrorRevert => 3,
            TxResult::ErrorOutOfGas => 4,
            TxResult::ErrorBalanceTooLow => 5,
            TxResult::ErrorStackUnderrun => 6,
            TxResult::ErrorBadJumpDestination => 7,
            TxResult::ErrorInvalidOpcode => 8,
            TxResult::ErrorStackLimitExceeded => 9,
            TxResult::ErrorStateChangeWhileStatic => 10,
            TxResult::ErrorCallDepthLimitReached => 11,
            TxResult::ErrorAssertionFailed => 12,
            TxResult::ErrorOther => 13,
        }
    }
}

/// Concatenate consecutive NoCall transactions by summing their delays
pub fn cat_no_calls(txs: Vec<Tx>) -> Vec<Tx> {
    if txs.len() < 2 {
        return txs;
    }

    let mut result = Vec::with_capacity(txs.len());
    let mut iter = txs.into_iter().peekable();

    while let Some(tx) = iter.next() {
        if tx.call.is_no_call() {
            // Accumulate the entire run of consecutive NoCalls
            let mut acc_time = tx.delay.0;
            let mut acc_blocks = tx.delay.1;
            let base_tx = tx;

            while iter.peek().map_or(false, |next| next.call.is_no_call()) {
                let next = iter.next().unwrap();
                acc_time = acc_time.saturating_add(next.delay.0);
                acc_blocks = acc_blocks.saturating_add(next.delay.1);
            }

            result.push(Tx {
                delay: (acc_time, acc_blocks),
                ..base_tx
            });
        } else {
            result.push(tx);
        }
    }

    result
}

/// Absorb NoCall transactions into their next neighbor by summing delays
///
/// Since `exec_tx` applies delay BEFORE execution, `[NoCall(d1), call(d2)]`
/// is semantically identical to `[call(d1+d2)]` — the call executes at the
/// same timestamp/block. This eliminates NoCalls without changing behavior,
/// directly reducing sequence length.
///
/// A trailing NoCall (last tx) cannot be absorbed forward and is kept as-is,
/// since its delay may affect the final test check.
///
/// Should be called after `cat_no_calls` (which first merges consecutive NoCalls).
pub fn absorb_no_calls(txs: Vec<Tx>) -> Vec<Tx> {
    if txs.len() < 2 {
        return txs;
    }

    let mut result: Vec<Tx> = Vec::with_capacity(txs.len());
    let mut pending_delay: (u64, u64) = (0, 0);

    for tx in txs {
        if tx.call.is_no_call() {
            // Accumulate this NoCall's delay to be added to the next real tx
            pending_delay.0 = pending_delay.0.saturating_add(tx.delay.0);
            pending_delay.1 = pending_delay.1.saturating_add(tx.delay.1);
        } else {
            // Real call — absorb any pending delay from preceding NoCalls
            if pending_delay != (0, 0) {
                result.push(Tx {
                    delay: (
                        tx.delay.0.saturating_add(pending_delay.0),
                        tx.delay.1.saturating_add(pending_delay.1),
                    ),
                    ..tx
                });
                pending_delay = (0, 0);
            } else {
                result.push(tx);
            }
        }
    }

    // If there's a trailing NoCall delay with no next tx to absorb into,
    // emit it as a NoCall to preserve the final timestamp for test checks
    if pending_delay != (0, 0) {
        result.push(Tx::no_call(
            Address::ZERO,
            Address::ZERO,
            pending_delay,
        ));
    }

    result
}

/// Remove useless no-calls from a transaction sequence
pub fn remove_useless_no_calls(txs: Vec<Tx>) -> Vec<Tx> {
    txs.into_iter()
        .filter(|tx| !tx.is_useless_no_call())
        .collect()
}
