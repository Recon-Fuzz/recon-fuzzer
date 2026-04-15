//! Core shrink helper functions for browser-fuzzer
//!
//! Matches main fuzzer's campaign/src/shrink/core.rs structure.
//! Contains: sequence shortening, delay candidates, shrink_sender, can_shrink_tx.

use alloy_primitives::Address;
use rand::prelude::*;

use crate::abi::shrink::can_shrink as abi_can_shrink;
use super::super::transaction::Tx;

/// Shorten a sequence by removing a random transaction.
pub fn shorten_seq<R: Rng>(rng: &mut R, txs: &[Tx]) -> Vec<Tx> {
    if txs.len() <= 1 {
        return txs.to_vec();
    }
    let idx = rng.gen_range(0..txs.len());
    [&txs[..idx], &txs[idx + 1..]].concat()
}

/// Multi-position shorten: drop 2-3 transactions at once.
/// More aggressive than single-drop for faster reduction of long sequences.
pub fn multi_shorten_seq<R: Rng>(rng: &mut R, txs: &[Tx]) -> Vec<Tx> {
    if txs.len() <= 2 {
        return shorten_seq(rng, txs);
    }

    let max_drop = (txs.len() / 3).max(2).min(3);
    let drop_count = rng.gen_range(2..=max_drop);

    let mut indices: Vec<usize> = (0..txs.len()).collect();
    indices.shuffle(rng);
    let drop_set: std::collections::HashSet<usize> =
        indices.into_iter().take(drop_count).collect();

    txs.iter()
        .enumerate()
        .filter(|(i, _)| !drop_set.contains(i))
        .map(|(_, tx)| tx.clone())
        .collect()
}

/// Generate structured delay-focused shrink candidates.
/// Matches main fuzzer's generate_delay_candidates():
/// 1. All-zero delays (most aggressive)
/// 2. Uniform halving (preserves relative timing)
/// 3. Per-tx random delay shrinking
/// 4. Minimum viable delays (1, 1)
pub fn generate_delay_candidates<R: Rng>(
    rng: &mut R,
    txs: &[Tx],
    candidates: &mut Vec<Vec<Tx>>,
) {
    let has_nonzero_delay = txs.iter().any(|tx| tx.delay != (0, 0));
    if !has_nonzero_delay {
        return;
    }

    // 1. All-zero delays
    let zero_delays: Vec<Tx> = txs
        .iter()
        .map(|tx| Tx {
            delay: (0, 0),
            ..tx.clone()
        })
        .collect();
    candidates.push(zero_delays);

    // 2. Uniform halving
    let k = rng.gen_range(1..=4u32);
    let halved: Vec<Tx> = txs
        .iter()
        .map(|tx| Tx {
            delay: (tx.delay.0 >> k, tx.delay.1 >> k),
            ..tx.clone()
        })
        .collect();
    candidates.push(halved);

    // 3. Per-tx random delay shrinking
    let random_shrunk: Vec<Tx> = txs
        .iter()
        .map(|tx| {
            let mut result = tx.clone();
            result.delay = (
                lower_u64(rng, tx.delay.0),
                lower_u64(rng, tx.delay.1),
            );
            result
        })
        .collect();
    candidates.push(random_shrunk);

    // 4. Minimum viable delays (1, 1)
    let minimal: Vec<Tx> = txs
        .iter()
        .map(|tx| {
            if tx.delay == (0, 0) {
                tx.clone()
            } else {
                Tx {
                    delay: (1, 1),
                    ..tx.clone()
                }
            }
        })
        .collect();
    candidates.push(minimal);
}

/// Shrink a single delay value (for delay-only candidates)
pub fn lower_u64<R: Rng>(rng: &mut R, x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    match rng.gen_range(0..4) {
        0 => 0,
        1 => x / 2,
        2 => 1,
        _ => rng.gen_range(0..=x),
    }
}

/// Shrink the sender address to a simpler one.
///
/// Given a transaction, replace the sender with another one which is simpler
/// (i.e., closer to zero). Usually this means simplified transactions will
/// try to use 0x10000 as the same caller.
pub fn shrink_sender<R: Rng>(
    rng: &mut R,
    tx: &Tx,
    ordered_senders: &[Address],
) -> Tx {
    if ordered_senders.is_empty() {
        return tx.clone();
    }

    // Find current sender's position in the sorted list
    let pos = ordered_senders.iter().position(|&s| s == tx.sender);

    match pos {
        Some(i) if i > 0 => {
            // sender <- uniform (take (i+1) orderedSenders)
            // Pick any sender from index 0 to i (inclusive)
            let new_idx = rng.gen_range(0..=i);
            Tx {
                sender: ordered_senders[new_idx],
                ..tx.clone()
            }
        }
        _ => tx.clone(),
    }
}

/// Check if a transaction can be shrunk.
pub fn can_shrink_tx(tx: &Tx) -> bool {
    // If value or delay are non-zero, we can shrink
    if !tx.value.is_zero() || tx.delay != (0, 0) {
        return true;
    }

    // Otherwise check if call arguments can be shrunk
    if tx.is_no_call() {
        return false;
    }

    tx.args.iter().any(|a| abi_can_shrink(a))
}

/// Calculate delay complexity (sum of all delays).
/// Matches main fuzzer's calculate_delay_complexity().
pub fn calculate_delay_complexity(txs: &[Tx]) -> u128 {
    let mut total: u128 = 0;
    for tx in txs {
        total = total.saturating_add(tx.delay.0 as u128);
        total = total.saturating_add(tx.delay.1 as u128);
    }
    total
}

/// Generate call-to-delay conversion candidates.
/// Matches main fuzzer's generate_call_to_delay_candidates().
///
/// Key insight: many transactions in a reproducer only contribute their delay
/// (time/block advancement) to the bug — their state changes are irrelevant.
/// This strategy identifies such transactions by testing: "if I replace this
/// call with a NoCall (keeping its delay), does the test still fail?"
///
/// Generates 2 candidates:
/// 1. Greedy forward scan: convert each non-last tx to NoCall if the sequence
///    still falsifies the test.
/// 2. Random batch conversion: pick a random subset of non-last txs and convert
///    them all at once.
pub fn generate_call_to_delay_candidates<R: Rng, F>(
    rng: &mut R,
    txs: &[Tx],
    mut check_fn: F,
    candidates: &mut Vec<Vec<Tx>>,
) where
    F: FnMut(&[Tx]) -> bool,
{
    let len = txs.len();
    if len <= 2 {
        return;
    }

    // Only try if there are actual calls to convert (not already all NoCalls)
    let real_call_count = txs[..len - 1]
        .iter()
        .filter(|tx| !tx.is_no_call())
        .count();
    if real_call_count == 0 {
        return;
    }

    // 1. Greedy forward scan: convert each non-last tx to NoCall if test still fails
    {
        let mut candidate = txs.to_vec();
        let max_probes = 20;
        let probe_indices: Vec<usize> = if real_call_count <= max_probes {
            (0..len - 1)
                .filter(|&i| !txs[i].is_no_call())
                .collect()
        } else {
            let mut indices: Vec<usize> = (0..len - 1)
                .filter(|&i| !txs[i].is_no_call())
                .collect();
            indices.shuffle(rng);
            indices.truncate(max_probes);
            indices.sort();
            indices
        };
        for i in probe_indices {
            if candidate[i].is_no_call() {
                continue;
            }
            let original = candidate[i].clone();
            candidate[i] = Tx::no_call(original.sender, original.target, original.delay);

            if !check_fn(&candidate) {
                // Revert: this tx's call effect matters
                candidate[i] = original;
            }
        }
        // Only add if we actually converted something
        let converted_count = candidate[..len - 1]
            .iter()
            .zip(txs[..len - 1].iter())
            .filter(|(new, old)| new.is_no_call() && !old.is_no_call())
            .count();
        if converted_count > 0 {
            candidates.push(candidate);
        }
    }

    // 2. Random batch conversion: convert a random subset of non-last txs
    {
        let convert_prob = rng.gen_range(30..=50) as f64 / 100.0;
        let candidate: Vec<Tx> = txs
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                if i < len - 1 && !tx.is_no_call() && rng.gen_bool(convert_prob) {
                    Tx::no_call(tx.sender, tx.target, tx.delay)
                } else {
                    tx.clone()
                }
            })
            .collect();
        candidates.push(candidate);
    }
}

/// Remove useless NoCalls from a sequence.
/// Merges consecutive NoCalls (sums delays), removes zero-delay NoCalls.
/// Matches main fuzzer's cat_no_calls + absorb_no_calls + remove_useless_no_calls.
pub fn remove_useless_no_calls(txs: Vec<Tx>) -> Vec<Tx> {
    if txs.is_empty() {
        return txs;
    }

    // Step 1: merge consecutive NoCalls (cat_no_calls + absorb_no_calls)
    let mut merged = Vec::with_capacity(txs.len());
    for tx in txs {
        if tx.is_no_call() {
            if let Some(last) = merged.last_mut() {
                let last_tx: &mut Tx = last;
                if last_tx.is_no_call() {
                    // Merge: sum delays
                    last_tx.delay.0 = last_tx.delay.0.saturating_add(tx.delay.0);
                    last_tx.delay.1 = last_tx.delay.1.saturating_add(tx.delay.1);
                    continue;
                }
            }
        }
        merged.push(tx);
    }

    // Step 2: remove zero-delay NoCalls (remove_useless_no_calls)
    merged
        .into_iter()
        .filter(|tx| !(tx.is_no_call() && tx.delay == (0, 0)))
        .collect()
}
