//! Core test shrinking logic
//!
//! Rust equivalent of Echidna's Shrink.hs
//!
//! Optimizations over Echidna:
//! - Parallel candidate validation using Rayon
//! - Try multiple shrink strategies per iteration
//! - Multi-position shortening for faster sequence reduction
//! - Aggressive shortening for long sequences
//! - Mode-based shrinking: switches between sequence reduction and value shrinking
//! - Smart strategy selection: skips no-op strategies (e.g., shrink value when already 0)

use alloy_primitives::Address;
use rand::prelude::*;
use rayon::prelude::*;
use std::collections::HashSet;

use evm::exec::EvmState;
use evm::types::{absorb_no_calls, cat_no_calls, remove_useless_no_calls, Tx, TxCall};

use crate::config::Env;
use crate::testing::{
    calculate_delay_complexity, calculate_value_complexity, EchidnaTest, ShrinkMode, TestState,
    TestValue,
};
use crate::worker_env::WorkerEnv;

/// Shrink a test's reproducer
///
/// Key insight from The VM passed in is the INITIAL VM (after setup).
/// - `removeReverts` runs txs on a clone to identify reverts
/// - `shrinkSeq` validates candidate sequences starting from FRESH clones of initial VM
///
/// OPTIMIZED: Tracks shrink mode (Sequence vs ValueOnly) and switches automatically
/// when stuck on one type of reduction.
pub fn shrink_test<R: Rng>(
    env: &Env,
    initial_vm: &EvmState, // The initial VM (after setup) - we only read/clone from this
    test: &EchidnaTest,
    rng: &mut R,
) -> anyhow::Result<Option<EchidnaTest>> {
    let shrink_limit = env.cfg.campaign_conf.shrink_limit as i32;
    let is_optimization = matches!(
        test.test_type,
        crate::testing::TestType::OptimizationTest { .. }
    );

    match &test.state {
        TestState::Large(n) => {
            // Check if we've reached shrink limit
            // For optimization tests, keep trying (Large (i + 1) for optimization)
            // For other tests, mark as Solved when limit reached
            if *n >= shrink_limit && !is_optimization {
                let mut shrunk = test.clone();
                shrunk.state = TestState::Solved;
                return Ok(Some(shrunk));
            }

            // Try to simplify the reproducer
            let mut shrunk = test.clone();

            // Remove reverts (removeReverts vm test.reproducer)
            // This needs its own VM clone since it modifies state during execution
            let mut vm_for_remove_reverts = initial_vm.clone();
            let simplified = remove_reverts(
                &mut vm_for_remove_reverts,
                &test.reproducer,
                &env.world.view_pure_functions,
            )?;
            let simplified = remove_useless_no_calls(absorb_no_calls(cat_no_calls(simplified)));

            // Stop shrinking when we reach a single transaction - can't reduce further
            if simplified.len() <= 1 {
                shrunk.state = TestState::Solved;
                shrunk.reproducer = simplified;
                return Ok(Some(shrunk));
            }

            // Check if we can shrink further (length rr > 1 || any canShrinkTx rr)
            if simplified.len() > 1 || simplified.iter().any(can_shrink_tx) {
                // Try shrinking - pass the INITIAL VM, shrink_seq will clone as needed
                if let Some((new_repro, new_val)) =
                    shrink_seq(env, initial_vm, rng, &simplified, &shrunk)?
                {
                    // Calculate value complexity for mode tracking
                    let new_complexity = calculate_value_complexity(&new_repro);

                    // Update shrink context to track progress and potentially switch modes
                    shrunk
                        .shrink_context
                        .update(new_repro.len(), new_complexity);

                    shrunk.reproducer = new_repro;
                    shrunk.value = new_val;
                    shrunk.state = TestState::Large(n + 1);
                    return Ok(Some(shrunk));
                } else {
                    // Shrink attempt failed (test passed with shrunk sequence)
                    // Keep the SIMPLIFIED reproducer (rr), bump counter
                    // Just test { state = Large (i + 1), reproducer = rr}

                    // Update context even on failure (counts as no progress)
                    let complexity = calculate_value_complexity(&simplified);
                    shrunk.shrink_context.update(simplified.len(), complexity);

                    shrunk.state = TestState::Large(n + 1);
                    shrunk.reproducer = simplified;
                    return Ok(Some(shrunk));
                }
            }

            // Can't shrink further (single non-shrinkable tx)
            // Validate that simplified sequence still fails the test before accepting
            // (shrinkSeq validates before accepting)
            let mut vm_for_validate = initial_vm.clone();
            let val = execute_and_check(&mut vm_for_validate, &simplified, test)?;

            match (&val, &test.value) {
                // Test still fails - accept simplified as final reproducer
                (TestValue::BoolValue(false), _) => {
                    shrunk.state = TestState::Solved;
                    shrunk.reproducer = simplified;
                }
                // Optimization test - accept if value is >= original
                (TestValue::IntValue(new), TestValue::IntValue(old)) if new >= old => {
                    shrunk.state = TestState::Solved;
                    shrunk.reproducer = simplified;
                    shrunk.value = val;
                }
                // Test passed with simplified sequence - keep original reproducer
                _ => {
                    shrunk.state = TestState::Solved;
                    // Keep original reproducer - simplified doesn't trigger the failure
                }
            }
            Ok(Some(shrunk))
        }
        _ => Ok(None),
    }
}

/// Check if a transaction can be shrunk
fn can_shrink_tx(tx: &Tx) -> bool {
    // canShrinkTx Tx { call, gasprice = 0, value = 0, delay = (0, 0) } =
    //   case call of SolCall (_, l) -> any canShrinkAbiValue l; _ -> False
    // canShrinkTx _ = True

    // If gasprice, value, or delay are non-zero, we can shrink
    if !tx.gasprice.is_zero() || !tx.value.is_zero() || tx.delay != (0, 0) {
        return true;
    }

    // Otherwise check if call arguments can be shrunk
    match &tx.call {
        TxCall::SolCall { args, .. } => args.iter().any(|a| abi::shrink::can_shrink(a)),
        TxCall::NoCall => false,
        _ => true, // SolCalldata and SolCreate can potentially be shrunk
    }
}

/// Remove reverting transactions and pure/view calls from the sequence
///
/// Executes transactions on the VM, replacing any that revert OR are pure/view with NoCall.
/// Pure/view functions don't modify state, so they can be removed to simplify reproducers.
fn remove_reverts(
    vm: &mut EvmState,
    txs: &[Tx],
    view_pure_functions: &std::collections::HashSet<String>,
) -> anyhow::Result<Vec<Tx>> {
    if txs.is_empty() {
        return Ok(vec![]);
    }

    let (init, last) = txs.split_at(txs.len() - 1);
    let mut result = Vec::with_capacity(txs.len());

    for tx in init {
        // Check if this is a pure/view function call (doesn't modify state)
        let is_view_pure = match &tx.call {
            TxCall::SolCall { name, .. } => view_pure_functions.contains(name),
            _ => false,
        };

        if is_view_pure {
            // Pure/view calls don't affect state, replace with NoCall
            result.push(Tx::no_call(tx.src, tx.dst, tx.delay));
        } else {
            // Execute and check for revert
            let tx_result = vm.exec_tx(tx)?;
            if tx_result.is_revert() {
                // Replace with NoCall but keep delay (replaceByNoCall)
                result.push(Tx::no_call(tx.src, tx.dst, tx.delay));
            } else {
                result.push(tx.clone());
            }
        }
    }

    // Keep the last transaction as-is (it's the one that triggers the failure)
    result.extend(last.iter().cloned());

    Ok(result)
}

/// Shrink a transaction sequence
///
/// OPTIMIZED: Uses parallel candidate validation for faster shrinking
/// - Generates multiple candidates (shorten at different positions + shrunk args)
/// - Validates candidates in parallel using Rayon
/// - Mode-based: in Sequence mode focuses on shortening, in ValueOnly mode focuses on value shrinking
/// - Returns the best valid candidate (shortest, then smallest values)
fn shrink_seq<R: Rng>(
    env: &Env,
    initial_vm: &EvmState, // Read-only reference to initial VM
    rng: &mut R,
    txs: &[Tx],
    test: &EchidnaTest,
) -> anyhow::Result<Option<(Vec<Tx>, TestValue)>> {
    if txs.is_empty() {
        return Ok(None);
    }

    // Get sorted senders for shrinkSender 
    let mut sorted_senders: Vec<Address> = env.cfg.sol_conf.sender.iter().cloned().collect();
    sorted_senders.sort();

    // Generate candidates based on current shrink mode
    let mut candidates: Vec<Vec<Tx>> = Vec::new();
    let mode = test.shrink_context.mode;

    match mode {
        ShrinkMode::Sequence => {
            // Focus on sequence shortening with some value shrinking
            if txs.len() > 10 {
                for _ in 0..3 {
                    candidates.push(multi_shorten_seq(rng, txs));
                }
            }
            let num_shorten = if txs.len() > 5 { 4 } else { 2 };
            for _ in 0..num_shorten {
                candidates.push(shorten_seq(rng, txs));
            }
            // Still include some value shrinking
            for _ in 0..2 {
                let shrunk: Vec<Tx> = txs
                    .iter()
                    .map(|tx| {
                        let t = crate::transaction::shrink_tx(rng, tx);
                        shrink_sender(rng, &t, &sorted_senders)
                    })
                    .collect();
                candidates.push(shrunk);
            }
            // Delay-focused candidates (decoupled from arg shrinking)
            generate_delay_candidates(rng, txs, &mut candidates);
            // Call-to-delay conversion: convert random txs to NoCalls, merge consecutive
            if txs.len() > 2 {
                generate_call_to_delay_candidates(rng, txs, initial_vm, test, &mut candidates);
            }
        }
        ShrinkMode::ValueOnly => {
            // Focus on value shrinking with minimal sequence shortening
            for _ in 0..2 {
                candidates.push(shorten_seq(rng, txs));
            }
            // Many more value shrinking attempts
            for _ in 0..8 {
                let shrunk: Vec<Tx> = txs
                    .iter()
                    .map(|tx| {
                        let t = crate::transaction::shrink_tx(rng, tx);
                        shrink_sender(rng, &t, &sorted_senders)
                    })
                    .collect();
                candidates.push(shrunk);
            }
            // Delay-focused candidates (decoupled from arg shrinking)
            generate_delay_candidates(rng, txs, &mut candidates);
            // Call-to-delay conversion (also useful in ValueOnly — can reduce length)
            if txs.len() > 2 {
                generate_call_to_delay_candidates(rng, txs, initial_vm, test, &mut candidates);
            }
        }
    }

    // Clean up candidates: merge consecutive NoCalls, then remove zero-delay NoCalls
    let candidates: Vec<Vec<Tx>> = candidates
        .into_iter()
        .map(|c| remove_useless_no_calls(absorb_no_calls(cat_no_calls(c))))
        .collect();

    // Validate candidates in parallel and collect valid ones
    let test_value = &test.value;
    let valid_results: Vec<(Vec<Tx>, TestValue)> = candidates
        .into_par_iter()
        .filter_map(|candidate| {
            let mut vm = initial_vm.clone();
            let val = execute_and_check(&mut vm, &candidate, test).ok()?;

            match (&val, test_value) {
                (TestValue::BoolValue(false), _) => Some((candidate, val)),
                (TestValue::IntValue(new), TestValue::IntValue(old)) if new >= old => {
                    Some((candidate, val))
                }
                _ => None,
            }
        })
        .collect();

    // Return the best valid candidate using lexicographic ordering:
    // 1. Prefer shorter sequences (fewer transactions)
    // 2. When lengths are equal, prefer smaller value complexity (args + delays combined)
    // 3. Break ties by delay complexity specifically (prefer smaller total delays)
    Ok(valid_results.into_iter().min_by(|(txs_a, _), (txs_b, _)| {
        let len_cmp = txs_a.len().cmp(&txs_b.len());
        if len_cmp != std::cmp::Ordering::Equal {
            return len_cmp;
        }
        let val_cmp = calculate_value_complexity(txs_a).cmp(&calculate_value_complexity(txs_b));
        if val_cmp != std::cmp::Ordering::Equal {
            return val_cmp;
        }
        calculate_delay_complexity(txs_a).cmp(&calculate_delay_complexity(txs_b))
    }))
}

/// Execute sequence and check test result
/// ```haskell
/// check [] vm' = f vm'
/// check (x:xs') vm' = do
///   (_, vm'') <- execTx vm' x
///   check xs' vm''
/// ```
fn execute_and_check(
    vm: &mut EvmState,
    txs: &[Tx],
    test: &EchidnaTest,
) -> anyhow::Result<TestValue> {
    use crate::testing::check_etest;

    // Execute all transactions in order
    for tx in txs {
        vm.exec_tx(tx)?;
    }

    // Check using check_etest (f vm' where f = checkETest test)
    let sender = txs.last().map(|t| t.src).unwrap_or(Address::ZERO);
    let (val, _res) = check_etest(vm, test, sender)?;

    Ok(val)
}

/// Shorten a sequence by removing a random transaction
fn shorten_seq<R: Rng>(rng: &mut R, txs: &[Tx]) -> Vec<Tx> {
    if txs.len() <= 1 {
        return txs.to_vec();
    }

    let idx = rng.gen_range(0..txs.len());
    [&txs[..idx], &txs[idx + 1..]].concat()
}

/// Shrink the sender address to a simpler one
///
/// Given a transaction, replace the sender with another one which is simpler
/// (i.e., closer to zero). Usually this means simplified transactions will
/// try to use 0x10000 as the same caller.
pub fn shrink_sender<R: Rng>(
    rng: &mut R,
    tx: &Tx,
    ordered_senders: &[alloy_primitives::Address],
) -> Tx {
    if ordered_senders.is_empty() {
        return tx.clone();
    }

    // Find current sender's position in the sorted list
    let pos = ordered_senders.iter().position(|&s| s == tx.src);

    match pos {
        Some(i) if i > 0 => {
            // sender <- uniform (take (i+1) orderedSenders)
            // Pick any sender from index 0 to i (inclusive)
            let new_idx = rng.gen_range(0..=i);
            Tx {
                src: ordered_senders[new_idx],
                ..tx.clone()
            }
        }
        _ => tx.clone(),
    }
}

// =============================================================================
// WorkerEnv variants
// =============================================================================

/// Shrink a test's reproducer (WorkerEnv variant)
///
/// OPTIMIZED: Tracks shrink mode (Sequence vs ValueOnly) and switches automatically
/// when stuck on one type of reduction.
pub fn shrink_test_worker<R: Rng>(
    env: &WorkerEnv,
    initial_vm: &EvmState,
    test: &EchidnaTest,
    rng: &mut R,
) -> anyhow::Result<Option<EchidnaTest>> {
    let shrink_limit = env.cfg.campaign_conf.shrink_limit as i32;
    let is_optimization = matches!(
        test.test_type,
        crate::testing::TestType::OptimizationTest { .. }
    );

    match &test.state {
        TestState::Large(n) => {
            if *n >= shrink_limit && !is_optimization {
                let mut shrunk = test.clone();
                shrunk.state = TestState::Solved;
                return Ok(Some(shrunk));
            }

            let mut shrunk = test.clone();

            let mut vm_for_remove_reverts = initial_vm.clone();
            let simplified = remove_reverts(
                &mut vm_for_remove_reverts,
                &test.reproducer,
                &env.world.view_pure_functions,
            )?;
            let simplified = remove_useless_no_calls(absorb_no_calls(cat_no_calls(simplified)));

            // Stop shrinking when we reach a single transaction - can't reduce further
            if simplified.len() <= 1 {
                shrunk.state = TestState::Solved;
                shrunk.reproducer = simplified;
                return Ok(Some(shrunk));
            }

            if simplified.len() > 1 || simplified.iter().any(can_shrink_tx) {
                if let Some((new_repro, new_val)) =
                    shrink_seq_worker(env, initial_vm, rng, &simplified, &shrunk)?
                {
                    // Calculate value complexity for mode tracking
                    let new_complexity = calculate_value_complexity(&new_repro);

                    // Update shrink context to track progress and potentially switch modes
                    shrunk
                        .shrink_context
                        .update(new_repro.len(), new_complexity);

                    shrunk.reproducer = new_repro;
                    shrunk.value = new_val;
                    shrunk.state = TestState::Large(n + 1);
                    return Ok(Some(shrunk));
                } else {
                    // Update context even on failure (counts as no progress)
                    let complexity = calculate_value_complexity(&simplified);
                    shrunk.shrink_context.update(simplified.len(), complexity);

                    shrunk.state = TestState::Large(n + 1);
                    shrunk.reproducer = simplified;
                    return Ok(Some(shrunk));
                }
            }

            // Can't shrink further (single non-shrinkable tx)
            // Mark as Solved for all test types - shrinking is complete
            shrunk.state = TestState::Solved;
            shrunk.reproducer = simplified;
            Ok(Some(shrunk))
        }
        _ => Ok(None),
    }
}

/// Shrink a transaction sequence (WorkerEnv variant)
///
/// OPTIMIZED: Uses parallel candidate validation for faster shrinking
/// - Generates multiple candidates (shorten at different positions + shrunk args)
/// - Validates candidates in parallel using Rayon
/// - Mode-based: in Sequence mode focuses on shortening, in ValueOnly mode focuses on value shrinking
/// - Returns the best valid candidate (shortest, then smallest values)
fn shrink_seq_worker<R: Rng>(
    env: &WorkerEnv,
    initial_vm: &EvmState,
    rng: &mut R,
    txs: &[Tx],
    test: &EchidnaTest,
) -> anyhow::Result<Option<(Vec<Tx>, TestValue)>> {
    if txs.is_empty() {
        return Ok(None);
    }

    // Get sorted senders for shrinkSender 
    let mut sorted_senders: Vec<Address> = env.cfg.sol_conf.sender.iter().cloned().collect();
    sorted_senders.sort();

    // Generate candidates based on current shrink mode
    let mut candidates: Vec<Vec<Tx>> = Vec::new();
    let mode = test.shrink_context.mode;

    match mode {
        ShrinkMode::Sequence => {
            // Focus on sequence shortening with some value shrinking
            if txs.len() > 10 {
                for _ in 0..3 {
                    candidates.push(multi_shorten_seq(rng, txs));
                }
            }
            let num_shorten = if txs.len() > 5 { 4 } else { 2 };
            for _ in 0..num_shorten {
                candidates.push(shorten_seq(rng, txs));
            }
            // Still include some value shrinking
            for _ in 0..2 {
                let shrunk: Vec<Tx> = txs
                    .iter()
                    .map(|tx| {
                        let t = crate::transaction::shrink_tx(rng, tx);
                        shrink_sender(rng, &t, &sorted_senders)
                    })
                    .collect();
                candidates.push(shrunk);
            }
            // Delay-focused candidates (decoupled from arg shrinking)
            generate_delay_candidates(rng, txs, &mut candidates);
            // Call-to-delay conversion: convert random txs to NoCalls, merge consecutive
            if txs.len() > 2 {
                generate_call_to_delay_candidates(rng, txs, initial_vm, test, &mut candidates);
            }
        }
        ShrinkMode::ValueOnly => {
            // Focus on value shrinking with minimal sequence shortening
            for _ in 0..2 {
                candidates.push(shorten_seq(rng, txs));
            }
            // Many more value shrinking attempts
            for _ in 0..8 {
                let shrunk: Vec<Tx> = txs
                    .iter()
                    .map(|tx| {
                        let t = crate::transaction::shrink_tx(rng, tx);
                        shrink_sender(rng, &t, &sorted_senders)
                    })
                    .collect();
                candidates.push(shrunk);
            }
            // Delay-focused candidates (decoupled from arg shrinking)
            generate_delay_candidates(rng, txs, &mut candidates);
            // Call-to-delay conversion (also useful in ValueOnly — can reduce length)
            if txs.len() > 2 {
                generate_call_to_delay_candidates(rng, txs, initial_vm, test, &mut candidates);
            }
        }
    }

    // Clean up candidates: merge consecutive NoCalls, then remove zero-delay NoCalls
    let candidates: Vec<Vec<Tx>> = candidates
        .into_iter()
        .map(|c| remove_useless_no_calls(absorb_no_calls(cat_no_calls(c))))
        .collect();

    // Validate candidates in parallel and collect valid ones
    let test_value = &test.value;
    let valid_results: Vec<(Vec<Tx>, TestValue)> = candidates
        .into_par_iter()
        .filter_map(|candidate| {
            // Each parallel task gets its own VM clone
            let mut vm = initial_vm.clone();
            let val = execute_and_check(&mut vm, &candidate, test).ok()?;

            // Check if this candidate is valid (test still fails)
            match (&val, test_value) {
                (TestValue::BoolValue(false), _) => Some((candidate, val)),
                (TestValue::IntValue(new), TestValue::IntValue(old)) if new >= old => {
                    Some((candidate, val))
                }
                _ => None,
            }
        })
        .collect();

    // Return the best valid candidate using lexicographic ordering:
    // 1. Prefer shorter sequences (fewer transactions)
    // 2. When lengths are equal, prefer smaller value complexity (args + delays combined)
    // 3. Break ties by delay complexity specifically (prefer smaller total delays)
    Ok(valid_results.into_iter().min_by(|(txs_a, _), (txs_b, _)| {
        let len_cmp = txs_a.len().cmp(&txs_b.len());
        if len_cmp != std::cmp::Ordering::Equal {
            return len_cmp;
        }
        let val_cmp = calculate_value_complexity(txs_a).cmp(&calculate_value_complexity(txs_b));
        if val_cmp != std::cmp::Ordering::Equal {
            return val_cmp;
        }
        calculate_delay_complexity(txs_a).cmp(&calculate_delay_complexity(txs_b))
    }))
}

/// Generate structured delay-focused shrink candidates
///
/// These candidates target delays independently from call arguments, addressing
/// the strategy competition problem where shrink_tx randomly picks between
/// {call, value, gasprice, delay} strategies.
///
/// Generates 4 candidate types:
/// 1. **All-zero delays**: Tests if delays matter at all. Many bugs are triggered
///    by function ordering alone, not timing, so zeroed delays is often the optimal
///    reproducer. This is the most aggressive candidate.
///
/// 2. **Uniform halving**: Divides all delays by the same power of 2. Preserves
///    the relative timing relationships between transactions while making the
///    reproducer simpler. Useful for time-dependent bugs.
///
/// 3. **Per-tx random shrink**: Applies shrink_delay_only to each tx independently.
///    Provides stochastic exploration within the delay space.
///
/// 4. **Minimum viable delays**: Sets all delays to (1, 1) — the smallest non-zero
///    delay. Tests if the bug requires *any* time passage, without caring about magnitude.
fn generate_delay_candidates<R: Rng>(rng: &mut R, txs: &[Tx], candidates: &mut Vec<Vec<Tx>>) {
    let has_nonzero_delay = txs.iter().any(|tx| tx.delay != (0, 0));
    if !has_nonzero_delay {
        return;
    }

    // 1. All-zero delays: most aggressive, tests if delays matter at all
    let zero_delays: Vec<Tx> = txs
        .iter()
        .map(|tx| Tx {
            delay: (0, 0),
            ..tx.clone()
        })
        .collect();
    candidates.push(zero_delays);

    // 2. Uniform halving: divide all delays by 2^k (preserves relative timing)
    let k = rng.gen_range(1..=4u32); // halve by 2, 4, 8, or 16
    let halved: Vec<Tx> = txs
        .iter()
        .map(|tx| Tx {
            delay: (tx.delay.0 >> k, tx.delay.1 >> k),
            ..tx.clone()
        })
        .collect();
    candidates.push(halved);

    // 3. Per-tx random delay shrinking (independent of call args)
    let random_shrunk: Vec<Tx> = txs
        .iter()
        .map(|tx| crate::transaction::shrink_delay_only(rng, tx))
        .collect();
    candidates.push(random_shrunk);

    // 4. Minimum viable delays: (1, 1) for all — tests if "some" time passage suffices
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

/// Generate call-to-delay conversion candidates
///
/// Key insight: many transactions in a reproducer only contribute their delay
/// (time/block advancement) to the bug — their state changes are irrelevant.
/// This strategy identifies such transactions by testing: "if I replace this
/// call with a NoCall (keeping its delay), does the test still fail?"
///
/// When consecutive transactions are converted to NoCalls, they become mergeable
/// via `cat_no_calls`, which sums their delays into a single transaction.
/// This is a *structural* shrink that directly reduces sequence length — something
/// that per-tx `shrink_tx` can never achieve since it works on individual transactions.
///
/// Generates 2 candidates:
/// 1. **Greedy forward scan**: Walk left-to-right, convert each non-last tx to NoCall
///    if the sequence still falsifies the test. This finds the maximal set of
///    convertible txs in O(n) time with a single VM clone.
/// 2. **Random batch conversion**: Pick a random subset of non-last txs and convert
///    them all at once. This explores different conversion combinations that the
///    greedy scan might miss due to ordering dependencies.
fn generate_call_to_delay_candidates<R: Rng>(
    rng: &mut R,
    txs: &[Tx],
    initial_vm: &EvmState,
    test: &EchidnaTest,
    candidates: &mut Vec<Vec<Tx>>,
) {
    let len = txs.len();
    if len <= 2 {
        return;
    }

    // Only try if there are actual calls to convert (not already all NoCalls)
    let real_call_count = txs[..len - 1]
        .iter()
        .filter(|tx| !tx.call.is_no_call())
        .count();
    if real_call_count == 0 {
        return;
    }

    // 1. Greedy forward scan: convert each non-last tx to NoCall if test still fails
    //    Re-executes the full sequence from initial VM for each probe.
    //    For long sequences (>20 txs), only probe a random subset to limit cost.
    {
        let mut candidate = txs.to_vec();
        let max_probes = 20;
        let probe_indices: Vec<usize> = if real_call_count <= max_probes {
            (0..len - 1)
                .filter(|&i| !txs[i].call.is_no_call())
                .collect()
        } else {
            let mut indices: Vec<usize> = (0..len - 1)
                .filter(|&i| !txs[i].call.is_no_call())
                .collect();
            indices.shuffle(rng);
            indices.truncate(max_probes);
            indices.sort(); // process in order for greedy correctness
            indices
        };
        for i in probe_indices {
            if candidate[i].call.is_no_call() {
                continue;
            }
            // Try converting this tx to a NoCall (keeping its delay)
            let original = candidate[i].clone();
            candidate[i] = Tx::no_call(original.src, original.dst, original.delay);

            // Check: does the test still fail with this conversion?
            let mut vm = initial_vm.clone();
            let still_fails = match execute_and_check(&mut vm, &candidate, test) {
                Ok(TestValue::BoolValue(false)) => true,
                _ => false,
            };

            if !still_fails {
                // Revert: this tx's call effect matters
                candidate[i] = original;
            }
        }
        // Only add if we actually converted something
        let converted_count = candidate[..len - 1]
            .iter()
            .zip(txs[..len - 1].iter())
            .filter(|(new, old)| new.call.is_no_call() && !old.call.is_no_call())
            .count();
        if converted_count > 0 {
            candidates.push(candidate);
        }
    }

    // 2. Random batch conversion: convert a random subset of non-last txs
    {
        // Pick ~30-50% of non-last real-call txs to convert
        let convert_prob = rng.gen_range(30..=50) as f64 / 100.0;
        let candidate: Vec<Tx> = txs
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                if i < len - 1 && !tx.call.is_no_call() && rng.gen_bool(convert_prob) {
                    Tx::no_call(tx.src, tx.dst, tx.delay)
                } else {
                    tx.clone()
                }
            })
            .collect();
        candidates.push(candidate);
    }
}

/// Multi-position shorten: try dropping multiple transactions at once
/// More aggressive than single-drop for faster reduction of long sequences
fn multi_shorten_seq<R: Rng>(rng: &mut R, txs: &[Tx]) -> Vec<Tx> {
    if txs.len() <= 2 {
        return shorten_seq(rng, txs);
    }

    // Drop 2-3 transactions at once
    let max_drop = (txs.len() / 3).max(2).min(3);
    let drop_count = rng.gen_range(2..=max_drop);

    // Select random indices to drop
    let mut indices: Vec<usize> = (0..txs.len()).collect();
    indices.shuffle(rng);
    let to_drop: HashSet<usize> = indices.into_iter().take(drop_count).collect();

    txs.iter()
        .enumerate()
        .filter(|(i, _)| !to_drop.contains(i))
        .map(|(_, tx)| tx.clone())
        .collect()
}
