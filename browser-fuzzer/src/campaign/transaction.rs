//! Transaction generation, shrinking, and mutation for browser-fuzzer
//!
//! Uses the full abi module for exact mutation/shrink parity with main fuzzer.

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_json_abi::Function;
use alloy_primitives::{Address, Bytes, U256};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use crate::abi::types::CachedSet;

use crate::abi::mutate::mutate_call_enhanced;
use crate::abi::mutable::Mutable;
use crate::abi::shrink::{shrink_call as abi_shrink_call, can_shrink as abi_can_shrink};
use crate::abi::types::GenDict;
use crate::evm::exec::DEFAULT_SENDERS;

// =========================================================================
// Tx
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx {
    pub function_name: String,
    pub selector: [u8; 4],
    pub calldata: Bytes,
    pub sender: Address,
    pub target: Address,
    pub value: U256,
    pub delay: (u64, u64), // (time_seconds, blocks)
    /// Decoded arguments (for shrinking/mutation)
    /// Matches main fuzzer's TxCall::SolCall { name, args }
    #[serde(skip)]
    pub args: Vec<DynSolValue>,
}

impl Tx {
    pub fn no_call(sender: Address, target: Address, delay: (u64, u64)) -> Self {
        Self {
            function_name: String::new(),
            selector: [0; 4],
            calldata: Bytes::new(),
            sender,
            target,
            value: U256::ZERO,
            delay,
            args: Vec::new(),
        }
    }

    pub fn is_no_call(&self) -> bool {
        self.calldata.is_empty() && self.function_name.is_empty()
    }

    /// Re-encode calldata from args (after mutation/shrink)
    fn re_encode(&mut self) {
        if self.args.is_empty() {
            self.calldata = Bytes::from(self.selector.to_vec());
            return;
        }
        let encoded_args = DynSolValue::Tuple(self.args.clone()).abi_encode();
        let mut calldata = self.selector.to_vec();
        calldata.extend(encoded_args);
        self.calldata = Bytes::from(calldata);
    }
}

// =========================================================================
// gen_abi_call_m — uses abi::gen
// =========================================================================

/// Generate a random function call using the full abi::gen module.
/// Accepts pre-cached param types to avoid re-parsing on every call (matches main fuzzer pattern).
/// Generate a random function call using gen_abi_call_m.
/// Accepts pre-cached param types to avoid re-parsing on every call (matches main fuzzer pattern).
fn gen_abi_call_for_func<R: Rng>(
    rng: &mut R,
    dict: &GenDict,
    func: &Function,
    cached_param_types: Option<&[DynSolType]>,
) -> (String, Vec<DynSolValue>) {
    let param_types: Vec<DynSolType> = match cached_param_types {
        Some(types) => types.to_vec(),
        None => func
            .inputs
            .iter()
            .filter_map(|p| p.ty.parse().ok())
            .collect(),
    };

    // Matches main fuzzer: gen_abi_call_m(rng, dict, &func.name, param_types)
    crate::abi::gen::gen_abi_call_m(rng, dict, &func.name, &param_types)
}

// =========================================================================
// Transaction generation
// =========================================================================

/// Generate a random transaction for a random fuzzable function.
/// If `param_types_lookup` is provided, uses pre-cached types instead of re-parsing.
/// This matches the main fuzzer pattern: `contract.get_param_types(&selector)`.
pub fn gen_tx<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    fuzzable_funcs: &[Function],
    contract_addr: Address,
    max_value: U256,
    max_time_delay: u64,
    max_block_delay: u64,
    param_types_lookup: Option<&std::collections::HashMap<alloy_primitives::FixedBytes<4>, Vec<DynSolType>>>,
) -> Option<Tx> {
    if fuzzable_funcs.is_empty() {
        return None;
    }

    let sender = DEFAULT_SENDERS[rng.gen_range(0..DEFAULT_SENDERS.len())];
    let func = &fuzzable_funcs[rng.gen_range(0..fuzzable_funcs.len())];

    // Use pre-cached param types if available (matches main fuzzer)
    let cached = param_types_lookup
        .and_then(|m| m.get(&func.selector()))
        .map(|v| v.as_slice());

    let (name, args) = gen_abi_call_for_func(rng, dict, func, cached);

    // Encode calldata
    let selector = func.selector();
    let encoded_args = if args.is_empty() {
        vec![]
    } else {
        DynSolValue::Tuple(args.clone()).abi_encode()
    };
    let mut calldata = selector.to_vec();
    calldata.extend(encoded_args);

    let value = gen_value(rng, max_value, &mut dict.dict_values, func);
    let delay = gen_delay(rng, max_time_delay, max_block_delay, &mut dict.dict_values);

    Some(Tx {
        function_name: name,
        selector: selector.0,
        calldata: Bytes::from(calldata),
        sender,
        target: contract_addr,
        value,
        delay,
        args,
    })
}

/// Generate a random sequence of transactions
pub fn rand_seq<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    fuzzable_funcs: &[Function],
    contract_addr: Address,
    seq_len: usize,
    max_value: U256,
    max_time_delay: u64,
    max_block_delay: u64,
    param_types_lookup: Option<&std::collections::HashMap<alloy_primitives::FixedBytes<4>, Vec<DynSolType>>>,
) -> Vec<Tx> {
    (0..seq_len)
        .filter_map(|_| {
            gen_tx(
                rng, dict, fuzzable_funcs, contract_addr,
                max_value, max_time_delay, max_block_delay,
                param_types_lookup,
            )
        })
        .collect()
}

// =========================================================================
// Value / delay generation (from campaign/src/transaction.rs)
// =========================================================================

fn gen_value<R: Rng>(
    rng: &mut R,
    max_value: U256,
    dict_values: &mut CachedSet<U256>,
    func: &Function,
) -> U256 {
    let is_payable = matches!(func.state_mutability, alloy_json_abi::StateMutability::Payable);
    if is_payable {
        if often_usually_bool(rng) {
            from_dict_value(rng, dict_values, max_value)
        } else {
            gen_random_value(rng, max_value)
        }
    } else {
        if usually_very_rarely_bool(rng) {
            U256::ZERO
        } else {
            gen_random_value(rng, max_value)
        }
    }
}

fn from_dict_value<R: Rng>(rng: &mut R, dict_values: &mut CachedSet<U256>, max: U256) -> U256 {
    if dict_values.is_empty() {
        return gen_random_value(rng, max);
    }
    let picked = *dict_values.random_pick(rng).unwrap();
    if max.is_zero() { U256::ZERO } else { picked % (max + U256::from(1)) }
}

fn gen_random_value<R: Rng>(rng: &mut R, max: U256) -> U256 {
    if max.is_zero() { return U256::ZERO; }
    let random_bytes: [u8; 32] = rng.gen();
    U256::from_be_bytes(random_bytes) % (max + U256::from(1))
}

fn gen_delay<R: Rng>(
    rng: &mut R,
    max_time: u64,
    max_block: u64,
    dict_values: &mut CachedSet<U256>,
) -> (u64, u64) {
    let time = gen_single_delay(rng, max_time, dict_values);
    let block = gen_single_delay(rng, max_block, dict_values);
    if time == 0 || block == 0 { (0, 0) } else { (time, block) }
}

fn gen_single_delay<R: Rng>(rng: &mut R, max: u64, dict_values: &mut CachedSet<U256>) -> u64 {
    if max == 0 { return 0; }
    if often_usually_bool(rng) && !dict_values.is_empty() {
        let picked = *dict_values.random_pick(rng).unwrap();
        let as_u64: u64 = picked.try_into().unwrap_or(u64::MAX);
        as_u64 % (max + 1)
    } else {
        rng.gen_range(1..=max)
    }
}

fn often_usually_bool<R: Rng>(rng: &mut R) -> bool { rng.gen_ratio(11, 12) }
fn usually_rarely_bool<R: Rng>(rng: &mut R) -> bool { rng.gen_ratio(101, 102) }
fn usually_very_rarely_bool<R: Rng>(rng: &mut R) -> bool { rng.gen_ratio(1001, 1002) }

// =========================================================================
// Shrinking — uses full abi::shrink module
// =========================================================================

/// Shrink a transaction using the full abi shrink module
pub fn shrink_tx<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    if usually_rarely_bool(rng) {
        // 99%: normal shrink strategies
        let mut strategies: Vec<Box<dyn Fn(&mut R, &Tx) -> Tx>> = Vec::new();

        if !tx.value.is_zero() {
            strategies.push(Box::new(shrink_value));
        }
        if tx.delay != (0, 0) {
            strategies.push(Box::new(shrink_delay));
        }
        // Use abi::shrink for calldata shrinking
        if !tx.args.is_empty() && tx.args.iter().any(abi_can_shrink) {
            strategies.push(Box::new(shrink_calldata));
        }

        if strategies.is_empty() {
            return tx.clone();
        }
        let idx = rng.gen_range(0..strategies.len());
        strategies[idx](rng, tx)
    } else {
        // 1%: remove call
        Tx::no_call(tx.sender, tx.target, tx.delay)
    }
}

fn shrink_value<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    Tx {
        value: lower_u256(rng, tx.value),
        ..tx.clone()
    }
}

fn lower_u256<R: Rng>(rng: &mut R, x: U256) -> U256 {
    if x.is_zero() { return U256::ZERO; }
    let r = gen_random_value(rng, x);
    if rng.gen() { U256::ZERO } else { r }
}

fn lower_u64<R: Rng>(rng: &mut R, x: u64) -> u64 {
    if x == 0 { return 0; }
    let strategy = rng.gen_range(0..10);
    match strategy {
        0..=4 => {
            let max_depth = 64 - x.leading_zeros() as u32;
            let depth = rng.gen_range(0..=max_depth);
            if depth == 0 { 0 } else { x.saturating_sub(x >> depth) }
        }
        5 | 6 => {
            const BOUNDARIES: [u64; 7] = [1, 60, 3600, 86400, 604800, 2592000, 31536000];
            let valid: Vec<u64> = BOUNDARIES.iter().copied().filter(|&b| b < x).collect();
            if valid.is_empty() { x / 2 } else { valid[rng.gen_range(0..valid.len())] }
        }
        _ => {
            let r = rng.gen_range(0..=x);
            if rng.gen() { 0 } else { r }
        }
    }
}

fn shrink_delay<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    let (time, blocks) = tx.delay;
    let new_delay = match rng.gen_range(0..7) {
        0 => (time, lower_u64(rng, blocks)),
        1 => (lower_u64(rng, time), blocks),
        2 | 3 => (lower_u64(rng, time), lower_u64(rng, blocks)),
        4 => { if rng.gen() { (0, blocks) } else { (time, 0) } }
        5 => {
            if blocks == 0 || time == 0 {
                (lower_u64(rng, time), lower_u64(rng, blocks))
            } else {
                let factor = rng.gen_range(2..=8u64);
                (time / factor, blocks / factor)
            }
        }
        _ => (0, 0),
    };
    Tx { delay: new_delay, ..tx.clone() }
}

/// Shrink calldata using abi::shrink::shrink_call
fn shrink_calldata<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    let (_, shrunk_args) = abi_shrink_call(rng, &tx.function_name, &tx.args);
    let mut result = tx.clone();
    result.args = shrunk_args;
    result.re_encode();
    result
}

// =========================================================================
// Mutation — uses full abi::mutate module (AFL++ strategies)
// =========================================================================

/// Mutate a transaction using the full abi mutation module
pub fn mutate_tx<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    let mut result = tx.clone();

    // Mutate args using abi::mutate::mutate_call_enhanced (10% per arg via Mutable trait)
    if !result.args.is_empty() {
        let (_, mutated_args) = mutate_call_enhanced(rng, &result.function_name, &result.args);
        result.args = mutated_args;
        result.re_encode();
    }

    // Mutate value (10% chance)
    if rng.gen_ratio(1, 10) {
        result.value = mutate_tx_value(rng, result.value);
    }

    // Mutate delay using Mutable trait (10% chance)
    if rng.gen_ratio(1, 10) {
        result.delay.mutate(rng);
    }

    result
}

fn mutate_tx_value<R: Rng>(rng: &mut R, value: U256) -> U256 {
    let max_value = U256::from(10000u64) * U256::from(10u64).pow(U256::from(18u64));
    match rng.gen_range(0..8) {
        0 => U256::ZERO,
        1 => U256::from(1u64),
        2 => U256::from(10u64).pow(U256::from(18u64)),
        3 => value.saturating_add(U256::from(rng.gen_range(1u64..=1000))),
        4 => value.saturating_sub(U256::from(rng.gen_range(1u64..=1000))),
        5 => {
            let eth = U256::from(rng.gen_range(1u64..=10)) * U256::from(10u64).pow(U256::from(18u64));
            if rng.gen() { value.saturating_add(eth) } else { value.saturating_sub(eth) }
        }
        6 => {
            let random_bytes: [u8; 32] = rng.gen();
            U256::from_be_bytes(random_bytes) % (max_value + U256::from(1u64))
        }
        _ => value / U256::from(2u64),
    }.min(max_value)
}
