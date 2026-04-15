//! Corpus management and mutation for browser-fuzzer
//!
//! Port of campaign/src/corpus/mutator.rs adapted for single-threaded WASM.

use rand::prelude::*;

use crate::campaign::transaction::{shrink_tx, mutate_tx, Tx};

/// Corpus entry: (priority, sequence)
pub type CorpusEntry = (usize, Vec<Tx>);

/// Mutation constants (c1, c2, c3, c4)
pub type MutationConsts = (f64, f64, f64, f64);

pub const DEFAULT_MUTATION_CONSTS: MutationConsts = (1.0, 1.0, 1.0, 1.0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxsMutation {
    Identity,
    Shrinking,
    Mutation,
    Expansion,
    Swapping,
    Deletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusMutation {
    RandomAppend(TxsMutation),
    RandomPrepend(TxsMutation),
    RandomSplice,
    RandomInterleave,
}

/// Apply a TxsMutation to a transaction list
pub fn mutator<R: Rng>(rng: &mut R, mutation: TxsMutation, txs: &[Tx]) -> Vec<Tx> {
    match mutation {
        TxsMutation::Identity => txs.to_vec(),
        TxsMutation::Shrinking => txs.iter().map(|tx| shrink_tx(rng, tx)).collect(),
        TxsMutation::Mutation => txs.iter().map(|tx| mutate_tx(rng, tx)).collect(),
        TxsMutation::Expansion => expand_rand_list(rng, txs),
        TxsMutation::Swapping => swap_rand_list(rng, txs),
        TxsMutation::Deletion => delete_rand_list(rng, txs),
    }
}

/// Select a random sequence from the corpus (weighted by priority)
pub fn select_from_corpus<R: Rng>(rng: &mut R, corpus: &[CorpusEntry]) -> Vec<Tx> {
    if corpus.is_empty() {
        return Vec::new();
    }
    let total_weight: usize = corpus.iter().map(|(i, _)| *i).sum();
    if total_weight == 0 {
        return corpus[rng.gen_range(0..corpus.len())].1.clone();
    }
    let mut n = rng.gen_range(0..total_weight);
    for (priority, txs) in corpus {
        if n < *priority {
            return txs.clone();
        }
        n -= priority;
    }
    corpus.last().map(|(_, txs)| txs.clone()).unwrap_or_default()
}

/// Select from corpus and apply mutation (strict prefix invariant)
pub fn select_and_mutate<R: Rng>(
    rng: &mut R,
    mutation: TxsMutation,
    corpus: &[CorpusEntry],
) -> Vec<Tx> {
    let rtxs = select_from_corpus(rng, corpus);
    if rtxs.is_empty() {
        return Vec::new();
    }
    // Strict prefix: pick k from 0 to len-1 (never replay full sequence)
    let k = rng.gen_range(0..rtxs.len());
    mutator(rng, mutation, &rtxs[..k])
}

/// Apply a corpus mutation
pub fn apply_corpus_mutation<R: Rng>(
    rng: &mut R,
    mutation: CorpusMutation,
    seq_len: usize,
    corpus: &[CorpusEntry],
    generated_txs: &[Tx],
) -> Vec<Tx> {
    match mutation {
        CorpusMutation::RandomAppend(m) => {
            let mut result = select_and_mutate(rng, m, corpus);
            result.extend_from_slice(generated_txs);
            result.truncate(seq_len);
            result
        }
        CorpusMutation::RandomPrepend(m) => {
            let rtxs = select_and_mutate(rng, m, corpus);
            let k = if seq_len > 0 {
                rng.gen_range(0..seq_len).min(generated_txs.len())
            } else {
                0
            };
            let mut result: Vec<Tx> = generated_txs[..k].to_vec();
            result.extend(rtxs);
            result.truncate(seq_len);
            result
        }
        CorpusMutation::RandomSplice => {
            let rtxs1 = select_from_corpus(rng, corpus);
            let rtxs2 = select_from_corpus(rng, corpus);
            let mut result = splice_at_random(rng, &rtxs1, &rtxs2);
            result.extend_from_slice(generated_txs);
            result.truncate(seq_len);
            result
        }
        CorpusMutation::RandomInterleave => {
            let rtxs1 = select_from_corpus(rng, corpus);
            let rtxs2 = select_from_corpus(rng, corpus);
            let mut result = interleave_at_random(rng, &rtxs1, &rtxs2);
            result.extend_from_slice(generated_txs);
            result.truncate(seq_len);
            result
        }
    }
}

pub fn seq_mutators_stateful<R: Rng>(rng: &mut R, consts: MutationConsts) -> CorpusMutation {
    let (c1, c2, c3, c4) = consts;
    let choices: &[(CorpusMutation, f64)] = &[
        (CorpusMutation::RandomAppend(TxsMutation::Identity), 800.0),
        (CorpusMutation::RandomPrepend(TxsMutation::Identity), 200.0),
        (CorpusMutation::RandomAppend(TxsMutation::Shrinking), c1),
        (CorpusMutation::RandomAppend(TxsMutation::Mutation), c2),
        (CorpusMutation::RandomAppend(TxsMutation::Expansion), c3),
        (CorpusMutation::RandomAppend(TxsMutation::Swapping), c3),
        (CorpusMutation::RandomAppend(TxsMutation::Deletion), c3),
        (CorpusMutation::RandomPrepend(TxsMutation::Shrinking), c1),
        (CorpusMutation::RandomPrepend(TxsMutation::Mutation), c2),
        (CorpusMutation::RandomPrepend(TxsMutation::Expansion), c3),
        (CorpusMutation::RandomPrepend(TxsMutation::Swapping), c3),
        (CorpusMutation::RandomPrepend(TxsMutation::Deletion), c3),
        (CorpusMutation::RandomSplice, c4),
        (CorpusMutation::RandomInterleave, c4),
    ];
    weighted_choose(rng, choices)
}

pub fn seq_mutators_stateless<R: Rng>(rng: &mut R, consts: MutationConsts) -> CorpusMutation {
    let (c1, c2, _, _) = consts;
    let choices: &[(CorpusMutation, f64)] = &[
        (CorpusMutation::RandomAppend(TxsMutation::Identity), 800.0),
        (CorpusMutation::RandomPrepend(TxsMutation::Identity), 200.0),
        (CorpusMutation::RandomAppend(TxsMutation::Shrinking), c1),
        (CorpusMutation::RandomAppend(TxsMutation::Mutation), c2),
        (CorpusMutation::RandomPrepend(TxsMutation::Shrinking), c1),
        (CorpusMutation::RandomPrepend(TxsMutation::Mutation), c2),
    ];
    weighted_choose(rng, choices)
}

fn weighted_choose<R: Rng, T: Copy>(rng: &mut R, choices: &[(T, f64)]) -> T {
    let total: f64 = choices.iter().map(|(_, w)| w).sum();
    let mut n = rng.gen::<f64>() * total;
    for (item, weight) in choices {
        if n < *weight {
            return *item;
        }
        n -= weight;
    }
    choices.last().unwrap().0
}

// =========================================================================
// Array mutation helpers (port of abi/src/mutator_array.rs)
// =========================================================================

/// Expand: duplicate a random element
fn expand_rand_list<R: Rng>(rng: &mut R, list: &[Tx]) -> Vec<Tx> {
    if list.is_empty() {
        return Vec::new();
    }
    let mut result = list.to_vec();
    let idx = rng.gen_range(0..list.len());
    let pos = rng.gen_range(0..=result.len());
    result.insert(pos, list[idx].clone());
    result
}

/// Swap: swap two random elements
fn swap_rand_list<R: Rng>(rng: &mut R, list: &[Tx]) -> Vec<Tx> {
    if list.len() < 2 {
        return list.to_vec();
    }
    let mut result = list.to_vec();
    let i = rng.gen_range(0..list.len());
    let j = rng.gen_range(0..list.len());
    result.swap(i, j);
    result
}

/// Delete: remove a random element
fn delete_rand_list<R: Rng>(rng: &mut R, list: &[Tx]) -> Vec<Tx> {
    if list.is_empty() {
        return Vec::new();
    }
    let mut result = list.to_vec();
    let idx = rng.gen_range(0..result.len());
    result.remove(idx);
    result
}

/// Splice: take prefix of first, suffix of second
fn splice_at_random<R: Rng>(rng: &mut R, a: &[Tx], b: &[Tx]) -> Vec<Tx> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    let split_a = rng.gen_range(0..=a.len());
    let split_b = rng.gen_range(0..=b.len());
    let mut result = a[..split_a].to_vec();
    result.extend_from_slice(&b[split_b..]);
    result
}

/// Interleave: alternate elements from two lists
fn interleave_at_random<R: Rng>(
    rng: &mut R,
    a: &[Tx],
    b: &[Tx],
) -> Vec<Tx> {
    let mut result = Vec::with_capacity(a.len() + b.len());
    let mut ia = 0;
    let mut ib = 0;
    while ia < a.len() && ib < b.len() {
        if rng.gen() {
            result.push(a[ia].clone());
            ia += 1;
        } else {
            result.push(b[ib].clone());
            ib += 1;
        }
    }
    result.extend_from_slice(&a[ia..]);
    result.extend_from_slice(&b[ib..]);
    result
}
