//! Corpus mutation strategies
//!
//! Rust equivalent of Echidna's Mutator/Corpus.hs

use std::sync::Arc;

use evm::types::Tx;
use rand::prelude::*;

use crate::transaction::{mutate_tx, shrink_tx};
use crate::worker_env::CorpusEntry;

/// Mutation constants (c1, c2, c3, c4)
pub type MutationConsts = (f64, f64, f64, f64);

pub const DEFAULT_MUTATION_CONSTS: MutationConsts = (1.0, 1.0, 1.0, 1.0);

/// Types of transaction list mutations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxsMutation {
    Identity,
    Shrinking,
    Mutation,
    Expansion,
    Swapping,
    Deletion,
}

/// Types of corpus mutations
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
/// Returns Arc<Vec<Tx>> to avoid cloning the transaction data
pub fn select_from_corpus<R: Rng>(rng: &mut R, corpus: &[CorpusEntry]) -> Arc<Vec<Tx>> {
    if corpus.is_empty() {
        return Arc::new(Vec::new());
    }
    // Weighted selection by priority (higher priority = more likely)
    let total_weight: usize = corpus.iter().map(|(i, _)| *i).sum();
    if total_weight == 0 {
        return corpus[rng.gen_range(0..corpus.len())].1.clone();
    }
    let mut n = rng.gen_range(0..total_weight);
    for (priority, txs) in corpus {
        if n < *priority {
            return txs.clone(); // Arc clone is cheap (just ref count increment)
        }
        n -= priority;
    }
    corpus
        .last()
        .map(|(_, txs)| txs.clone())
        .unwrap_or_else(|| Arc::new(Vec::new()))
}

/// Select from corpus and apply mutation
pub fn select_and_mutate<R: Rng>(
    rng: &mut R,
    mutation: TxsMutation,
    corpus: &[CorpusEntry],
) -> Vec<Tx> {
    let rtxs = select_from_corpus(rng, corpus);
    if rtxs.is_empty() {
        return Vec::new();
    }
    // Echidna picks k from 0 to length-1, and takes k items
    // This implies taking a STRICT prefix (0 to len-1 items)
    // It can take 0 items (empty list) or up to len-1 items
    // This forces branching from intermediate states or starting fresh
    let k = rng.gen_range(0..rtxs.len());
    mutator(rng, mutation, &rtxs[..k])
}

/// Get the corpus mutation function
pub fn apply_corpus_mutation<R: Rng>(
    rng: &mut R,
    mutation: CorpusMutation,
    seq_len: usize,
    corpus: &[CorpusEntry],
    generated_txs: &[Tx],
) -> Vec<Tx> {
    match mutation {
        CorpusMutation::RandomAppend(m) => {
            let rtxs = select_and_mutate(rng, m, corpus);
            let mut result = rtxs;
            result.extend_from_slice(generated_txs);
            result.truncate(seq_len);
            result
        }
        CorpusMutation::RandomPrepend(m) => {
            let rtxs = select_and_mutate(rng, m, corpus);
            // k <- getRandomR (0, ql - 1) - range is 0 to seq_len-1 (exclusive of ql)
            // This ensures we never take ALL of generated_txs, leaving room for corpus prefix
            let k = if seq_len > 0 { rng.gen_range(0..seq_len) } else { 0 };
            let k = k.min(generated_txs.len());
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

/// Generate a random corpus mutation (stateful version, for seqLen > 1)
/// Weights exactly match Echidna to prioritize replaying successful sequences
pub fn seq_mutators_stateful<R: Rng>(rng: &mut R, consts: MutationConsts) -> CorpusMutation {
    let (c1, c2, c3, c4) = consts;

    // Echidna-exact weights from Mutator/Corpus.hs:92-110
    // High Identity weight (800) ensures we replay corpus sequences reliably
    // This is crucial for multi-step bug discovery (e.g., deposit -> allocate -> break)
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

/// Generate a random corpus mutation (stateless version, for seqLen == 1)
/// Weights exactly match Echidna from Mutator/Corpus.hs:116-124
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

// Array mutation helpers (from Mutator/Array.hs) implemented in recon-abi
use abi::mutator_array::{
    delete_rand_list, expand_rand_list, interleave_at_random, splice_at_random, swap_rand_list,
};
