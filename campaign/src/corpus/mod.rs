//! Corpus management module
//!
//! Rust equivalent of Echidna's Mutator/Corpus.hs
//! Contains corpus loading, saving, and mutation strategies.

mod loader;
mod mutator;

// Re-export all public items from loader
pub use loader::{add_to_corpus_worker, load_corpus, load_reproducers_for_shrinking, save_coverage_sequence_worker, HEVM_ADDRESS};

// Re-export all public items from mutator
pub use mutator::{
    apply_corpus_mutation, mutator, select_and_mutate, select_from_corpus, seq_mutators_stateful,
    seq_mutators_stateless, CorpusMutation, MutationConsts, TxsMutation, DEFAULT_MUTATION_CONSTS,
};
