//! Corpus loading and saving
//!
//! Handles loading transaction sequences from disk and saving new coverage to corpus.

use std::sync::Arc;

use evm::types::Tx;

use crate::config::Env;
use crate::output;
use crate::worker_env::{CorpusEntry, WorkerEnv};

/// HEVM cheatcode address - transactions to this address should not be retargeted
pub const HEVM_ADDRESS: alloy_primitives::Address = alloy_primitives::Address::new([
    0x71, 0x09, 0x70, 0x9E, 0xCf, 0xa9, 0x1a, 0x80, 0x62, 0x6f, 0xF3, 0x98, 0x9D, 0x68, 0xf6, 0x7F,
    0x5b, 0x1D, 0xD1, 0x2D,
]);

/// Load corpus from disk
/// Returns sequences with priority 1 (lowest) since we don't know their original discovery order
pub fn load_corpus(env: &Env) -> anyhow::Result<Vec<CorpusEntry>> {
    let target_address = env.cfg.sol_conf.contract_addr;
    let mut corpus = Vec::new();
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("echidna"));

    // Load from reproducers subdirectory
    let reproducers_dir = corpus_dir.join("reproducers");
    if reproducers_dir.exists() {
        let loaded = load_txs_from_dir(&reproducers_dir, target_address)?;
        println!(
            "Loaded {} transaction sequences from {}",
            loaded.len(),
            reproducers_dir.display()
        );
        // Assign priority 1 to all loaded sequences (lowest priority)
        // New discoveries during fuzzing will get higher priority
        // Wrap in Arc for cheap cloning during corpus mutation
        corpus.extend(loaded.into_iter().map(|txs| (1, Arc::new(txs))));
    }

    // Load from coverage subdirectory
    let coverage_dir = corpus_dir.join("coverage");
    if coverage_dir.exists() {
        let loaded = load_txs_from_dir(&coverage_dir, target_address)?;
        println!(
            "Loaded {} transaction sequences from {}",
            loaded.len(),
            coverage_dir.display()
        );
        corpus.extend(loaded.into_iter().map(|txs| (1, Arc::new(txs))));
    }

    Ok(corpus)
}

/// Load reproducers from disk for shrink-only mode
/// Loads from both `reproducers-unshrunk/` and `reproducers/` directories
/// Returns just the sequences (no priority needed for shrinking)
pub fn load_reproducers_for_shrinking(
    corpus_dir: &std::path::Path,
    target_address: alloy_primitives::Address,
) -> anyhow::Result<Vec<Vec<Tx>>> {
    let mut all_sequences = Vec::new();

    // Load from reproducers-unshrunk/ first (primary source)
    let unshrunk_dir = corpus_dir.join("reproducers-unshrunk");
    if unshrunk_dir.exists() {
        let loaded = load_txs_from_dir(&unshrunk_dir, target_address)?;
        println!(
            "Loaded {} unshrunk reproducers from {}",
            loaded.len(),
            unshrunk_dir.display()
        );
        all_sequences.extend(loaded);
    }

    // Also load from reproducers/ (may contain partially shrunk or unshrunk ones)
    let reproducers_dir = corpus_dir.join("reproducers");
    if reproducers_dir.exists() {
        let loaded = load_txs_from_dir(&reproducers_dir, target_address)?;
        println!(
            "Loaded {} reproducers from {}",
            loaded.len(),
            reproducers_dir.display()
        );
        all_sequences.extend(loaded);
    }

    if all_sequences.is_empty() {
        println!("No reproducers found in {} - nothing to shrink", corpus_dir.display());
    }

    Ok(all_sequences)
}

/// Load transaction sequences from a directory
///
/// Sanitizes loaded transactions:
/// - Sets gasprice to 0 to avoid funding issues
/// - Retargets transactions to current target_address (except HEVM cheatcode calls)
pub fn load_txs_from_dir(
    dir: &std::path::Path,
    target_address: alloy_primitives::Address,
) -> anyhow::Result<Vec<Vec<Tx>>> {
    let mut corpus = Vec::new();

    if !dir.exists() {
        return Ok(corpus);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // Accept both .txt and .json extensions (Echidna uses .txt)
        if path
            .extension()
            .map_or(false, |ext| ext == "txt" || ext == "json")
        {
            let content = std::fs::read_to_string(&path)?;
            match serde_json::from_str::<Vec<Tx>>(&content) {
                Ok(mut txs) => {
                    // Sanitize transactions
                    for tx in &mut txs {
                        // Ensure gasprice is 0 to avoid funding issues
                        tx.gasprice = alloy_primitives::U256::ZERO;

                        // Retarget to current contract address
                        // EXCEPT for HEVM cheatcode calls which must stay on HEVM address
                        if tx.dst != HEVM_ADDRESS {
                            tx.dst = target_address;
                        }
                    }
                    corpus.push(txs);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse corpus file {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(corpus)
}

/// Add a sequence to the corpus and save it to disk (WorkerEnv variant)
/// Every sequence that finds new coverage is added with its ncallseqs as priority
/// This allows corpus to grow when we find the same instruction at different depths/results
/// Returns true if the sequence was new and added
pub fn add_to_corpus_worker(env: &WorkerEnv, tx_seq: Vec<Tx>, ncallseqs: usize) -> bool {
    if tx_seq.is_empty() {
        return false;
    }

    // Hash the sequence for deduplication (avoid adding exact duplicates)
    let seq_hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        if let Ok(json) = serde_json::to_string(&tx_seq) {
            json.hash(&mut hasher);
        }
        hasher.finish()
    };

    // Check if we've seen this exact sequence before
    {
        let mut seen = env.corpus_seen.write();
        if !seen.insert(seq_hash) {
            tracing::debug!("Skipping corpus - duplicate sequence");
            return false;
        }
    }

    // New sequence - add to corpus with ncallseqs as priority 
    // Higher priority = discovered later = more interesting (selected more often)
    // Note: callers pass the already-incremented ncallseqs value
    // Wrap in Arc for cheap cloning during corpus mutation selection
    let priority = ncallseqs;
    {
        let mut corpus = env.corpus_ref.write();
        corpus.push((priority, Arc::new(tx_seq.clone())));
        tracing::debug!("Corpus size: {} (added with priority {})", corpus.len(), priority);
    }

    if let Err(e) = save_coverage_sequence_worker(env, &tx_seq) {
        tracing::error!("Failed to save coverage sequence: {}", e);
    }

    true
}

/// Save a coverage sequence to disk (WorkerEnv variant)
pub fn save_coverage_sequence_worker(env: &WorkerEnv, tx_seq: &[Tx]) -> anyhow::Result<()> {
    let corpus_dir = env
        .cfg
        .campaign_conf
        .corpus_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("echidna"));

    let coverage_dir = corpus_dir.join("coverage");
    std::fs::create_dir_all(&coverage_dir)?;

    let json = serde_json::to_string_pretty(tx_seq)?;

    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    json.hash(&mut hasher);
    let hash = hasher.finish();

    let filename = coverage_dir.join(format!("{}.txt", hash));

    if !filename.exists() {
        std::fs::write(&filename, &json)?;
        println!(
            "{} Saved reproducer to {}",
            output::format_timestamp(),
            filename.display()
        );
    }

    Ok(())
}
