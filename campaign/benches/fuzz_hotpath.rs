//! Benchmarks for the fuzzing hot path — identifies bottlenecks that
//! scale with corpus size, dictionary size, and coverage map size.
//!
//! Run with:
//!   cargo bench -p campaign --bench fuzz_hotpath
//!
//! Key metrics to watch:
//!   - `corpus_clone_sort/*` — O(N) clone + O(N log N) sort per iteration
//!   - `corpus_select/*` — O(N) weighted linear scan per mutation
//!   - `cached_set/*` — O(N) rebuild on dirty flag after insert
//!   - `coverage_read/*` — read lock scan grows with unique PCs
//!   - `dict_add_value/*` — dict growth over campaign lifetime

use std::sync::Arc;
use std::time::Duration;

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{Address, B256, U256};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use parking_lot::RwLock;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

use evm::exec::CoverageMap;
use evm::types::{Tx, TxCall};

type CorpusEntry = (usize, Arc<Vec<Tx>>);

fn make_tx(i: u64) -> Tx {
    Tx {
        call: TxCall::SolCall {
            name: format!("fn_{}", i % 10),
            args: vec![DynSolValue::Uint(U256::from(i), 256)],
        },
        src: Address::repeat_byte(0x01),
        dst: Address::repeat_byte(0x42),
        gas: 1_000_000,
        gasprice: U256::ZERO,
        value: U256::ZERO,
        delay: (i as u64 % 100, i as u64 % 10),
        generate_calls_seed: None,
        generate_calls: Vec::new(),
    }
}

fn make_corpus(size: usize) -> Vec<CorpusEntry> {
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    (0..size)
        .map(|i| {
            let seq_len = rng.gen_range(1..=20);
            let txs: Vec<Tx> = (0..seq_len).map(|j| make_tx((i * 100 + j) as u64)).collect();
            (i + 1, Arc::new(txs))
        })
        .collect()
}

fn make_coverage_map(num_codehashes: usize, pcs_per_codehash: usize) -> CoverageMap {
    let mut map = CoverageMap::default();
    for i in 0..num_codehashes {
        let codehash = B256::repeat_byte(i as u8);
        let pcs = map.entry(codehash).or_default();
        for pc in 0..pcs_per_codehash {
            pcs.insert(pc, (1u64, 1u64));
        }
    }
    map
}

// ---------------------------------------------------------------------------
// 1. Corpus clone + sort — happens every fuzzing iteration
// ---------------------------------------------------------------------------

fn bench_corpus_clone_sort(c: &mut Criterion) {
    let mut group = c.benchmark_group("corpus_clone_sort");
    group.measurement_time(Duration::from_secs(5));

    for size in [10, 100, 500, 1000, 5000] {
        let corpus = make_corpus(size);
        let corpus_ref = Arc::new(RwLock::new(corpus));

        group.bench_with_input(
            BenchmarkId::new("clone_sort", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let corpus = corpus_ref.read();
                    let mut cloned: Vec<CorpusEntry> = corpus.clone();
                    let base_priority = cloned.iter().map(|(p, _)| *p).max().unwrap_or(0) + 1;
                    drop(corpus);
                    black_box(base_priority);
                    cloned.sort_by(|a, b| b.0.cmp(&a.0));
                    black_box(&cloned);
                })
            },
        );

        // Optimization: skip sort if corpus is already sorted (it is — we
        // always insert in priority order)
        let corpus_ref2 = corpus_ref.clone();
        group.bench_with_input(
            BenchmarkId::new("clone_only", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let corpus = corpus_ref2.read();
                    let cloned: Vec<CorpusEntry> = corpus.clone();
                    drop(corpus);
                    black_box(&cloned);
                })
            },
        );

        // Optimization: don't clone at all — read directly from the lock
        let corpus_ref3 = corpus_ref.clone();
        group.bench_with_input(
            BenchmarkId::new("read_no_clone", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let corpus = corpus_ref3.read();
                    let base_priority = corpus.iter().map(|(p, _)| *p).max().unwrap_or(0) + 1;
                    black_box(base_priority);
                    black_box(corpus.len());
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 2. Corpus weighted selection — O(N) linear scan
// ---------------------------------------------------------------------------

fn bench_corpus_select(c: &mut Criterion) {
    let mut group = c.benchmark_group("corpus_select");

    for size in [10, 100, 500, 1000, 5000] {
        let corpus = make_corpus(size);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Current: linear scan weighted selection
        group.bench_with_input(
            BenchmarkId::new("linear_weighted", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let total_weight: usize = corpus.iter().map(|(i, _)| *i).sum();
                    let mut n = rng.gen_range(0..total_weight.max(1));
                    for (priority, txs) in &corpus {
                        if n < *priority {
                            return black_box(txs.clone());
                        }
                        n -= priority;
                    }
                    black_box(corpus.last().unwrap().1.clone())
                })
            },
        );

        // Optimization: uniform random (skip weight computation)
        group.bench_with_input(
            BenchmarkId::new("uniform_random", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let idx = rng.gen_range(0..corpus.len());
                    black_box(corpus[idx].1.clone())
                })
            },
        );

        // Optimization: binary search on prefix sums (O(log N))
        let prefix_sums: Vec<usize> = corpus
            .iter()
            .scan(0usize, |acc, (p, _)| {
                *acc += p;
                Some(*acc)
            })
            .collect();
        let total = *prefix_sums.last().unwrap_or(&1);

        group.bench_with_input(
            BenchmarkId::new("binary_search", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let target = rng.gen_range(0..total);
                    let idx = prefix_sums.partition_point(|&s| s <= target);
                    black_box(corpus[idx.min(corpus.len() - 1)].1.clone())
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 3. CachedSet rebuild — O(N) Vec rebuild on dirty flag
// ---------------------------------------------------------------------------

fn bench_cached_set(c: &mut Criterion) {
    let mut group = c.benchmark_group("cached_set");

    for size in [100, 1000, 5000, 10000, 50000] {
        // Simulate: dict_values with N entries, then random_pick
        let mut set = abi::types::CachedSet::<U256>::new();
        for i in 0..size {
            set.insert(U256::from(i));
        }
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // random_pick when cache is clean (no recent insert)
        group.bench_with_input(
            BenchmarkId::new("pick_clean", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(set.random_pick(&mut rng));
                })
            },
        );

        // random_pick after insert (forces rebuild)
        group.bench_with_input(
            BenchmarkId::new("pick_after_insert", size),
            &size,
            |b, _| {
                let mut s = set.clone();
                b.iter(|| {
                    s.insert(U256::from(rng.gen::<u64>()));
                    black_box(s.random_pick(&mut rng));
                })
            },
        );

        // Optimization: pick from BTreeSet directly using nth (O(N) but no alloc)
        let btree: std::collections::BTreeSet<U256> =
            (0..size).map(|i| U256::from(i)).collect();
        group.bench_with_input(
            BenchmarkId::new("btree_nth", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let idx = rng.gen_range(0..btree.len());
                    black_box(btree.iter().nth(idx));
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 4. Coverage map read — per-tx read lock + scan
// ---------------------------------------------------------------------------

fn bench_coverage_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("coverage_read");

    // Simulate the per-tx coverage check: read lock, check if PC exists
    for total_pcs in [100, 1000, 5000, 10000] {
        let map = make_coverage_map(10, total_pcs / 10);
        let map_ref = Arc::new(RwLock::new(map));

        // Simulate checking a batch of touched PCs (typical: 5-50 per tx)
        let touched_pcs = 20usize;
        let codehash = B256::repeat_byte(0x05); // one of the codehashes

        group.bench_with_input(
            BenchmarkId::new("check_existing", total_pcs),
            &total_pcs,
            |b, _| {
                b.iter(|| {
                    let cov = map_ref.read();
                    for pc in 0..touched_pcs {
                        if let Some(contract_cov) = cov.get(&codehash) {
                            if let Some(&(depths, results)) = contract_cov.get(&pc) {
                                let new = (depths & 1) == 0;
                                black_box(new);
                                let _ = results;
                            }
                        }
                    }
                })
            },
        );

        // Same but with new codehash (miss path)
        let unknown_codehash = B256::repeat_byte(0xff);
        group.bench_with_input(
            BenchmarkId::new("check_miss", total_pcs),
            &total_pcs,
            |b, _| {
                b.iter(|| {
                    let cov = map_ref.read();
                    if let Some(contract_cov) = cov.get(&unknown_codehash) {
                        for pc in 0..touched_pcs {
                            black_box(contract_cov.get(&pc));
                        }
                    }
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 5. Dict add_value — how it scales with dict size
// ---------------------------------------------------------------------------

fn bench_dict_growth(c: &mut Criterion) {
    let mut group = c.benchmark_group("dict_growth");

    for dict_size in [100, 1000, 5000, 10000] {
        // Pre-fill dict to target size
        let mut dict = abi::types::GenDict::new(42);
        for i in 0..dict_size {
            dict.add_value(DynSolValue::Uint(U256::from(i as u64), 256));
        }

        group.bench_with_input(
            BenchmarkId::new("add_new_value", dict_size),
            &dict_size,
            |b, _| {
                let mut d = dict.clone();
                let mut counter = dict_size as u64;
                b.iter(|| {
                    counter += 1;
                    d.add_value(DynSolValue::Uint(U256::from(counter), 256));
                })
            },
        );

        // Adding a duplicate (should be faster with the early-exit optimization)
        group.bench_with_input(
            BenchmarkId::new("add_duplicate", dict_size),
            &dict_size,
            |b, _| {
                let mut d = dict.clone();
                b.iter(|| {
                    d.add_value(DynSolValue::Uint(U256::from(42u64), 256));
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 6. Full per-iteration overhead (corpus + dict, no EVM)
// ---------------------------------------------------------------------------

fn bench_per_iteration_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("per_iteration_overhead");
    group.measurement_time(Duration::from_secs(5));

    for corpus_size in [10, 100, 1000, 5000] {
        let corpus = make_corpus(corpus_size);
        let corpus_ref = Arc::new(RwLock::new(corpus));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Current approach: clone corpus, sort, select, mutate
        group.bench_with_input(
            BenchmarkId::new("current", corpus_size),
            &corpus_size,
            |b, _| {
                b.iter(|| {
                    let corpus = corpus_ref.read();
                    let mut cloned: Vec<CorpusEntry> = corpus.clone();
                    drop(corpus);
                    cloned.sort_by(|a, b| b.0.cmp(&a.0));

                    // weighted selection
                    let total_weight: usize = cloned.iter().map(|(i, _)| *i).sum();
                    if total_weight > 0 {
                        let mut n = rng.gen_range(0..total_weight);
                        for (priority, txs) in &cloned {
                            if n < *priority {
                                return black_box(txs.clone());
                            }
                            n -= priority;
                        }
                    }
                    black_box(cloned.last().unwrap().1.clone())
                })
            },
        );

        // Optimized: read lock, no clone, binary search selection
        let corpus2 = make_corpus(corpus_size);
        let corpus_ref2 = Arc::new(RwLock::new(corpus2));
        group.bench_with_input(
            BenchmarkId::new("optimized", corpus_size),
            &corpus_size,
            |b, _| {
                b.iter(|| {
                    let corpus = corpus_ref2.read();
                    // No clone, no sort — read directly
                    let total_weight: usize = corpus.iter().map(|(i, _)| *i).sum();
                    if total_weight > 0 {
                        let target = rng.gen_range(0..total_weight);
                        let mut acc = 0usize;
                        for (priority, txs) in corpus.iter() {
                            acc += priority;
                            if acc > target {
                                return black_box(txs.clone());
                            }
                        }
                    }
                    black_box(corpus.last().unwrap().1.clone())
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_corpus_clone_sort,
    bench_corpus_select,
    bench_cached_set,
    bench_coverage_read,
    bench_dict_growth,
    bench_per_iteration_overhead,
);
criterion_main!(benches);
