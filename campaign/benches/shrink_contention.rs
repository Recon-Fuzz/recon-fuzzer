//! Benchmark: how does one worker shrinking affect other workers' throughput?
//!
//! Simulates the real scenario: N worker threads doing fuzzing (vm.clone +
//! exec_tx_check_new_cov per sequence) while 0 or 1 threads do shrinking
//! (vm.clone + replay full sequence via exec_tx, with write lock on test_ref).
//!
//! Run with:
//!   cargo bench -p campaign --bench shrink_contention
//!
//! What to look for:
//!   - Compare `fuzz_only/4` vs `fuzz_with_shrink/3+1` — if the per-worker
//!     throughput drops significantly in the second case, there's contention.
//!   - The `contention_source/*` group isolates individual shared resources
//!     to find which lock is the bottleneck.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::{Address, Bytes, U256};
use criterion::{criterion_group, criterion_main, Criterion};
use parking_lot::RwLock;

use evm::coverage::MetadataToCodehash;
use evm::exec::{CoverageMap, EvmState};
use evm::types::{Tx, TxCall};

// Counter contract: SLOAD slot0, ADD 1, SSTORE slot0, STOP
const COUNTER_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x54, 0x01, 0x60, 0x00, 0x55, 0x00];
const CONTRACT_ADDR: Address = Address::repeat_byte(0x42);
const SENDER: Address = Address::repeat_byte(0x01);

fn make_vm() -> EvmState {
    let mut vm = EvmState::new();
    vm.set_code(CONTRACT_ADDR, Bytes::from_static(COUNTER_BYTECODE));
    vm.fund_account(SENDER, U256::MAX / U256::from(2u64));
    vm
}

fn make_tx() -> Tx {
    Tx {
        call: TxCall::SolCalldata(Bytes::new()),
        src: SENDER,
        dst: CONTRACT_ADDR,
        gas: 1_000_000,
        gasprice: U256::ZERO,
        value: U256::ZERO,
        delay: (0, 0),
        generate_calls_seed: None,
        generate_calls: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Simulate fuzzing worker: clone VM, execute sequence, check coverage
// ---------------------------------------------------------------------------

fn fuzz_iteration(
    initial_vm: &EvmState,
    tx: &Tx,
    seq_len: usize,
    coverage_ref: &Arc<RwLock<CoverageMap>>,
    codehash_map: &Arc<RwLock<MetadataToCodehash>>,
) {
    let mut vm = initial_vm.clone();
    for _ in 0..seq_len {
        let _ = vm.exec_tx_check_new_cov(tx, coverage_ref, codehash_map);
    }
}

// ---------------------------------------------------------------------------
// Simulate shrinking worker: clone VM, replay sequence via exec_tx (no cov),
// hold a write lock on a shared RwLock (simulates test_ref.write())
// ---------------------------------------------------------------------------

fn shrink_iteration_old(
    initial_vm: &EvmState,
    tx: &Tx,
    seq_len: usize,
    test_lock: &Arc<RwLock<u64>>,
) {
    // OLD: hold write lock for the entire shrink validation
    let mut test = test_lock.write();
    for _candidate in 0..10 {
        let mut vm = initial_vm.clone();
        for _ in 0..seq_len {
            let _ = vm.exec_tx(tx);
        }
    }
    *test += 1;
}

fn shrink_iteration_fixed(
    initial_vm: &EvmState,
    tx: &Tx,
    seq_len: usize,
    test_lock: &Arc<RwLock<u64>>,
) {
    // FIXED: snapshot under read lock, do heavy work unlocked, brief write to commit
    let _snapshot = { *test_lock.read() };
    for _candidate in 0..10 {
        let mut vm = initial_vm.clone();
        for _ in 0..seq_len {
            let _ = vm.exec_tx(tx);
        }
    }
    // Brief write lock to commit result
    *test_lock.write() += 1;
}

// ---------------------------------------------------------------------------
// Measure: fuzz-only throughput (all workers fuzzing)
// ---------------------------------------------------------------------------

fn bench_fuzz_only(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx();
    let coverage = Arc::new(RwLock::new(CoverageMap::default()));
    let codehash = Arc::new(RwLock::new(MetadataToCodehash::default()));

    let mut group = c.benchmark_group("fuzz_only");
    group.measurement_time(Duration::from_secs(10));

    for num_workers in [1, 2, 4] {
        group.bench_function(format!("{}_workers", num_workers), |b| {
            b.iter_custom(|iters| {
                let counter = Arc::new(AtomicUsize::new(0));
                let stop = Arc::new(AtomicBool::new(false));

                let handles: Vec<_> = (0..num_workers)
                    .map(|_| {
                        let vm = vm.clone();
                        let tx = tx.clone();
                        let cov = coverage.clone();
                        let ch = codehash.clone();
                        let counter = counter.clone();
                        let stop = stop.clone();
                        std::thread::spawn(move || {
                            while !stop.load(Ordering::Relaxed) {
                                fuzz_iteration(&vm, &tx, 10, &cov, &ch);
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                        })
                    })
                    .collect();

                // Let it run for `iters` total sequences across all workers
                let start = Instant::now();
                while counter.load(Ordering::Relaxed) < iters as usize {
                    std::thread::yield_now();
                }
                let elapsed = start.elapsed();

                stop.store(true, Ordering::Relaxed);
                for h in handles {
                    let _ = h.join();
                }
                elapsed
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Measure: fuzz + shrink throughput (N-1 fuzzing, 1 shrinking)
// ---------------------------------------------------------------------------

fn bench_fuzz_with_shrink(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx();
    let coverage = Arc::new(RwLock::new(CoverageMap::default()));
    let codehash = Arc::new(RwLock::new(MetadataToCodehash::default()));
    let test_lock = Arc::new(RwLock::new(0u64));

    let mut group = c.benchmark_group("fuzz_with_shrink");
    group.measurement_time(Duration::from_secs(10));

    // OLD: 3 fuzzing + 1 shrinking with write lock held during validation
    group.bench_function("3_fuzz_1_shrink_old", |b| {
        b.iter_custom(|iters| {
            let fuzz_counter = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));

            let fuzz_handles: Vec<_> = (0..3)
                .map(|_| {
                    let vm = vm.clone();
                    let tx = tx.clone();
                    let cov = coverage.clone();
                    let ch = codehash.clone();
                    let counter = fuzz_counter.clone();
                    let stop = stop.clone();
                    let tl = test_lock.clone();
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            let _ = *tl.read();
                            fuzz_iteration(&vm, &tx, 10, &cov, &ch);
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();

            let shrink_stop = stop.clone();
            let shrink_vm = vm.clone();
            let shrink_tx = tx.clone();
            let shrink_lock = test_lock.clone();
            let shrink_handle = std::thread::spawn(move || {
                while !shrink_stop.load(Ordering::Relaxed) {
                    shrink_iteration_old(&shrink_vm, &shrink_tx, 10, &shrink_lock);
                }
            });

            let start = Instant::now();
            while fuzz_counter.load(Ordering::Relaxed) < iters as usize {
                std::thread::yield_now();
            }
            let elapsed = start.elapsed();

            stop.store(true, Ordering::Relaxed);
            for h in fuzz_handles {
                let _ = h.join();
            }
            let _ = shrink_handle.join();
            elapsed
        });
    });

    // FIXED: 3 fuzzing + 1 shrinking with snapshot pattern (no lock during validation)
    group.bench_function("3_fuzz_1_shrink_fixed", |b| {
        let test_lock2 = Arc::new(RwLock::new(0u64));
        b.iter_custom(|iters| {
            let fuzz_counter = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));

            let fuzz_handles: Vec<_> = (0..3)
                .map(|_| {
                    let vm = vm.clone();
                    let tx = tx.clone();
                    let cov = coverage.clone();
                    let ch = codehash.clone();
                    let counter = fuzz_counter.clone();
                    let stop = stop.clone();
                    let tl = test_lock2.clone();
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            let _ = *tl.read();
                            fuzz_iteration(&vm, &tx, 10, &cov, &ch);
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();

            let shrink_stop = stop.clone();
            let shrink_vm = vm.clone();
            let shrink_tx = tx.clone();
            let shrink_lock = test_lock2.clone();
            let shrink_handle = std::thread::spawn(move || {
                while !shrink_stop.load(Ordering::Relaxed) {
                    shrink_iteration_fixed(&shrink_vm, &shrink_tx, 10, &shrink_lock);
                }
            });

            let start = Instant::now();
            while fuzz_counter.load(Ordering::Relaxed) < iters as usize {
                std::thread::yield_now();
            }
            let elapsed = start.elapsed();

            stop.store(true, Ordering::Relaxed);
            for h in fuzz_handles {
                let _ = h.join();
            }
            let _ = shrink_handle.join();
            elapsed
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Isolate contention sources: which shared resource is the bottleneck?
// ---------------------------------------------------------------------------

fn bench_contention_sources(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx();

    let mut group = c.benchmark_group("contention_source");
    group.measurement_time(Duration::from_secs(10));

    // Test 1: Coverage map write contention
    // All 4 threads doing exec_tx_check_new_cov (all write to same coverage map)
    group.bench_function("coverage_map_4_writers", |b| {
        let coverage = Arc::new(RwLock::new(CoverageMap::default()));
        let codehash = Arc::new(RwLock::new(MetadataToCodehash::default()));
        b.iter_custom(|iters| {
            let counter = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));

            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let vm = vm.clone();
                    let tx = tx.clone();
                    let cov = coverage.clone();
                    let ch = codehash.clone();
                    let counter = counter.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            fuzz_iteration(&vm, &tx, 10, &cov, &ch);
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();

            let start = Instant::now();
            while counter.load(Ordering::Relaxed) < iters as usize {
                std::thread::yield_now();
            }
            let elapsed = start.elapsed();
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                let _ = h.join();
            }
            elapsed
        });
    });

    // Test 2: No shared coverage — each worker has its own coverage map
    // This isolates whether the coverage map lock is the bottleneck
    group.bench_function("coverage_map_4_independent", |b| {
        let codehash = Arc::new(RwLock::new(MetadataToCodehash::default()));
        b.iter_custom(|iters| {
            let counter = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));

            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let vm = vm.clone();
                    let tx = tx.clone();
                    // Each worker gets its OWN coverage map — no contention
                    let cov = Arc::new(RwLock::new(CoverageMap::default()));
                    let ch = codehash.clone();
                    let counter = counter.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            fuzz_iteration(&vm, &tx, 10, &cov, &ch);
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();

            let start = Instant::now();
            while counter.load(Ordering::Relaxed) < iters as usize {
                std::thread::yield_now();
            }
            let elapsed = start.elapsed();
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                let _ = h.join();
            }
            elapsed
        });
    });

    // Test 3: RwLock contention — heavy writer vs readers
    // Simulates shrink_pending_tests_worker holding write lock
    // while fuzzing workers try to read test_refs every iteration
    group.bench_function("rwlock_heavy_writer", |b| {
        let lock = Arc::new(RwLock::new(0u64));
        b.iter_custom(|iters| {
            let counter = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));

            // 3 readers (fuzzing workers checking test state)
            let reader_handles: Vec<_> = (0..3)
                .map(|_| {
                    let lock = lock.clone();
                    let counter = counter.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            // Simulate: check all test_refs (read lock)
                            for _ in 0..10 {
                                let _ = *lock.read();
                            }
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();

            // 1 heavy writer (shrinking worker holding write lock for extended periods)
            let writer_lock = lock.clone();
            let writer_stop = stop.clone();
            let writer_handle = std::thread::spawn(move || {
                while !writer_stop.load(Ordering::Relaxed) {
                    let mut val = writer_lock.write();
                    // Hold the write lock for ~1ms (simulates shrink candidate validation)
                    std::thread::sleep(Duration::from_micros(1000));
                    *val += 1;
                }
            });

            let start = Instant::now();
            while counter.load(Ordering::Relaxed) < iters as usize {
                std::thread::yield_now();
            }
            let elapsed = start.elapsed();
            stop.store(true, Ordering::Relaxed);
            for h in reader_handles {
                let _ = h.join();
            }
            let _ = writer_handle.join();
            elapsed
        });
    });

    // Test 4: Same as Test 3 but writer releases lock between candidates
    // (what a fix would look like: drop + re-acquire between candidates)
    group.bench_function("rwlock_intermittent_writer", |b| {
        let lock = Arc::new(RwLock::new(0u64));
        b.iter_custom(|iters| {
            let counter = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));

            let reader_handles: Vec<_> = (0..3)
                .map(|_| {
                    let lock = lock.clone();
                    let counter = counter.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            for _ in 0..10 {
                                let _ = *lock.read();
                            }
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();

            let writer_lock = lock.clone();
            let writer_stop = stop.clone();
            let writer_handle = std::thread::spawn(move || {
                while !writer_stop.load(Ordering::Relaxed) {
                    // 10 candidates, but release lock between each
                    for _ in 0..10 {
                        let mut val = writer_lock.write();
                        std::thread::sleep(Duration::from_micros(100));
                        *val += 1;
                        drop(val);
                        // Brief window for readers
                    }
                }
            });

            let start = Instant::now();
            while counter.load(Ordering::Relaxed) < iters as usize {
                std::thread::yield_now();
            }
            let elapsed = start.elapsed();
            stop.store(true, Ordering::Relaxed);
            for h in reader_handles {
                let _ = h.join();
            }
            let _ = writer_handle.join();
            elapsed
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_fuzz_only,
    bench_fuzz_with_shrink,
    bench_contention_sources,
);
criterion_main!(benches);
