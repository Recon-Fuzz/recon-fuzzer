//! Benchmarks for the shrinking hot path.
//!
//! Profiles each component of a single shrink candidate validation:
//!   1. `vm_clone` — EvmState::clone() (per candidate)
//!   2. `exec_tx` — single tx replay (per tx in sequence)
//!   3. `encode_call` — ABI encoding (per tx)
//!   4. `full_candidate` — clone + replay N txs (end-to-end)
//!
//! Also tests optimizations:
//!   - `exec_tx_shrink` — stripped-down exec_tx that skips unnecessary work
//!   - Pre-encoded calldata to avoid re-encoding identical calls
//!
//! Run with:
//!   cargo bench -p evm --bench shrink_hotpath

use std::sync::Arc;

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{Address, Bytes, U256};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use parking_lot::RwLock;
use std::time::Duration;

use evm::coverage::MetadataToCodehash;
use evm::exec::{CoverageMap, EvmState};
use evm::types::{Tx, TxCall};

// A more realistic contract: counter with a function selector
// function increment() — selector 0xd09de08a
// PUSH4 selector, CALLDATALOAD 0, EQ, JUMPI, REVERT path...
// For simplicity, use the same counter but with SolCall encoding
const COUNTER_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x54, 0x01, 0x60, 0x00, 0x55, 0x00];
const CONTRACT_ADDR: Address = Address::repeat_byte(0x42);
const SENDER: Address = Address::repeat_byte(0x01);

fn make_vm() -> EvmState {
    let mut vm = EvmState::new();
    vm.set_code(CONTRACT_ADDR, Bytes::from_static(COUNTER_BYTECODE));
    vm.fund_account(SENDER, U256::MAX / U256::from(2u64));
    vm
}

fn make_tx_calldata() -> Tx {
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

fn make_tx_solcall() -> Tx {
    Tx {
        call: TxCall::SolCall {
            name: "increment".to_string(),
            args: vec![DynSolValue::Uint(U256::from(42u64), 256)],
        },
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

fn make_tx_nocall() -> Tx {
    Tx {
        call: TxCall::NoCall,
        src: SENDER,
        dst: CONTRACT_ADDR,
        gas: 0,
        gasprice: U256::ZERO,
        value: U256::ZERO,
        delay: (10, 1),
        generate_calls_seed: None,
        generate_calls: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Component benchmarks
// ---------------------------------------------------------------------------

fn bench_components(c: &mut Criterion) {
    let vm = make_vm();
    let tx_calldata = make_tx_calldata();
    let tx_solcall = make_tx_solcall();

    let mut group = c.benchmark_group("shrink_component");

    // 1. VM clone cost (this happens once per candidate)
    group.bench_function("vm_clone_fresh", |b| {
        b.iter(|| black_box(vm.clone()))
    });

    // VM clone after some execution (more realistic — DB has state)
    let vm_warm = {
        let mut v = vm.clone();
        for _ in 0..10 {
            let _ = v.exec_tx(&tx_calldata);
        }
        v
    };
    group.bench_function("vm_clone_warm", |b| {
        b.iter(|| black_box(vm_warm.clone()))
    });

    // 2. exec_tx with pre-encoded calldata (no ABI encoding)
    group.bench_function("exec_tx_calldata", |b| {
        let mut v = vm.clone();
        b.iter(|| {
            let _ = black_box(v.exec_tx(&tx_calldata));
        })
    });

    // 3. exec_tx with SolCall (ABI encoding happens inside)
    group.bench_function("exec_tx_solcall", |b| {
        let mut v = vm.clone();
        b.iter(|| {
            let _ = black_box(v.exec_tx(&tx_solcall));
        })
    });

    // 4. ABI encoding cost in isolation
    group.bench_function("abi_encode", |b| {
        let name = "increment";
        let args = vec![DynSolValue::Uint(U256::from(42u64), 256)];
        b.iter(|| {
            let _ = black_box(evm::exec::encode_call(name, &args));
        })
    });

    // 5. NoCall tx (just delay, no EVM)
    group.bench_function("exec_tx_nocall", |b| {
        let tx_nocall = make_tx_nocall();
        let mut v = vm.clone();
        b.iter(|| {
            let _ = black_box(v.exec_tx(&tx_nocall));
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Full candidate validation (clone + replay N txs) — what shrinking does
// ---------------------------------------------------------------------------

fn bench_full_candidate(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx_calldata();

    let mut group = c.benchmark_group("shrink_candidate");
    group.measurement_time(Duration::from_secs(10));

    for seq_len in [1, 5, 10, 20, 50] {
        // Current approach: clone + exec_tx per tx
        group.bench_with_input(
            BenchmarkId::new("current", seq_len),
            &seq_len,
            |b, &len| {
                b.iter(|| {
                    let mut v = vm.clone();
                    for _ in 0..len {
                        let _ = v.exec_tx(&tx);
                    }
                })
            },
        );
    }

    // Mixed sequence: SolCall + NoCall (more realistic)
    let mixed_seq: Vec<Tx> = (0..10)
        .map(|i| {
            if i % 3 == 0 {
                make_tx_nocall()
            } else {
                make_tx_solcall()
            }
        })
        .collect();

    group.bench_function("mixed_10tx", |b| {
        b.iter(|| {
            let mut v = vm.clone();
            for tx in &mixed_seq {
                let _ = v.exec_tx(tx);
            }
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Batch candidates: how does validating N candidates scale?
// This is what shrink_seq does per iteration.
// ---------------------------------------------------------------------------

fn bench_batch_candidates(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx_calldata();

    let mut group = c.benchmark_group("shrink_batch");
    group.measurement_time(Duration::from_secs(10));

    let seq_len = 10;

    for num_candidates in [1, 5, 10, 15] {
        group.bench_with_input(
            BenchmarkId::new("sequential", num_candidates),
            &num_candidates,
            |b, &n| {
                b.iter(|| {
                    for _ in 0..n {
                        let mut v = vm.clone();
                        for _ in 0..seq_len {
                            let _ = v.exec_tx(&tx);
                        }
                    }
                })
            },
        );
    }

    // Compare: parallel via std threads
    for num_candidates in [5, 10, 15] {
        group.bench_with_input(
            BenchmarkId::new("parallel", num_candidates),
            &num_candidates,
            |b, &n| {
                b.iter(|| {
                    let handles: Vec<_> = (0..n)
                        .map(|_| {
                            let vm = vm.clone();
                            let tx = tx.clone();
                            std::thread::spawn(move || {
                                let mut v = vm;
                                for _ in 0..seq_len {
                                    let _ = v.exec_tx(&tx);
                                }
                            })
                        })
                        .collect();
                    for h in handles {
                        let _ = h.join();
                    }
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Optimization ideas to benchmark
// ---------------------------------------------------------------------------

fn bench_optimizations(c: &mut Criterion) {
    let vm = make_vm();

    let mut group = c.benchmark_group("shrink_optimization");

    // OPT 1: Pre-encode calldata once, reuse across all candidates
    // Instead of SolCall { name, args } which re-encodes every exec_tx,
    // encode once and use SolCalldata
    let solcall_tx = make_tx_solcall();
    let pre_encoded_tx = {
        let calldata = match &solcall_tx.call {
            TxCall::SolCall { name, args } => evm::exec::encode_call(name, args).unwrap(),
            _ => unreachable!(),
        };
        Tx {
            call: TxCall::SolCalldata(calldata),
            ..solcall_tx.clone()
        }
    };

    let seq_len = 10;

    group.bench_function("solcall_10tx", |b| {
        b.iter(|| {
            let mut v = vm.clone();
            for _ in 0..seq_len {
                let _ = v.exec_tx(&solcall_tx);
            }
        })
    });

    group.bench_function("pre_encoded_10tx", |b| {
        b.iter(|| {
            let mut v = vm.clone();
            for _ in 0..seq_len {
                let _ = v.exec_tx(&pre_encoded_tx);
            }
        })
    });

    // OPT 2: Early termination — for shrinking, we only care if the test
    // still fails. If a tx reverts that didn't revert in the original,
    // the sequence is already different and likely won't reproduce.
    // Benchmark the cost of checking tx_result per tx.
    group.bench_function("with_result_check_10tx", |b| {
        let tx = make_tx_calldata();
        b.iter(|| {
            let mut v = vm.clone();
            for _ in 0..seq_len {
                let result = v.exec_tx(&tx).unwrap();
                if result.is_revert() {
                    break;
                }
            }
        })
    });

    // OPT 3: Compare exec_tx vs exec_tx_check_new_cov to see how much
    // overhead the coverage tracking adds (shrinking doesn't need it)
    let cov = Arc::new(RwLock::new(CoverageMap::default()));
    let ch = Arc::new(RwLock::new(MetadataToCodehash::default()));
    let tx = make_tx_calldata();

    group.bench_function("exec_tx_no_cov_10tx", |b| {
        b.iter(|| {
            let mut v = vm.clone();
            for _ in 0..seq_len {
                let _ = v.exec_tx(&tx);
            }
        })
    });

    group.bench_function("exec_tx_with_cov_10tx", |b| {
        b.iter(|| {
            let mut v = vm.clone();
            for _ in 0..seq_len {
                let _ = v.exec_tx_check_new_cov(&tx, &cov, &ch);
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_components,
    bench_full_candidate,
    bench_batch_candidates,
    bench_optimizations,
);
criterion_main!(benches);
