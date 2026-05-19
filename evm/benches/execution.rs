//! Benchmarks for the EVM execution hot path.
//!
//! These benchmarks measure the two dominant costs in the fuzzing inner loop:
//!
//! 1. `vm_clone`  — EvmState::clone(), which resets state before every sequence.
//! 2. `exec_tx`   — a single transaction through exec_tx_check_new_cov (the per-tx unit).
//! 3. `exec_sequence/{1,10,100}` — a full N-tx sequence, mirroring what the fuzzer runs.
//!
//! Run with:
//!   cargo bench -p evm --bench execution
//!
//! To save a baseline and compare after an optimization:
//!   cargo bench -p evm --bench execution -- --save-baseline before
//!   # make the change
//!   cargo bench -p evm --bench execution -- --baseline before

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, U256};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use parking_lot::RwLock;

use evm::coverage::MetadataToCodehash;
use evm::exec::{CoverageMap, EvmState};
use evm::types::{Tx, TxCall};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Minimal counter contract (pure EVM bytecode, no Solidity required).
///
/// On every call (regardless of calldata) it:
///   1. SLOADs storage slot 0
///   2. Adds 1
///   3. SSTOREs the result back
///   4. STOPs
///
/// This exercises the SLOAD/SSTORE path and populates `last_state_diff` on
/// the EvmState — making each clone realistically heavier after execution.
///
/// Bytecode: PUSH1 0x01, PUSH1 0x00, SLOAD, ADD, PUSH1 0x00, SSTORE, STOP
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
        // Empty calldata: the counter contract ignores calldata entirely.
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

fn make_coverage_refs() -> (
    Arc<RwLock<CoverageMap>>,
    Arc<RwLock<MetadataToCodehash>>,
) {
    (
        Arc::new(RwLock::new(CoverageMap::default())),
        Arc::new(RwLock::new(MetadataToCodehash::default())),
    )
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// How long does cloning a fresh EvmState take?
///
/// This is the baseline cost of `initial_vm.clone()` in `run_fuzz_worker`,
/// which happens once per sequence before any transactions are executed.
fn bench_vm_clone(c: &mut Criterion) {
    let vm = make_vm();

    let mut group = c.benchmark_group("vm_clone");

    // Fresh state: only the deployed contract is in the DB.
    group.bench_function("fresh", |b| b.iter(|| black_box(vm.clone())));

    // Post-tx state: last_state_diff is populated (SSTORE wrote to slot 0).
    // Cloning this is more expensive because last_state_diff contains entries.
    let (cov, codehash) = make_coverage_refs();
    let vm_after_tx = {
        let mut v = vm.clone();
        v.exec_tx_check_new_cov(&make_tx(), &cov, &codehash).unwrap();
        v
    };
    group.bench_function("after_tx", |b| b.iter(|| black_box(vm_after_tx.clone())));

    group.finish();
}

/// How long does a single transaction take through the full hot path?
///
/// Measures: vm_clone + exec_tx_check_new_cov (coverage read+write lock included).
/// This is the minimum cost of one fuzzing "step".
fn bench_exec_tx(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx();
    let (cov, codehash) = make_coverage_refs();

    c.bench_function("exec_tx/single", |b| {
        b.iter(|| {
            let mut vm = vm.clone();
            black_box(
                vm.exec_tx_check_new_cov(black_box(&tx), &cov, &codehash)
                    .unwrap(),
            )
        })
    });
}

/// How does total cost scale with sequence length?
///
/// Mirrors `execute_sequence_worker_with_checkpoints`: clone initial_vm once,
/// then execute seq_len transactions sequentially (each building on the prior
/// state). Parameterised over the default seq_len values used in the fuzzer.
fn bench_exec_sequence(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx();
    let (cov, codehash) = make_coverage_refs();

    let mut group = c.benchmark_group("exec_sequence");

    for seq_len in [1usize, 10, 100] {
        let seq: Vec<Tx> = vec![tx.clone(); seq_len];

        group.bench_with_input(
            BenchmarkId::from_parameter(seq_len),
            &seq_len,
            |b, _| {
                b.iter(|| {
                    let mut vm = vm.clone();
                    for t in black_box(&seq) {
                        let _ = vm.exec_tx_check_new_cov(t, &cov, &codehash).unwrap();
                    }
                })
            },
        );
    }

    group.finish();
}

/// How does coverage map contention scale with the number of unique PCs seen?
///
/// As the fuzzer runs, the shared CoverageMap grows. The read-then-conditionally-write
/// pattern in exec_tx_check_new_cov checks the map for every touched PC. This
/// benchmark measures the map access cost under a realistic coverage map size.
fn bench_coverage_check(c: &mut Criterion) {
    let vm = make_vm();
    let tx = make_tx();
    let codehash = Arc::new(RwLock::new(MetadataToCodehash::default()));

    let mut group = c.benchmark_group("coverage_check");

    // Pre-warm the coverage map with N prior sequences so it has entries.
    for prior_sequences in [0usize, 100, 1000] {
        let cov = Arc::new(RwLock::new(CoverageMap::default()));
        {
            let mut vm_warmup = vm.clone();
            for _ in 0..prior_sequences {
                let _ = vm_warmup.exec_tx_check_new_cov(&tx, &cov, &codehash);
                // Reset VM to initial state so each warmup tx re-executes identically.
                vm_warmup = vm.clone();
            }
        }

        group.bench_with_input(
            BenchmarkId::new("prior_sequences", prior_sequences),
            &prior_sequences,
            |b, _| {
                b.iter(|| {
                    let mut vm = vm.clone();
                    black_box(vm.exec_tx_check_new_cov(black_box(&tx), &cov, &codehash).unwrap())
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_vm_clone,
    bench_exec_tx,
    bench_exec_sequence,
    bench_coverage_check,
);
criterion_main!(benches);
