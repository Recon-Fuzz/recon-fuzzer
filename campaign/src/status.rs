//! Status reporting functions
//!
//! Contains functions for reporting campaign status and gathering statistics.

use crate::output;
use crate::testing::TestState;
use crate::worker_env::WorkerEnv;

/// Print status in Echidna format (WorkerEnv variant)
pub fn print_status_worker(env: &WorkerEnv, ncalls: usize, test_limit: usize, gas_per_second: u64) {
    let (tests_failed, total_tests) = count_tests_worker(env);
    let (coverage, _codehashes) = get_coverage_stats_worker(env);
    let corpus_size = get_corpus_size_worker(env);
    let shrink_limit = env.cfg.campaign_conf.shrink_limit;

    // Collect shrinking workers info
    let shrinking_workers = get_shrinking_workers_worker(env, shrink_limit);

    // Collect optimization test values 
    let opt_values = get_optimization_values_worker(env);

    output::print_status(
        tests_failed,
        total_tests,
        ncalls,
        test_limit,
        &opt_values,
        coverage,
        corpus_size,
        &shrinking_workers,
        gas_per_second,
    );
}

/// Count failed and total tests (WorkerEnv variant)
pub fn count_tests_worker(env: &WorkerEnv) -> (usize, usize) {
    let mut failed = 0;
    let total = env.test_refs.len();

    for test_ref in &env.test_refs {
        let test = test_ref.read();
        if test.state.did_fail() {
            failed += 1;
        }
    }

    (failed, total)
}

/// Get coverage statistics (WorkerEnv variant)
/// Returns (points, numCodehashes) exactly like Echidna's coverageStats
pub fn get_coverage_stats_worker(env: &WorkerEnv) -> (usize, usize) {
    let init_cov = env.coverage_ref_init.read();
    let runtime_cov = env.coverage_ref_runtime.read();
    evm::coverage::coverage_stats(&init_cov, &runtime_cov)
}

/// Write LCOV coverage report to lcov.info in the project root (WorkerEnv variant)
/// Called periodically during fuzzing to allow real-time coverage tracking
pub fn write_lcov_info_worker(env: &WorkerEnv) {
    use evm::coverage::{
        build_codehash_to_source_info, build_init_codehash_to_source_info,
        generate_source_coverage_multi, load_source_info,
    };

    // Load source files (this is cached internally, so reasonably fast)
    let (source_files, _) = match load_source_info(&env.project_path) {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!("Failed to load source info for lcov: {}", e);
            return;
        }
    };

    // Build codehash -> source info maps for runtime and init code
    let runtime_source_info = build_codehash_to_source_info(&env.contracts);
    let init_source_info = build_init_codehash_to_source_info(&env.contracts);

    // Get separate coverage for init (constructor) and runtime
    let init_cov = env.coverage_ref_init.read();
    let runtime_cov = env.coverage_ref_runtime.read();

    // Generate source-level coverage separately for init and runtime
    // Init code has different source maps than runtime code
    let mut source_coverage = generate_source_coverage_multi(
        &runtime_cov,
        &runtime_source_info,
        &source_files,
    );

    // Generate init code coverage and merge
    let init_source_coverage = generate_source_coverage_multi(
        &init_cov,
        &init_source_info,
        &source_files,
    );

    // Merge init coverage into runtime coverage
    for (path, init_file_cov) in init_source_coverage.files {
        let file_cov = source_coverage.files.entry(path).or_default();
        for (line, hits) in init_file_cov.line_hits {
            *file_cov.line_hits.entry(line).or_insert(0) += hits;
        }
    }

    // Filter to only show relevant sources (src/ + files with hits)
    source_coverage.filter_relevant_sources(&env.project_path);

    // Generate LCOV content
    let lcov_content = source_coverage.to_lcov(&env.project_path);

    // Write to lcov.info in project root
    let output_path = env.project_path.join("lcov.info");
    if let Err(e) = std::fs::write(&output_path, &lcov_content) {
        tracing::warn!("Failed to write lcov.info: {}", e);
    } else {
        tracing::trace!("Updated lcov.info with current coverage");
    }
}

/// Get corpus size (WorkerEnv variant)
pub fn get_corpus_size_worker(env: &WorkerEnv) -> usize {
    env.corpus_ref.read().len()
}

/// Get optimization test values (WorkerEnv variant)
pub fn get_optimization_values_worker(env: &WorkerEnv) -> Vec<i128> {
    let mut values = Vec::new();
    for test_ref in &env.test_refs {
        let test = test_ref.read();
        if matches!(
            test.test_type,
            crate::testing::TestType::OptimizationTest { .. }
        ) {
            if let crate::testing::TestValue::IntValue(v) = &test.value {
                let val: i128 = (*v).try_into().unwrap_or_else(|_| {
                    if v.is_negative() {
                        i128::MIN
                    } else {
                        i128::MAX
                    }
                });
                values.push(val);
            }
        }
    }
    values
}

/// Get info about workers currently shrinking (WorkerEnv variant)
pub fn get_shrinking_workers_worker(
    env: &WorkerEnv,
    shrink_limit: usize,
) -> Vec<output::ShrinkingWorker> {
    let mut shrinking = Vec::new();
    for test_ref in &env.test_refs {
        let test = test_ref.read();
        if let (TestState::Large(step), Some(wid)) = (&test.state, test.worker_id) {
            if (*step as usize) < shrink_limit {
                shrinking.push(output::ShrinkingWorker {
                    worker_id: wid,
                    step: *step,
                    shrink_limit,
                    seq_length: test.reproducer.len(),
                });
            }
        }
    }
    shrinking
}

/// Check if any test needs shrinking by this worker (WorkerEnv variant)
pub fn any_pending_shrink_for_worker_env(env: &WorkerEnv, worker_id: usize) -> bool {
    env.test_refs.iter().any(|t| {
        let test = t.read();
        matches!(test.state, TestState::Large(_)) && test.worker_id == Some(worker_id)
    })
}

/// Check if any test has failed (WorkerEnv variant)
pub fn any_test_failed_worker(env: &WorkerEnv) -> bool {
    env.test_refs.iter().any(|t| t.read().state.did_fail())
}

/// Check if all tests are complete (WorkerEnv variant)
pub fn all_tests_complete_worker(env: &WorkerEnv) -> bool {
    env.test_refs.iter().all(|t| !t.read().is_open())
}
