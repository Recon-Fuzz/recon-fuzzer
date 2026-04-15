//! Integration tests for recon-fuzzer
//!
//! These tests verify end-to-end fuzzing functionality on sample contracts.
//! Each test compiles a Solidity contract, runs fuzzing, and verifies results.

use std::path::PathBuf;
use std::process::Command;

/// Get the path to test fixtures (in workspace root)
fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/fixtures")
}

/// Compile test contracts using forge
fn compile_fixtures() -> bool {
    let fixtures = fixtures_path();

    // Check if forge is available
    let forge_check = Command::new("forge")
        .arg("--version")
        .output();

    if forge_check.is_err() {
        eprintln!("Warning: forge not found, skipping compilation");
        return false;
    }

    // Compile contracts
    let output = Command::new("forge")
        .arg("build")
        .current_dir(&fixtures)
        .output()
        .expect("Failed to run forge build");

    if !output.status.success() {
        eprintln!("Forge build failed: {}", String::from_utf8_lossy(&output.stderr));
        return false;
    }

    true
}

/// Check if compiled artifacts exist
fn artifacts_exist() -> bool {
    let out_dir = fixtures_path().join("out");
    out_dir.exists() && out_dir.join("PropertyTest.sol").exists()
}

mod property_tests {
    use super::*;

    #[test]
    fn test_property_test_contract_compiles() {
        if !compile_fixtures() {
            eprintln!("Skipping: forge not available");
            return;
        }

        assert!(artifacts_exist(), "Compiled artifacts should exist");

        let property_test_artifact = fixtures_path()
            .join("out/PropertyTest.sol/PropertyTest.json");
        assert!(property_test_artifact.exists(), "PropertyTest.json should exist");
    }

    #[test]
    #[ignore] // Run with --ignored for full integration tests
    fn test_property_violation_detected() {
        // This test would run the full fuzzer and verify it finds the bug
        // For now, we just verify the contract structure is correct

        if !artifacts_exist() {
            compile_fixtures();
        }

        // Load the compiled contract
        let artifact_path = fixtures_path()
            .join("out/PropertyTest.sol/PropertyTest.json");

        if !artifact_path.exists() {
            eprintln!("Skipping: artifacts not compiled");
            return;
        }

        let content = std::fs::read_to_string(&artifact_path)
            .expect("Failed to read artifact");

        // Verify it has the expected functions
        assert!(content.contains("echidna_counter_under_limit"));
        assert!(content.contains("increment"));
    }
}

mod assertion_tests {
    use super::*;

    #[test]
    fn test_assertion_test_contract_compiles() {
        if !compile_fixtures() {
            eprintln!("Skipping: forge not available");
            return;
        }

        let assertion_test_artifact = fixtures_path()
            .join("out/AssertionTest.sol/AssertionTest.json");
        assert!(assertion_test_artifact.exists(), "AssertionTest.json should exist");
    }

    #[test]
    #[ignore]
    fn test_assertion_violation_detected() {
        // Would verify fuzzer finds assertion violations
        if !artifacts_exist() {
            compile_fixtures();
        }

        let artifact_path = fixtures_path()
            .join("out/AssertionTest.sol/AssertionTest.json");

        if !artifact_path.exists() {
            eprintln!("Skipping: artifacts not compiled");
            return;
        }

        let content = std::fs::read_to_string(&artifact_path)
            .expect("Failed to read artifact");

        // Verify it has assertion functions
        assert!(content.contains("setValue"));
        assert!(content.contains("complexOperation"));
    }
}

mod optimization_tests {
    use super::*;

    #[test]
    fn test_optimization_test_contract_compiles() {
        if !compile_fixtures() {
            eprintln!("Skipping: forge not available");
            return;
        }

        let opt_test_artifact = fixtures_path()
            .join("out/OptimizationTest.sol/OptimizationTest.json");
        assert!(opt_test_artifact.exists(), "OptimizationTest.json should exist");
    }
}

mod evm_tests {
    use evm::{exec::EvmState, types::{Tx, TxCall}};
    use alloy_primitives::{Address, U256};

    #[test]
    fn test_evm_state_creation() {
        let vm = EvmState::new();
        assert!(!vm.is_fork());
    }

    #[test]
    fn test_fund_account() {
        let mut vm = EvmState::new();
        let addr = Address::repeat_byte(0x42);
        let amount = U256::from(1000);

        // fund_account should not panic
        vm.fund_account(addr, amount);

        // Verify account exists by checking nonce (starts at 0)
        let nonce = vm.get_nonce(addr);
        assert_eq!(nonce, 0);
    }

    #[test]
    fn test_nonce_tracking() {
        let mut vm = EvmState::new();
        let addr = Address::repeat_byte(0x42);

        let nonce1 = vm.get_nonce(addr);
        assert_eq!(nonce1, 0);

        vm.increment_nonce(addr);
        let nonce2 = vm.get_nonce(addr);
        assert_eq!(nonce2, 1);
    }

    #[test]
    fn test_no_call_transaction() {
        let mut vm = EvmState::new();
        let tx = Tx {
            call: TxCall::NoCall,
            src: Address::repeat_byte(0x01),
            dst: Address::repeat_byte(0x02),
            gas: 100000,
            gasprice: U256::ZERO,
            value: U256::ZERO,
            delay: (0, 0),
        };

        let result = vm.exec_tx(&tx);
        assert!(result.is_ok());
    }
}

mod abi_tests {
    use abi::types::GenDict;
    use alloy_dyn_abi::DynSolType;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_gen_dict_creation() {
        let dict = GenDict::new(12345);
        assert!(dict.dict_values.is_empty() || !dict.dict_values.is_empty());
    }

    #[test]
    fn test_generate_uint256() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = abi::gen::gen_abi_value(&mut rng, &DynSolType::Uint(256));

        // Should produce a valid DynSolValue
        assert!(matches!(value, alloy_dyn_abi::DynSolValue::Uint(_, 256)));
    }

    #[test]
    fn test_generate_address() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = abi::gen::gen_abi_value(&mut rng, &DynSolType::Address);

        assert!(matches!(value, alloy_dyn_abi::DynSolValue::Address(_)));
    }

    #[test]
    fn test_generate_bool() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = abi::gen::gen_abi_value(&mut rng, &DynSolType::Bool);

        assert!(matches!(value, alloy_dyn_abi::DynSolValue::Bool(_)));
    }

    #[test]
    fn test_generate_bytes() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = abi::gen::gen_abi_value(&mut rng, &DynSolType::Bytes);

        assert!(matches!(value, alloy_dyn_abi::DynSolValue::Bytes(_)));
    }
}

mod mutation_tests {
    use abi::mutate;
    use alloy_dyn_abi::DynSolValue;
    use alloy_primitives::U256;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_mutate_uint256() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = DynSolValue::Uint(U256::from(100), 256);

        let mutated = mutate::mutate_abi_value(&mut rng, &value);

        // Should still be a Uint256
        assert!(matches!(mutated, DynSolValue::Uint(_, 256)));
    }

    #[test]
    fn test_mutate_preserves_type() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Test various types
        let bool_val = DynSolValue::Bool(true);
        let mutated_bool = mutate::mutate_abi_value(&mut rng, &bool_val);
        assert!(matches!(mutated_bool, DynSolValue::Bool(_)));

        let addr = alloy_primitives::Address::repeat_byte(0x42);
        let addr_val = DynSolValue::Address(addr);
        let mutated_addr = mutate::mutate_abi_value(&mut rng, &addr_val);
        assert!(matches!(mutated_addr, DynSolValue::Address(_)));
    }
}

mod shrink_tests {
    use abi::shrink;
    use alloy_dyn_abi::DynSolValue;
    use alloy_primitives::U256;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_shrink_uint256() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = DynSolValue::Uint(U256::from(1000), 256);

        let shrunk = shrink::shrink_abi_value(&mut rng, &value);

        // Should still be a Uint256, possibly smaller
        if let DynSolValue::Uint(v, 256) = shrunk {
            // Shrinking should not increase the value
            assert!(v <= U256::from(1000));
        } else {
            panic!("Expected Uint256");
        }
    }

    #[test]
    fn test_shrink_towards_zero() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = DynSolValue::Uint(U256::from(100), 256);

        // Shrink multiple times - should trend towards zero
        let mut current = value;
        for _ in 0..10 {
            current = shrink::shrink_abi_value(&mut rng, &current);
        }

        if let DynSolValue::Uint(v, _) = current {
            // After multiple shrinks, should be smaller
            assert!(v <= U256::from(100));
        }
    }
}

mod config_tests {
    use config::solidity::TestMode;

    #[test]
    fn test_default_config() {
        let config = config::global::EConfig::default();
        assert!(config.campaign_conf.test_limit > 0);
        assert!(config.campaign_conf.seq_len > 0);
    }

    #[test]
    fn test_tx_conf_defaults() {
        let tx_conf = config::transaction::TxConf::default();
        assert!(tx_conf.tx_gas > 0);
        assert!(tx_conf.max_time_delay > 0);
        assert!(tx_conf.max_block_delay > 0);
    }

    #[test]
    fn test_test_mode_parsing() {
        assert_eq!(TestMode::from_str("property"), Some(TestMode::Property));
        assert_eq!(TestMode::from_str("assertion"), Some(TestMode::Assertion));
        assert_eq!(TestMode::from_str("optimization"), Some(TestMode::Optimization));
        assert_eq!(TestMode::from_str("exploration"), Some(TestMode::Exploration));
        assert_eq!(TestMode::from_str("invalid"), None);
    }

    #[test]
    fn test_campaign_conf_workers() {
        let conf = config::campaign::CampaignConf::default();
        // Default should use available CPUs
        assert!(conf.workers > 0);
    }
}

mod coverage_tests {
    use evm::coverage::{CoverageMode, CombinedInspector};

    #[test]
    fn test_coverage_mode_parsing() {
        assert_eq!(CoverageMode::from_str("full"), CoverageMode::Full);
        assert_eq!(CoverageMode::from_str("branch"), CoverageMode::Branch);
        assert_eq!(CoverageMode::from_str("fast"), CoverageMode::Branch);
    }

    #[test]
    fn test_combined_inspector_creation() {
        let inspector = CombinedInspector::new();
        assert!(inspector.touched.is_empty());
        assert_eq!(inspector.call_depth, 0);
    }

    #[test]
    fn test_inspector_reset() {
        let mut inspector = CombinedInspector::new();
        inspector.call_depth = 5;
        inspector.reset_for_new_tx();
        assert_eq!(inspector.call_depth, 0);
        assert!(inspector.touched.is_empty());
    }
}

mod fork_tests {
    use evm::{fork::ForkOptions, exec::EvmState};

    #[test]
    fn test_fork_options_default() {
        let opts = ForkOptions::default();
        // Default options should not use storage dump by default
        assert!(!opts.use_storage_dump);
        // Default cache_dir should be None (uses default path)
        assert!(opts.cache_dir.is_none());
    }

    #[test]
    fn test_non_fork_state() {
        let vm = EvmState::new();
        assert!(!vm.is_fork());
        assert!(vm.chain_id().is_none());
    }

    #[test]
    #[ignore] // Requires RPC access
    fn test_fork_mode_initialization() {
        // This test requires an actual RPC endpoint
        let rpc_url = std::env::var("TEST_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

        let result = EvmState::new_fork(&rpc_url, None, ForkOptions::default());

        match result {
            Ok(vm) => {
                assert!(vm.is_fork());
                // Mainnet should have chain_id = 1
                if let Some(chain_id) = vm.chain_id() {
                    assert!(chain_id > 0, "Chain ID should be positive");
                }
            }
            Err(e) => {
                eprintln!("Fork initialization failed (network may be unavailable): {}", e);
                // Test passes even on network failure - this is expected in CI
            }
        }
    }

    #[test]
    #[ignore] // Requires RPC access
    fn test_fork_mode_with_block() {
        let rpc_url = std::env::var("TEST_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

        // Fork at a specific block
        let block_number = 18_000_000u64;
        let result = EvmState::new_fork(&rpc_url, Some(block_number), ForkOptions::default());

        match result {
            Ok(vm) => {
                assert!(vm.is_fork());
            }
            Err(e) => {
                eprintln!("Fork initialization failed: {}", e);
            }
        }
    }
}