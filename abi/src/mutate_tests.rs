//! Unit tests for ABI value mutation

use super::*;
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{I256, U256};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_mutate_uint256_bounds() {
    let mut rng = StdRng::seed_from_u64(12345);

    // Test mutation of zero
    let zero = DynSolValue::Uint(U256::ZERO, 256);
    for _ in 0..10 {
        let mutated = mutate_abi_value(&mut rng, &zero);
        assert!(matches!(mutated, DynSolValue::Uint(_, 256)));
    }

    // Test mutation of MAX
    let max = DynSolValue::Uint(U256::MAX, 256);
    for _ in 0..10 {
        let mutated = mutate_abi_value(&mut rng, &max);
        assert!(matches!(mutated, DynSolValue::Uint(_, 256)));
    }
}

#[test]
fn test_mutate_uint_respects_bit_width() {
    let mut rng = StdRng::seed_from_u64(42);

    // uint8 should stay within 0-255
    let uint8_val = DynSolValue::Uint(U256::from(100), 8);
    for _ in 0..20 {
        let mutated = mutate_abi_value(&mut rng, &uint8_val);
        if let DynSolValue::Uint(v, 8) = mutated {
            assert!(v <= U256::from(255), "uint8 exceeded max: {}", v);
        } else {
            panic!("Type changed during mutation");
        }
    }
}

#[test]
fn test_mutate_int256_bounds() {
    let mut rng = StdRng::seed_from_u64(12345);

    // Test mutation of I256::MIN
    let min = DynSolValue::Int(I256::MIN, 256);
    for _ in 0..10 {
        let mutated = mutate_abi_value(&mut rng, &min);
        assert!(matches!(mutated, DynSolValue::Int(_, 256)));
    }

    // Test mutation of I256::MAX
    let max = DynSolValue::Int(I256::MAX, 256);
    for _ in 0..10 {
        let mutated = mutate_abi_value(&mut rng, &max);
        assert!(matches!(mutated, DynSolValue::Int(_, 256)));
    }
}

#[test]
fn test_mutate_call_empty_args() {
    let mut rng = StdRng::seed_from_u64(12345);
    let (name, args) = mutate_call(&mut rng, "test", &[]);
    assert_eq!(name, "test");
    assert!(args.is_empty());
}

#[test]
fn test_mutate_call_preserves_length() {
    let mut rng = StdRng::seed_from_u64(12345);
    let args = vec![
        DynSolValue::Uint(U256::from(100), 256),
        DynSolValue::Bool(true),
        DynSolValue::Address(alloy_primitives::Address::ZERO),
    ];

    let (name, new_args) = mutate_call(&mut rng, "myFunc", &args);
    assert_eq!(name, "myFunc");
    assert_eq!(new_args.len(), 3);
}

#[test]
fn test_infer_element_type_coverage() {
    // Test all element type inference paths
    let bool_arr = vec![DynSolValue::Bool(true)];
    assert!(matches!(infer_element_type(&bool_arr), ElementType::Bool));

    let uint_arr = vec![DynSolValue::Uint(U256::from(1), 128)];
    assert!(matches!(
        infer_element_type(&uint_arr),
        ElementType::Uint(128)
    ));

    let int_arr = vec![DynSolValue::Int(I256::try_from(1).unwrap(), 64)];
    assert!(matches!(infer_element_type(&int_arr), ElementType::Int(64)));

    let addr_arr = vec![DynSolValue::Address(alloy_primitives::Address::ZERO)];
    assert!(matches!(
        infer_element_type(&addr_arr),
        ElementType::Address
    ));

    let empty: Vec<DynSolValue> = vec![];
    assert!(matches!(infer_element_type(&empty), ElementType::Unknown));
}

#[test]
fn test_generate_fresh_value_types() {
    let mut rng = StdRng::seed_from_u64(12345);

    // Test that generate_fresh_value produces correct types
    let bool_val = generate_fresh_value(&mut rng, &ElementType::Bool);
    assert!(matches!(bool_val, DynSolValue::Bool(_)));

    let uint_val = generate_fresh_value(&mut rng, &ElementType::Uint(256));
    assert!(matches!(uint_val, DynSolValue::Uint(_, 256)));

    let addr_val = generate_fresh_value(&mut rng, &ElementType::Address);
    assert!(matches!(addr_val, DynSolValue::Address(_)));

    let bytes_val = generate_fresh_value(&mut rng, &ElementType::Bytes);
    assert!(matches!(bytes_val, DynSolValue::Bytes(_)));

    let string_val = generate_fresh_value(&mut rng, &ElementType::String);
    assert!(matches!(string_val, DynSolValue::String(_)));
}
