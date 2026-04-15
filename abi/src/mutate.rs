//! ABI value mutation
//!
//! This module provides two mutation approaches:
//! Uses Mutable trait with AFL++ strategies

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{I256, U256};
use rand::prelude::*;

use crate::mutable::Mutable;

/// Mutate an ABI value to a "similar" value
/// 10% chance of actual mutation
pub fn mutate_abi_value<R: Rng>(rng: &mut R, value: &DynSolValue) -> DynSolValue {
    match value {
        DynSolValue::Uint(n, bits) => {
            // 10% chance
            if rng.gen_range(0..10) == 0 {
                let mutated = mutate_num_u256(rng, *n);
                if *bits >= 256 {
                    DynSolValue::Uint(mutated, *bits)
                } else {
                    let max_val = (U256::from(1) << bits) - U256::from(1);
                    DynSolValue::Uint(mutated % (max_val + U256::from(1)), *bits)
                }
            } else {
                value.clone()
            }
        }

        DynSolValue::Int(n, bits) => {
            // 10% chance
            if rng.gen_range(0..10) == 0 {
                let mutated = mutate_num_i256(rng, *n);
                if *bits >= 256 {
                    DynSolValue::Int(mutated, *bits)
                } else {
                    let max = (I256::ONE << (*bits - 1)) - I256::ONE;
                    let min = -max - I256::ONE;
                    let clamped = if mutated > max {
                        max
                    } else if mutated < min {
                        min
                    } else {
                        mutated
                    };
                    DynSolValue::Int(clamped, *bits)
                }
            } else {
                value.clone()
            }
        }

        DynSolValue::Address(_) => value.clone(),

        DynSolValue::Bool(_) => DynSolValue::Bool(rng.gen()),

        DynSolValue::Bytes(b) => {
            DynSolValue::Bytes(crate::mutator_array::mutate_ll(rng, None, vec![], b))
        }

        DynSolValue::String(s) => {
            let bytes = s.as_bytes().to_vec();
            let mutated = crate::mutator_array::mutate_ll(rng, None, vec![], &bytes);
            DynSolValue::String(String::from_utf8_lossy(&mutated).to_string())
        }

        DynSolValue::FixedBytes(b, size) => {
            let bytes = b.to_vec();
            let random_bytes: Vec<u8> = (0..*size).map(|_| rng.gen()).collect();
            let mutated = crate::mutator_array::mutate_ll(rng, Some(*size), random_bytes, &bytes);
            // DynSolValue::FixedBytes stores (FixedBytes<32>, actual_size)
            // We must create a 32-byte buffer with mutated data in the first `size` bytes
            let mut padded = [0u8; 32];
            let copy_len = mutated.len().min(32);
            padded[..copy_len].copy_from_slice(&mutated[..copy_len]);
            DynSolValue::FixedBytes(alloy_primitives::FixedBytes::from_slice(&padded), *size)
        }

        DynSolValue::Array(elements) => {
            DynSolValue::Array(crate::mutator_array::mutate_ll(rng, None, vec![], elements))
        }

        DynSolValue::FixedArray(elements) => {
            if elements.is_empty() {
                value.clone()
            } else {
                let len = elements.len();
                let element_type = infer_element_type(elements);
                let complement: Vec<DynSolValue> = (0..len)
                    .map(|_| generate_fresh_value(rng, &element_type))
                    .collect();

                let mutated = crate::mutator_array::mutate_ll(rng, Some(len), complement, elements);
                DynSolValue::FixedArray(mutated)
            }
        }

        DynSolValue::Tuple(elements) => {
            let new_elements: Vec<DynSolValue> =
                elements.iter().map(|e| mutate_abi_value(rng, e)).collect();
            DynSolValue::Tuple(new_elements)
        }

        _ => value.clone(),
    }
}

/// Mutate an unsigned integer
/// Simple delta mutation, no explicit boundary injection
fn mutate_num_u256<R: Rng>(rng: &mut R, x: U256) -> U256 {
    // Delta can be anything from 0 to x
    let delta = if x.is_zero() {
        U256::ZERO
    } else if x == U256::MAX {
        let random_bytes: [u8; 32] = rng.gen();
        U256::from_be_bytes(random_bytes)
    } else {
        let random_bytes: [u8; 32] = rng.gen();
        let val = U256::from_be_bytes(random_bytes);
        val % (x + U256::from(1))
    };

    if rng.gen() {
        x.saturating_add(delta)
    } else {
        x.saturating_sub(delta)
    }
}

/// Mutate a signed integer
fn mutate_num_i256<R: Rng>(rng: &mut R, x: I256) -> I256 {
    let abs_x = x.unsigned_abs();

    let delta_u256 = if abs_x.is_zero() {
        U256::ZERO
    } else {
        let random_bytes: [u8; 32] = rng.gen();
        let val = U256::from_be_bytes(random_bytes);
        val % (abs_x + U256::from(1))
    };

    if x == I256::MIN {
        return x.saturating_add(I256::unchecked_from(1i64));
    }

    // PERF: Use from_raw instead of try_from - we know delta_u256 <= abs_x <= I256::MAX
    // since x != I256::MIN (handled above), so this is safe.
    let delta = I256::from_raw(delta_u256);

    if rng.gen() {
        x.saturating_add(delta)
    } else {
        x.saturating_sub(delta)
    }
}

// mutate_bytes removed as it is replaced by mutate_ll

/// Infer the element type from a non-empty array of DynSolValues
/// Used to generate complement values for FixedArray mutation
fn infer_element_type(elements: &[DynSolValue]) -> ElementType {
    if elements.is_empty() {
        return ElementType::Unknown;
    }

    match &elements[0] {
        DynSolValue::Bool(_) => ElementType::Bool,
        DynSolValue::Uint(_, bits) => ElementType::Uint(*bits),
        DynSolValue::Int(_, bits) => ElementType::Int(*bits),
        DynSolValue::Address(_) => ElementType::Address,
        DynSolValue::Bytes(_) => ElementType::Bytes,
        DynSolValue::String(_) => ElementType::String,
        DynSolValue::FixedBytes(_, size) => ElementType::FixedBytes(*size),
        DynSolValue::Tuple(inner) => ElementType::Tuple(inner.len()),
        DynSolValue::Array(_) => ElementType::Array,
        DynSolValue::FixedArray(_) => ElementType::FixedArray,
        _ => ElementType::Unknown,
    }
}

/// Simple element type enum for complement generation
#[derive(Clone, Copy)]
enum ElementType {
    Bool,
    Uint(usize),
    Int(usize),
    Address,
    Bytes,
    String,
    FixedBytes(usize),
    Tuple(usize),
    Array,
    FixedArray,
    Unknown,
}

/// Generate a fresh random value based on inferred type
/// Used for FixedArray complement 
fn generate_fresh_value<R: Rng>(rng: &mut R, element_type: &ElementType) -> DynSolValue {
    use alloy_primitives::FixedBytes;

    match element_type {
        ElementType::Bool => DynSolValue::Bool(rng.gen()),
        ElementType::Uint(bits) => {
            let val = crate::gen::gen_random_uint(rng, *bits);
            DynSolValue::Uint(val, *bits)
        }
        ElementType::Int(bits) => {
            let val = crate::gen::gen_random_int(rng, *bits);
            DynSolValue::Int(val, *bits)
        }
        ElementType::Address => {
            let addrs = crate::gen::pregen_addresses();
            DynSolValue::Address(addrs[rng.gen_range(0..addrs.len())])
        }
        ElementType::Bytes => {
            let len = rng.gen_range(1..=32);
            let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            DynSolValue::Bytes(bytes)
        }
        ElementType::String => {
            let len = rng.gen_range(1..=32);
            let s: String = (0..len).map(|_| rng.gen_range(32u8..127) as char).collect();
            DynSolValue::String(s)
        }
        ElementType::FixedBytes(size) => {
            // DynSolValue::FixedBytes stores (FixedBytes<32>, actual_size)
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes[..*size]);
            DynSolValue::FixedBytes(FixedBytes::from_slice(&bytes), *size)
        }
        ElementType::Tuple(len) => {
            // Generate tuple with unknown element types - use uint256 as fallback
            let elements: Vec<DynSolValue> = (0..*len)
                .map(|_| DynSolValue::Uint(crate::gen::gen_random_uint(rng, 256), 256))
                .collect();
            DynSolValue::Tuple(elements)
        }
        ElementType::Array | ElementType::FixedArray => {
            // Nested arrays - generate empty for simplicity
            DynSolValue::Array(vec![])
        }
        ElementType::Unknown => {
            // Fallback to uint256
            DynSolValue::Uint(crate::gen::gen_random_uint(rng, 256), 256)
        }
    }
}

/// Mutate a call's arguments
/// Always mutate exactly one argument
pub fn mutate_call<R: Rng>(
    rng: &mut R,
    name: &str,
    args: &[DynSolValue],
) -> (String, Vec<DynSolValue>) {
    if args.is_empty() {
        return (name.to_string(), vec![]);
    }

    let mut new_args = args.to_vec();

    // Mutate a single random argument (matches Echidna exactly)
    let idx = rng.gen_range(0..args.len());
    new_args[idx] = mutate_abi_value(rng, &args[idx]);

    (name.to_string(), new_args)
}

// ============================================================================
// Enhanced Mutation (using Mutable trait)
// ============================================================================

/// Enhanced mutation using the Mutable trait
/// Uses AFL++ style strategies including bit flips, interesting values, etc.
///
/// This is the recommended mutation function for new code.
/// providing richer mutation strategies.
pub fn mutate_abi_value_enhanced<R: Rng>(rng: &mut R, value: &DynSolValue) -> DynSolValue {
    let mut result = value.clone();
    result.mutate(rng);
    result
}

/// Enhanced call mutation using the Mutable trait
/// Mutates exactly one argument  using enhanced strategies
pub fn mutate_call_enhanced<R: Rng>(
    rng: &mut R,
    name: &str,
    args: &[DynSolValue],
) -> (String, Vec<DynSolValue>) {
    if args.is_empty() {
        return (name.to_string(), vec![]);
    }

    let mut new_args = args.to_vec();

    // Mutate a single random argument (matches Echidna exactly)
    let idx = rng.gen_range(0..args.len());
    new_args[idx].mutate(rng);

    (name.to_string(), new_args)
}

/// Mutate multiple arguments using enhanced strategies
/// Unlike mutate_call which mutates exactly one argument,
/// this can mutate multiple arguments for more aggressive exploration
pub fn mutate_call_multi<R: Rng>(
    rng: &mut R,
    name: &str,
    args: &[DynSolValue],
    mutation_probability: f32,
) -> (String, Vec<DynSolValue>) {
    if args.is_empty() {
        return (name.to_string(), vec![]);
    }

    let mut new_args = args.to_vec();

    // Each argument has mutation_probability chance of being mutated
    for arg in new_args.iter_mut() {
        if rng.gen::<f32>() < mutation_probability {
            arg.mutate(rng);
        }
    }

    (name.to_string(), new_args)
}

#[cfg(test)]
#[path = "mutate_tests.rs"]
mod tests;
