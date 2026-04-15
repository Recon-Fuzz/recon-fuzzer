//! ABI value shrinking for test minimization

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{Address, I256, U256};
use rand::prelude::*;

/// Check if a value can be shrunk further
pub fn can_shrink(value: &DynSolValue) -> bool {
    match value {
        DynSolValue::Uint(n, _) => *n != U256::ZERO,
        DynSolValue::Int(n, _) => *n != I256::ZERO,
        DynSolValue::Bool(b) => *b, // true can shrink to false
        DynSolValue::Address(a) => *a != Address::ZERO,
        DynSolValue::Bytes(b) => !b.is_empty(),
        DynSolValue::String(s) => !s.is_empty(),
        DynSolValue::FixedBytes(b, _) => b.iter().any(|&x| x != 0),
        DynSolValue::Array(elements) => !elements.is_empty() || elements.iter().any(can_shrink),
        DynSolValue::FixedArray(elements) => elements.iter().any(can_shrink),
        DynSolValue::Tuple(elements) => elements.iter().any(can_shrink),
        _ => true,
    }
}

/// Shrink an ABI value to a simpler version
pub fn shrink_abi_value<R: Rng>(rng: &mut R, value: &DynSolValue) -> DynSolValue {
    match value {
        DynSolValue::Uint(n, bits) => {
            // Shrink to a random value between 0 and current
            let shrunk = if *n == U256::ZERO {
                U256::ZERO
            } else {
                let random_bytes: [u8; 32] = rng.gen();
                U256::from_be_bytes(random_bytes) % *n
            };
            DynSolValue::Uint(shrunk, *bits)
        }

        DynSolValue::Int(n, bits) => {
            // Shrink towards zero
            let shrunk = if *n == I256::ZERO {
                I256::ZERO
            } else if *n > I256::ZERO {
                // Positive: shrink to random in [0, n]
                let random_bytes: [u8; 32] = rng.gen();
                let rand_val = I256::from_be_bytes(random_bytes).abs();
                if rand_val < *n {
                    rand_val
                } else {
                    I256::ZERO
                }
            } else {
                // Negative: shrink to random in [n, 0]
                let random_bytes: [u8; 32] = rng.gen();
                let rand_val = -I256::from_be_bytes(random_bytes).abs();
                if rand_val > *n {
                    rand_val
                } else {
                    I256::ZERO
                }
            };
            DynSolValue::Int(shrunk, *bits)
        }

        DynSolValue::Address(_) => {
            // Shrink to zero address or deadbeef
            if rng.gen() {
                DynSolValue::Address(Address::ZERO)
            } else {
                DynSolValue::Address(Address::from_word(U256::from(0xdeadbeefu64).into()))
            }
        }

        DynSolValue::Bool(_) => DynSolValue::Bool(false),

        DynSolValue::Bytes(b) => {
            // Shrink by removing bytes and adding nulls
            let new_len = if b.is_empty() {
                0
            } else {
                rng.gen_range(0..b.len())
            };
            let mut shrunk: Vec<u8> = b.iter().take(new_len).cloned().collect();
            // Replace some bytes with nulls
            for byte in &mut shrunk {
                if rng.gen_range(0..4) == 0 {
                    *byte = 0;
                }
            }
            DynSolValue::Bytes(shrunk)
        }

        DynSolValue::String(s) => {
            let bytes = s.as_bytes();
            let new_len = if bytes.is_empty() {
                0
            } else {
                rng.gen_range(0..bytes.len())
            };
            let shrunk = String::from_utf8_lossy(&bytes[..new_len]).to_string();
            DynSolValue::String(shrunk)
        }

        DynSolValue::FixedBytes(b, size) => {
            // Add nulls to some positions
            // DynSolValue::FixedBytes stores (FixedBytes<32>, actual_size)
            let mut bytes = b.0; // Get the full 32-byte array
            for byte in &mut bytes[..*size] {
                if rng.gen_range(0..4) == 0 {
                    *byte = 0;
                }
            }
            DynSolValue::FixedBytes(alloy_primitives::FixedBytes::from_slice(&bytes), *size)
        }

        DynSolValue::Array(elements) => {
            // 10% chance to shrink elements, 90% to remove elements
            if rng.gen_range(0..10) == 0 {
                // Shrink all elements
                let shrunk: Vec<DynSolValue> =
                    elements.iter().map(|e| shrink_abi_value(rng, e)).collect();
                DynSolValue::Array(shrunk)
            } else {
                // Remove some elements
                shrink_vec(rng, elements)
                    .map(DynSolValue::Array)
                    .unwrap_or_else(|| DynSolValue::Array(vec![]))
            }
        }

        DynSolValue::FixedArray(elements) => {
            // Can only shrink element values, not remove them
            let shrunk: Vec<DynSolValue> = elements
                .iter()
                .map(|e| {
                    if rng.gen() {
                        shrink_abi_value(rng, e)
                    } else {
                        e.clone()
                    }
                })
                .collect();
            DynSolValue::FixedArray(shrunk)
        }

        DynSolValue::Tuple(elements) => {
            let shrunk: Vec<DynSolValue> = elements
                .iter()
                .map(|e| {
                    if rng.gen() {
                        shrink_abi_value(rng, e)
                    } else {
                        e.clone()
                    }
                })
                .collect();
            DynSolValue::Tuple(shrunk)
        }

        _ => value.clone(),
    }
}

/// Shrink a vector by removing elements at random
fn shrink_vec<R: Rng>(rng: &mut R, v: &[DynSolValue]) -> Option<Vec<DynSolValue>> {
    if v.is_empty() {
        return None;
    }
    let start = rng.gen_range(0..v.len());
    let end = rng.gen_range(start..=v.len());
    Some([&v[..start], &v[end..]].concat())
}

/// Shrink a call by simplifying its arguments
pub fn shrink_call<R: Rng>(
    rng: &mut R,
    name: &str,
    args: &[DynSolValue],
) -> (String, Vec<DynSolValue>) {
    let shrinkable_count = args.iter().filter(|a| can_shrink(a)).count();
    if shrinkable_count == 0 {
        return (name.to_string(), args.to_vec());
    }

    // Decide how many to shrink
    let halfway = shrinkable_count / 2;
    let num_to_shrink_options = [1, 2, halfway, shrinkable_count];
    // Clamp to shrinkable_count to ensure prob <= 1.0 (prevents InvalidProbability panic)
    let initial_num_to_shrink = (*num_to_shrink_options.choose(rng).unwrap_or(&1)).min(shrinkable_count);

    // Track state as we iterate 
    let mut num_shrinkable = shrinkable_count;
    let mut num_to_shrink = initial_num_to_shrink;

    let shrunk_args: Vec<DynSolValue> = args
        .iter()
        .map(|arg| {
            if !can_shrink(arg) {
                // Non-shrinkable args pass through unchanged
                return arg.clone();
            }

            // shouldShrink <- fromList [(True, numToShrink), (False, numShrinkable-numToShrink)]
            // Probability of shrinking = numToShrink / numShrinkable
            let should_shrink = if num_shrinkable > 0 && num_to_shrink > 0 {
                let prob = num_to_shrink as f64 / num_shrinkable as f64;
                rng.gen_bool(prob)
            } else {
                false
            };

            // Decrement num_shrinkable for each shrinkable arg we process
            num_shrinkable = num_shrinkable.saturating_sub(1);

            if should_shrink {
                // Decrement num_to_shrink when we actually shrink
                num_to_shrink = num_to_shrink.saturating_sub(1);
                shrink_abi_value(rng, arg)
            } else {
                arg.clone()
            }
        })
        .collect();

    (name.to_string(), shrunk_args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_can_shrink() {
        assert!(!can_shrink(&DynSolValue::Uint(U256::ZERO, 256)));
        assert!(can_shrink(&DynSolValue::Uint(U256::from(100), 256)));
        assert!(!can_shrink(&DynSolValue::Bool(false)));
        assert!(can_shrink(&DynSolValue::Bool(true)));
    }

    #[test]
    fn test_shrink_uint() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let val = DynSolValue::Uint(U256::from(1000), 256);
        let shrunk = shrink_abi_value(&mut rng, &val);
        if let DynSolValue::Uint(n, _) = shrunk {
            assert!(n <= U256::from(1000));
        } else {
            panic!("Expected uint");
        }
    }

    #[test]
    fn test_shrink_bytes_can_produce_empty() {
        // Shrinking should be able to produce empty bytes
        // This is critical for minimizing test cases that trigger callback skips
        let mut found_empty = false;

        for seed in 0..100 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let val = DynSolValue::Bytes(vec![1u8, 2, 3]);
            let shrunk = shrink_abi_value(&mut rng, &val);
            if let DynSolValue::Bytes(b) = shrunk {
                if b.is_empty() {
                    found_empty = true;
                    break;
                }
            }
        }
        assert!(found_empty, "Shrinking should eventually produce empty bytes ");
    }

    #[test]
    fn test_empty_bytes_cannot_shrink() {
        // Empty bytes should not be shrinkable (already minimal)
        assert!(!can_shrink(&DynSolValue::Bytes(vec![])));
    }
}
