//! Bytecode constant extraction
//!
//! Extracts numeric constants from EVM bytecode PUSH instructions.

use alloy_primitives::{I256, U256};
use std::collections::HashSet;

/// EVM PUSH opcodes (0x60 = PUSH1, 0x7f = PUSH32)
const PUSH1: u8 = 0x60;
const PUSH32: u8 = 0x7f;

/// Extract all numeric constants from bytecode
/// Returns U256 values from PUSH1-PUSH32 instructions
pub fn extract_constants(bytecode: &[u8]) -> HashSet<U256> {
    let mut constants = HashSet::new();
    let mut i = 0;

    while i < bytecode.len() {
        let opcode = bytecode[i];

        // Check if this is a PUSH opcode (0x60-0x7f)
        if opcode >= PUSH1 && opcode <= PUSH32 {
            let push_size = (opcode - PUSH1 + 1) as usize; // 1-32 bytes
            let start = i + 1;
            let end = start + push_size;

            if end <= bytecode.len() {
                // Extract the constant
                let data = &bytecode[start..end];

                // Convert to U256 (big-endian)
                let mut bytes = [0u8; 32];
                bytes[32 - push_size..].copy_from_slice(data);
                let value = U256::from_be_bytes(bytes);

                // Check if value is interesting:
                // 1. Small positive values (2 to 2^80)
                // 2. Large negative values in 2's complement (values close to MAX)
                let is_small_positive = value > U256::from(1) && value < U256::from(1u128 << 80);

                // Check if it looks like a negative number (top bit set, and most upper bytes are 0xff)
                // A 256-bit negative number like -4242 would be 0xffff...ef6e
                let is_negative_looking = {
                    let bytes = value.to_be_bytes::<32>();
                    // Check if upper bytes are mostly 0xff (indicating sign extension)
                    let ff_count = bytes.iter().take(24).filter(|&&b| b == 0xff).count();
                    ff_count >= 20 && bytes[0] == 0xff
                };

                if is_small_positive || is_negative_looking {
                    constants.insert(value);
                }

                // Skip past the PUSH data
                i = end;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    constants
}

/// Extract constants and generate both positive and negative variants
/// Returns (unsigned_constants, signed_variants)
pub fn extract_constants_with_variants(bytecode: &[u8]) -> (HashSet<U256>, HashSet<I256>) {
    let raw_constants = extract_constants(bytecode);
    let mut unsigned = HashSet::new();
    let mut signed = HashSet::new();

    for val in raw_constants {
        // Add unsigned value
        unsigned.insert(val);

        // Convert to signed I256 for analysis
        let signed_val = I256::from_raw(val);

        // Determine if this is a negative or positive value
        let is_negative = signed_val < I256::ZERO;

        if is_negative {
            // For negative values like -4242 (stored as 0xffff...ef6e)
            // Add the signed value and generate variants
            signed.insert(signed_val);

            // Generate variants: val-3 to val+3 and positive counterpart
            for offset in -3i64..=3 {
                // Variants around the negative value
                let variant =
                    signed_val.saturating_add(I256::try_from(offset).unwrap_or(I256::ZERO));
                signed.insert(variant);

                // Also add the positive counterpart (-signed_val)
                let pos_variant = -signed_val + I256::try_from(offset).unwrap_or(I256::ZERO);
                signed.insert(pos_variant);
                if pos_variant >= I256::ZERO {
                    if let Ok(u) = pos_variant.try_into() {
                        unsigned.insert(u);
                    }
                }
            }
        } else {
            // For positive values, generate signed variants if value fits in i128
            if val <= U256::from(i128::MAX as u128) {
                let n: i128 = val.try_into().unwrap_or(0);

                // Generate n-3 to n+3 and their negations (Echidna's makeNumAbiValues)
                for offset in -3i128..=3 {
                    // Positive variants
                    if let Ok(v) = I256::try_from(n.saturating_add(offset)) {
                        signed.insert(v);
                        if v >= I256::ZERO {
                            if let Ok(u) = v.try_into() {
                                unsigned.insert(u);
                            }
                        }
                    }

                    // Negative variants
                    let neg_n = n.saturating_neg();
                    if let Ok(v) = I256::try_from(neg_n.saturating_add(offset)) {
                        signed.insert(v);
                    }
                }
            }
        }
    }

    (unsigned, signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_push1() {
        // PUSH1 0x42
        let bytecode = vec![0x60, 0x42];
        let constants = extract_constants(&bytecode);
        assert!(constants.contains(&U256::from(0x42)));
    }

    #[test]
    fn test_extract_push2() {
        // PUSH2 0x1092 (4242)
        let bytecode = vec![0x61, 0x10, 0x92];
        let constants = extract_constants(&bytecode);
        assert!(constants.contains(&U256::from(4242)));
    }

    #[test]
    fn test_extract_with_variants() {
        // PUSH2 0x1092 (4242)
        let bytecode = vec![0x61, 0x10, 0x92];
        let (unsigned, signed) = extract_constants_with_variants(&bytecode);

        // Should have 4242 and variants
        assert!(unsigned.contains(&U256::from(4242)));
        assert!(unsigned.contains(&U256::from(4239))); // 4242 - 3
        assert!(unsigned.contains(&U256::from(4245))); // 4242 + 3

        // Should have negative variants
        assert!(signed.contains(&I256::try_from(-4242i64).unwrap()));
        assert!(signed.contains(&I256::try_from(-4239i64).unwrap())); // -4242 + 3
        assert!(signed.contains(&I256::try_from(-4245i64).unwrap())); // -4242 - 3
    }

    #[test]
    fn test_extract_multiple() {
        // PUSH1 0x05 PUSH2 0x1092 PUSH1 0x0A
        let bytecode = vec![0x60, 0x05, 0x61, 0x10, 0x92, 0x60, 0x0A];
        let constants = extract_constants(&bytecode);
        assert!(constants.contains(&U256::from(5)));
        assert!(constants.contains(&U256::from(4242)));
        assert!(constants.contains(&U256::from(10)));
    }

    #[test]
    fn test_extract_negative_constant() {
        // PUSH32 with -4242 in 2's complement (0xffff...ef6e)
        // -4242 in 256-bit 2's complement
        let neg_4242 = I256::try_from(-4242i64).unwrap();
        let neg_bytes = neg_4242.to_be_bytes::<32>();

        let mut bytecode = vec![0x7f]; // PUSH32
        bytecode.extend_from_slice(&neg_bytes);

        let constants = extract_constants(&bytecode);
        // Should extract the raw U256 representation
        assert!(!constants.is_empty(), "Should extract the negative constant");

        let (unsigned, signed) = extract_constants_with_variants(&bytecode);

        // Should have -4242 in signed
        assert!(
            signed.contains(&I256::try_from(-4242i64).unwrap()),
            "Should have -4242"
        );
        // Should also have the positive counterpart 4242
        assert!(
            signed.contains(&I256::try_from(4242i64).unwrap()),
            "Should have +4242"
        );
        assert!(
            unsigned.contains(&U256::from(4242u64)),
            "Should have unsigned 4242"
        );

        // Variants
        assert!(
            signed.contains(&I256::try_from(-4239i64).unwrap()),
            "Should have -4239"
        );
        assert!(
            signed.contains(&I256::try_from(-4245i64).unwrap()),
            "Should have -4245"
        );
    }
}
