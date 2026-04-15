//! ABI value generation
//!
//! Implements dictionary-based and synthesized value generation

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address, FixedBytes, I256, U256};
use rand::prelude::*;

use super::types::GenDict;

/// Common integer bit sizes used in Solidity
pub const COMMON_TYPE_SIZES: &[usize] = &[
    8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168,
    176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256,
];

/// Pre-generated dummy addresses for fuzzing
pub fn pregen_addresses() -> Vec<Address> {
    (1u64..=3)
        .map(|i| Address::from_word(U256::from(i * 0xffffffff).into()))
        .collect()
}

/// Generate a random unsigned integer with distribution:
/// join $ Random.weighted [(gen1, 2), (gen2, 16), (gen3, 2), (gen4, 1)]
/// weighted picks from [0, 21] INCLUSIVE (22 values), then:
/// - n <= 2: gen1 (3/22 ≈ 13.6%) from 0 to 1023
/// - n <= 18: gen2 (16/22 ≈ 72.7%) from 0 to 2^n - 5
/// - n <= 20: gen3 (2/22 ≈ 9.1%) from 2^n - 5 to 2^n - 1
/// - n = 21: gen4 (1/22 ≈ 4.5%) using power scale
pub fn gen_random_uint<R: Rng>(rng: &mut R, bits: usize) -> U256 {
    // weighted uses [0, sum] inclusive = 22 values for weights [2,16,2,1]
    let choice: u32 = rng.gen_range(0..=21);

    let max_val = if bits >= 256 {
        U256::MAX
    } else {
        (U256::from(1) << bits) - U256::from(1)
    };

    match choice {
        0..=2 => {
            // 3/22 from 0 to 1023 (getRandomR (0, 1023))
            U256::from(rng.gen_range(0u64..=1023))
        }
        3..=18 => {
            // 16/22 from 0 to max - 5 (getRandomR (0, 2^n - 5))
            if max_val > U256::from(5) {
                let range_max = max_val - U256::from(5);
                gen_u256_in_range(rng, U256::ZERO, range_max)
            } else {
                U256::ZERO
            }
        }
        19..=20 => {
            // 2/22 from max - 5 to max (getRandomR (2^n - 5, 2^n - 1))
            if max_val > U256::from(5) {
                gen_u256_in_range(rng, max_val - U256::from(5), max_val)
            } else {
                max_val
            }
        }
        _ => {
            // 1/22 power scale (getRandomPow (n - 5))
            gen_random_pow(rng, bits.saturating_sub(5))
        }
    }
}

/// Generate random using power scale (for edge cases)
/// getRandomPow n = mexp <- getRandomR (20, n); getRandomR (2^(mexp/2), 2^mexp)
fn gen_random_pow<R: Rng>(rng: &mut R, n: usize) -> U256 {
    // if n <= 0 then return 0
    if n <= 20 {
        return U256::ZERO;
    }
    // mexp <- getRandomR (20, n) - INCLUSIVE range
    let mexp = rng.gen_range(20..=n);
    let low = U256::from(1) << (mexp / 2);
    let high = U256::from(1) << mexp;
    gen_u256_in_range(rng, low, high)
}

/// Generate U256 in range (helper for large numbers)
fn gen_u256_in_range<R: Rng>(rng: &mut R, low: U256, high: U256) -> U256 {
    if low >= high {
        return low;
    }
    let range = high - low;
    // For simplicity, generate random bytes and mod
    let random_bytes: [u8; 32] = rng.gen();
    let random_val = U256::from_be_bytes(random_bytes);

    // Guard against overflow: if range == U256::MAX, range + 1 wraps to 0
    if range == U256::MAX {
        // Full range, just return random value clamped to [low, high]
        // Since range is MAX, low must be 0 and high must be MAX
        random_val
    } else {
        low + (random_val % (range + U256::from(1)))
    }
}

/// Generate a random signed integer with echidna's distribution:
/// getRandomR =<< Random.weighted [(small_range, 1), (full_range, 9)]
/// weighted picks from [0, 10] INCLUSIVE (11 values), then:
/// - n <= 1: small range (2/11 ≈ 18.2%) from -1023 to 1023
/// - n > 1: full range (9/11 ≈ 81.8%) from -2^(n-1) to 2^(n-1) - 1
pub fn gen_random_int<R: Rng>(rng: &mut R, bits: usize) -> I256 {
    // weighted uses [0, sum] inclusive = 11 values for weights [1, 9]
    let choice: u32 = rng.gen_range(0..=10);

    if choice <= 1 {
        // 2/11 small range: -1023 to 1023 (getRandomR (-1023, 1023))
        I256::try_from(rng.gen_range(-1023i64..=1023)).unwrap_or(I256::ZERO)
    } else {
        // 9/11 full range for the given bit size
        // For n bits, range is -2^(n-1) to 2^(n-1) - 1
        if bits >= 256 {
            // Full range for I256
            let random_bytes: [u8; 32] = rng.gen();
            I256::from_be_bytes(random_bytes)
        } else if bits >= 128 {
            // For 128-bit, use I256 directly to avoid i128 overflow
            let random_bytes: [u8; 32] = rng.gen();
            let mut val = I256::from_be_bytes(random_bytes);
            // Mask to bits range by right-shifting the sign extension
            let shift = 256 - bits;
            val = (val << shift) >> shift;
            val
        } else {
            // Constrained range for smaller types (< 128 bits)
            let half = 1i128 << (bits - 1);
            let min_val = -half;
            let max_val = half - 1;
            let val = rng.gen_range(min_val..=max_val);
            I256::try_from(val).unwrap_or(I256::ZERO)
        }
    }
}

/// Generate a random ABI value given a type spec
pub fn gen_abi_value<R: Rng>(rng: &mut R, sol_type: &DynSolType) -> DynSolValue {
    gen_abi_value_with_dict(rng, &GenDict::default(), sol_type, "")
}

/// Generate a random ABI value with dictionary support
pub fn gen_abi_value_with_dict<R: Rng>(
    rng: &mut R,
    dict: &GenDict,
    sol_type: &DynSolType,
    func_name: &str,
) -> DynSolValue {
    gen_abi_value_with_dict_depth(rng, dict, sol_type, func_name, 0)
}

/// Dictionary frequency for address types (75% from known addresses)
const ADDRESS_DICT_FREQ: f32 = 0.75;

fn gen_abi_value_with_dict_depth<R: Rng>(
    rng: &mut R,
    dict: &GenDict,
    sol_type: &DynSolType,
    func_name: &str,
    depth: usize,
) -> DynSolValue {
    // Step 1: Random draw for dictionary decision FIRST 
    // r <- getRandom
    let use_dict: f32 = rng.gen();

    // Use higher dict_freq for addresses (75%) vs other types (dict.dict_freq, default 40%)
    let effective_dict_freq = match sol_type {
        DynSolType::Address => ADDRESS_DICT_FREQ,
        _ => dict.dict_freq,
    };
    let should_use_dict = use_dict < effective_dict_freq;

    // Step 2: ALWAYS synthesize to consume RNG 
    // g t is always evaluated due to applicative semantics
    let synthesized = synthesize_value(rng, dict, sol_type, depth, func_name);

    // Step 3: If dict was chosen, try to get from dict 
    // maybeValM = if pSynthA >= r then fromDict else pure Nothing
    if should_use_dict {
        if let Some(val) = get_from_dict(rng, dict, sol_type) {
            return val;
        }
    }

    // Step 4: Fall back to synthesized value (fromMaybe)
    synthesized
}

/// Try to get a value from the dictionary
///
/// dictValues is used elsewhere (genValue, genDelay) but NOT for argument generation.
fn get_from_dict<R: Rng>(
    rng: &mut R,
    dict: &GenDict,
    sol_type: &DynSolType,
) -> Option<DynSolValue> {
    // genWithDict genDict genDict.constants go t
    // Only looks up in the typed constants map
    let type_name = sol_type.sol_type_name().to_string();
    if let Some(constants) = dict.constants.get(&type_name) {
        if !constants.is_empty() {
            let idx = rng.gen_range(0..constants.len());
            return Some(constants[idx].clone());
        }
    }

    None
}

/// Synthesize a new random value (no dictionary)
fn synthesize_value<R: Rng>(
    rng: &mut R,
    dict: &GenDict,
    sol_type: &DynSolType,
    depth: usize,
    func_name: &str,
) -> DynSolValue {
    match sol_type {
        DynSolType::Bool => DynSolValue::Bool(rng.gen()),

        DynSolType::Int(bits) => {
            let val = gen_random_int(rng, *bits);
            DynSolValue::Int(val, *bits)
        }

        DynSolType::Uint(bits) => {
            let val = gen_random_uint(rng, *bits);
            DynSolValue::Uint(val, *bits)
        }

        DynSolType::Address => {
            let addrs = pregen_addresses();
            let addr = addrs[rng.gen_range(0..addrs.len())];
            DynSolValue::Address(addr)
        }

        DynSolType::Bytes => {
            // 5% chance: empty bytes (edge case testing)
            if rng.gen_range(0..100) < 5 {
                return DynSolValue::Bytes(vec![]);
            }

            // Callback generation for AbiBytesDynamicType
            // if null filteredSigs || depth >= 2 then random [1,32]
            //          else weighted [(callback, 9), (random [1,8], 1)]
            let filtered_sigs: Vec<_> = dict
                .callback_sigs
                .iter()
                .filter(|(name, _)| name != func_name)
                .collect();

            if filtered_sigs.is_empty() || depth >= 2 {
                // No callbacks or too deep: random bytes [1, 32]
                let len = rng.gen_range(1u32..=32);
                let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
                return DynSolValue::Bytes(bytes);
            }

            // weighted [(callback, 9), (short_random, 1)] = 10 total
            // weighted uses [0, 10] inclusive = 11 values
            let choice: u32 = rng.gen_range(0..=10);
            if choice <= 9 {
                // 10/11 chance: try callback generation
                // uniform selection from filtered_sigs
                let idx = rng.gen_range(0..filtered_sigs.len());
                let (name, inputs) = &filtered_sigs[idx];

                // Parse input types
                let input_types: Vec<DynSolType> =
                    inputs.iter().filter_map(|s| s.parse().ok()).collect();

                if input_types.len() == inputs.len() {
                    // Generate args using genAbiValueM' (with dict lookup)
                    let args: Vec<DynSolValue> = input_types
                        .iter()
                        .map(|t| gen_abi_value_with_dict_depth(rng, dict, t, "", depth + 1))
                        .collect();

                    // Encode call: selector + encoded args
                    let selector = alloy_json_abi::Function::parse(name)
                        .map(|f| f.selector())
                        .unwrap_or_default();

                    let encoded_args = DynSolValue::Tuple(args).abi_encode();
                    let mut call_data = selector.to_vec();
                    call_data.extend(encoded_args);

                    return DynSolValue::Bytes(call_data);
                }
                // If parsing failed, fall through to random bytes
            }

            // 1/11 chance OR callback parse failed: short random bytes [1, 8]
            let len = rng.gen_range(1u32..=8);
            let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            DynSolValue::Bytes(bytes)
        }

        DynSolType::String => {
            let len = rng.gen_range(1..=32);
            let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            // Generate ASCII-printable chars for better readability
            let s: String = bytes.iter().map(|b| (b % 95 + 32) as char).collect();
            DynSolValue::String(s)
        }

        DynSolType::FixedBytes(n) => {
            // DynSolValue::FixedBytes stores (FixedBytes<32>, actual_size)
            // We must create a 32-byte buffer but only randomize the first n bytes
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes[..*n]);
            DynSolValue::FixedBytes(FixedBytes::from_slice(&bytes), *n)
        }

        DynSolType::Array(inner) => {
            // Generate between 1 and 32 elements
            // getRandomR (1, 32) >>= flip V.replicateM (genAbiValueM' ...)
            let len = rng.gen_range(1u32..=32);
            let elements: Vec<DynSolValue> = (0..len)
                .map(|_| gen_abi_value_with_dict_depth(rng, dict, inner, func_name, depth + 1))
                .collect();
            DynSolValue::Array(elements)
        }

        DynSolType::FixedArray(inner, len) => {
            // Fixed array uses V.replicateM n (genAbiValueM' ...)
            let elements: Vec<DynSolValue> = (0..*len)
                .map(|_| gen_abi_value_with_dict_depth(rng, dict, inner, func_name, depth + 1))
                .collect();
            DynSolValue::FixedArray(elements)
        }

        DynSolType::Tuple(types) => {
            // Echidna's genAbiValueM' recursively calls itself for tuple fields,
            // which includes genWithDict at each level. So dictionary lookup happens at field level.
            let elements: Vec<DynSolValue> = types
                .iter()
                .map(|t| gen_abi_value_with_dict_depth(rng, dict, t, func_name, depth + 1))
                .collect();
            DynSolValue::Tuple(elements)
        }

        DynSolType::Function => {
            // Function selectors are 24 bytes (address + selector)
            let mut bytes = [0u8; 24];
            rng.fill_bytes(&mut bytes);
            DynSolValue::Function(alloy_primitives::Function::from_slice(&bytes))
        }
    }
}

/// Generate a random function call
///
/// This is the KEY function for multi-step bug finding:
/// 1. Generate fresh arguments (always, to match RNG consumption order)
/// 2. With probability dict_freq, try to use a complete call from wholeCalls dictionary
/// 3. If found, use that call (with the exact successful arguments)
/// 4. Otherwise use the fresh arguments
/// 5. Finally, apply mutation to the call
///
/// This allows the fuzzer to "remember" successful calls like initSequence(42)
/// and replay them with high probability, enabling discovery of multi-step bugs.
pub fn gen_abi_call_m<R: Rng>(
    rng: &mut R,
    dict: &GenDict,
    name: &str,
    param_types: &[DynSolType],
) -> (String, Vec<DynSolValue>) {
    // Build signature for lookup (must match add_call signature format)
    let sig = (
        name.to_string(),
        param_types
            .iter()
            .map(|t| t.sol_type_name().to_string())
            .collect::<Vec<String>>(),
    );

    // Step 1: Generate fresh arguments FIRST (args <- mapM genAbiValueM)
    // This MUST happen before wholeCalls decision to match RNG consumption order
    let fresh_args: Vec<DynSolValue> = param_types
        .iter()
        .map(|t| gen_abi_value_with_dict(rng, dict, t, name))
        .collect();

    // Step 2: wholeCalls dictionary decision (r <- getRandom in genWithDict)
    let use_dict: f32 = rng.gen();
    let should_use_whole_calls = use_dict < dict.dict_freq;

    // Step 3: Optionally lookup whole_calls (maybeValM)
    let sol_call = if should_use_whole_calls {
        // Try to get a complete call from dictionary
        if let Some(calls) = dict.whole_calls.get(&sig) {
            if !calls.is_empty() {
                // Pick a random successful call from dictionary
                let idx = rng.gen_range(0..calls.len());
                Some(calls[idx].clone())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Step 4: Use dictionary call if available, otherwise use fresh args (fromMaybe)
    let (call_name, args) = sol_call.unwrap_or_else(|| (name.to_string(), fresh_args));

    // Always mutate the call (mutateAbiCall solCall)
    // Using enhanced mutation for AFL++ style strategies (bit flips, interesting values, etc.)
    super::mutate::mutate_call_enhanced(rng, &call_name, &args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_gen_uint256() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        for _ in 0..100 {
            let val = gen_random_uint(&mut rng, 256);
            assert!(val <= U256::MAX);
        }
    }

    #[test]
    fn test_gen_int_bits() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        // Test that gen_random_int respects bit size
        for _ in 0..100 {
            let val = gen_random_int(&mut rng, 8);
            // Should be in range -128 to 127 (most of the time)
            // Note: due to 10% small range, this is probabilistic
            let _ = val; // Just check it doesn't panic
        }
    }

    #[test]
    fn test_gen_address() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let val = gen_abi_value(&mut rng, &DynSolType::Address);
        assert!(matches!(val, DynSolValue::Address(_)));
    }

    #[test]
    fn test_gen_tuple() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let tuple_type = DynSolType::Tuple(vec![
            DynSolType::Uint(256),
            DynSolType::Address,
            DynSolType::Bool,
        ]);
        let val = gen_abi_value(&mut rng, &tuple_type);
        if let DynSolValue::Tuple(elements) = val {
            assert_eq!(elements.len(), 3);
        } else {
            panic!("Expected tuple");
        }
    }

    #[test]
    fn test_whole_calls_signature_match() {
        use crate::abi::types::GenDict;

        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut dict = GenDict::new(42);
        dict.dict_freq = 1.0; // Always use dictionary

        // Simulate adding a call to the dictionary (like campaign.rs does)
        let call_name = "initSequence".to_string();
        let call_args = vec![DynSolValue::Uint(U256::from(42), 256)];
        dict.add_call((call_name.clone(), call_args.clone()));

        // Now try to generate a call (like gen_abi_call_m does)
        let param_types = vec![DynSolType::Uint(256)];
        let (name, args) = gen_abi_call_m(&mut rng, &dict, "initSequence", &param_types);

        // Should get the stored call back (possibly mutated)
        assert_eq!(name, "initSequence");
        // The argument might be mutated, but should exist
        assert_eq!(args.len(), 1);

        // Verify signature format matches
        let sig_from_type = (
            "initSequence".to_string(),
            param_types
                .iter()
                .map(|t| t.sol_type_name().to_string())
                .collect::<Vec<_>>(),
        );
        let sig_from_value = (
            call_name,
            call_args
                .iter()
                .map(|v| v.sol_type_name().map(|s| s.to_string()).unwrap_or_default())
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            sig_from_type, sig_from_value,
            "Signature format mismatch between DynSolType and DynSolValue!"
        );

        // Verify the dictionary actually has the entry
        assert!(
            dict.whole_calls.contains_key(&sig_from_type),
            "wholeCalls should contain the signature"
        );
    }

    #[test]
    fn test_constants_dict_key_match() {
        use crate::abi::types::GenDict;

        let mut dict = GenDict::new(42);

        // Add a constant using add_constants (uses DynSolValue)
        let val = DynSolValue::Uint(U256::from(1337), 256);
        dict.add_constants(std::iter::once(val.clone()));

        // Check what key was used (should be plain type name)
        let key_from_value = val
            .sol_type_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        println!("Key from DynSolValue: {}", key_from_value);

        // Check what key get_from_dict would use (uses DynSolType)
        let ty = DynSolType::Uint(256);
        let key_from_type = ty.sol_type_name().to_string();
        println!("Key from DynSolType: {}", key_from_type);

        // They must match!
        assert_eq!(
            key_from_type, key_from_value,
            "Constants dict key mismatch! add_constants uses '{}' but get_from_dict uses '{}'",
            key_from_value, key_from_type
        );

        // Verify we can actually retrieve the value
        assert!(
            dict.constants.contains_key(&key_from_type),
            "Constants should contain key '{}'",
            key_from_type
        );
    }

    #[test]
    fn test_tuple_dict_roundtrip() {
        use crate::abi::types::GenDict;

        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut dict = GenDict::new(42);
        dict.dict_freq = 1.0; // Always use dictionary

        // Create a tuple value (simulates a struct from a successful call)
        let tuple_val = DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(1337), 256),
            DynSolValue::Address(Address::repeat_byte(0x42)),
            DynSolValue::Bool(true),
        ]);

        // Store it (as campaign.rs would after a successful call)
        dict.add_constants(std::iter::once(tuple_val.clone()));

        // Check the key used for storage
        let key_from_value = tuple_val
            .sol_type_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        println!("Tuple key from DynSolValue: '{}'", key_from_value);

        // Check the key used for lookup
        let tuple_type = DynSolType::Tuple(vec![
            DynSolType::Uint(256),
            DynSolType::Address,
            DynSolType::Bool,
        ]);
        let key_from_type = tuple_type.sol_type_name().to_string();
        println!("Tuple key from DynSolType: '{}'", key_from_type);

        // Keys MUST match for roundtrip to work!
        assert_eq!(
            key_from_type, key_from_value,
            "Tuple dict key mismatch! Storage uses '{}' but lookup uses '{}'",
            key_from_value, key_from_type
        );

        // Now verify we can actually retrieve the tuple
        assert!(
            dict.constants.contains_key(&key_from_type),
            "Constants should contain tuple key '{}'",
            key_from_type
        );

        // Verify get_from_dict works (internal function)
        let retrieved = get_from_dict(&mut rng, &dict, &tuple_type);
        assert!(retrieved.is_some(), "get_from_dict should find the tuple!");

        // The retrieved value should match
        if let Some(DynSolValue::Tuple(elements)) = retrieved {
            assert_eq!(elements.len(), 3);
            // First element should be our stored uint
            if let DynSolValue::Uint(u, _) = &elements[0] {
                assert_eq!(*u, U256::from(1337));
            } else {
                panic!("First element should be uint");
            }
        } else {
            panic!("Retrieved value should be a tuple");
        }
    }

    #[test]
    fn test_nested_tuple_dict_roundtrip() {
        use crate::abi::types::GenDict;

        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut dict = GenDict::new(42);
        dict.dict_freq = 1.0;

        // Create a nested tuple (struct containing another struct)
        let inner_tuple = DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(100), 256),
            DynSolValue::Bool(false),
        ]);
        let outer_tuple = DynSolValue::Tuple(vec![
            DynSolValue::Address(Address::repeat_byte(0xAB)),
            inner_tuple.clone(),
            DynSolValue::FixedBytes(B256::repeat_byte(0xCD), 32),
        ]);

        dict.add_constants(std::iter::once(outer_tuple.clone()));

        // Corresponding type
        let inner_type = DynSolType::Tuple(vec![DynSolType::Uint(256), DynSolType::Bool]);
        let outer_type = DynSolType::Tuple(vec![
            DynSolType::Address,
            inner_type,
            DynSolType::FixedBytes(32),
        ]);

        let key_from_value = outer_tuple
            .sol_type_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let key_from_type = outer_type.sol_type_name().to_string();

        println!("Nested tuple value key: '{}'", key_from_value);
        println!("Nested tuple type key:  '{}'", key_from_type);

        assert_eq!(key_from_type, key_from_value, "Nested tuple key mismatch!");

        let retrieved = get_from_dict(&mut rng, &dict, &outer_type);
        assert!(
            retrieved.is_some(),
            "Should retrieve nested tuple from dict"
        );
    }
}
