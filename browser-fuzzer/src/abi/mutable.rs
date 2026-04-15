//! Mutable trait for structure-aware fuzzing mutations
//!
//! Inspired by fuzztools' Mutable derive macro pattern.
//! Provides composable mutations for ABI values while preserving
//! the existing dictionary-based seeding approach.
//!
//! Key design decisions:
//! - Senders are NOT mutated (they come from config)
//! - Delays, values, and call arguments ARE mutated
//! - Full support for complex Solidity types (structs, arrays, nested types)
//! - AFL++ interesting values for better edge case coverage
//! - 10% mutation rate for integers preserved

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{Address, Bytes, FixedBytes, I128, I256, I64, U128, U256, U512, U64};
use rand::prelude::*;

// ============================================================================
// AFL++ Interesting Values (from fuzztools)
// ============================================================================

/// Interesting u8 values for mutation (AFL++ style)
pub const INTERESTING_U8: &[u8] = &[
    0, 1, 2, 4, 8, 16, 32, 64, 100, 127, 128, 255,
    // Powers of 2 minus 1
    3, 7, 15, 31, 63,
];

/// Interesting u16 values for mutation (AFL++ style)
pub const INTERESTING_U16: &[u16] = &[
    0, 1, 2, 4, 8, 16, 32, 64, 100, 127, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535,
    // Common boundaries
    1023, 2047, 4095, 8191, 16383,
];

/// Interesting u32 values for mutation (AFL++ style)
pub const INTERESTING_U32: &[u32] = &[
    0,
    1,
    2,
    4,
    8,
    16,
    32,
    64,
    100,
    127,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    32768,
    65535,
    65536,
    100000,
    1000000,
    // Max values
    u32::MAX,
    u32::MAX - 1,
    // Common boundaries
    0x7FFFFFFF,
    0x80000000,
    // Time values (seconds)
    60,
    3600,
    86400,
    604800,
    2592000,
    31536000,
];

/// Interesting u64 values for mutation (AFL++ style + Ethereum specific)
pub const INTERESTING_U64: &[u64] = &[
    0,
    1,
    2,
    4,
    8,
    16,
    32,
    64,
    100,
    127,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    32768,
    65535,
    65536,
    // Max values
    u64::MAX,
    u64::MAX - 1,
    // Common boundaries
    0x7FFFFFFFFFFFFFFF,
    0x8000000000000000,
    // Time values (seconds)
    60,
    3600,
    86400,
    604800,
    2592000,
    31536000,
    // Ethereum specific
    1_000_000_000,         // 1 gwei
    1_000_000_000_000_000, // 0.001 ether
    // Block numbers
    1,
    10,
    100,
    1000,
    10000,
    100000,
];

/// Interesting U256 values for mutation (AFL++ style + Ethereum specific)
pub fn interesting_u256() -> Vec<U256> {
    vec![
        U256::ZERO,
        U256::from(1u64),
        U256::from(2u64),
        U256::MAX,
        U256::MAX - U256::from(1u64),
        // Powers of 2
        U256::from(1u64) << 8,
        U256::from(1u64) << 16,
        U256::from(1u64) << 32,
        U256::from(1u64) << 64,
        U256::from(1u64) << 128,
        U256::from(1u64) << 255,
        // Powers of 2 minus 1
        (U256::from(1u64) << 8) - U256::from(1u64),
        (U256::from(1u64) << 16) - U256::from(1u64),
        (U256::from(1u64) << 32) - U256::from(1u64),
        (U256::from(1u64) << 64) - U256::from(1u64),
        (U256::from(1u64) << 128) - U256::from(1u64),
        (U256::from(1u64) << 256) - U256::from(1u64), // U256::MAX
        // Ethereum specific
        U256::from(1_000_000_000u64),                   // 1 gwei
        U256::from(1_000_000_000_000_000_000u128),      // 1 ether
        U256::from(1_000_000_000_000_000_000_000u128),  // 1000 ether
        // Percentages (basis points)
        U256::from(100u64),   // 1%
        U256::from(1000u64),  // 10%
        U256::from(5000u64),  // 50%
        U256::from(10000u64), // 100%
        // Time values
        U256::from(60u64),       // 1 minute
        U256::from(3600u64),     // 1 hour
        U256::from(86400u64),    // 1 day
        U256::from(604800u64),   // 1 week
        U256::from(2592000u64),  // 30 days
        U256::from(31536000u64), // 1 year
        // Signed boundary (for when cast to I256)
        U256::from(1u64) << 255, // I256::MIN as U256
    ]
}

/// Interesting I256 values for mutation
pub fn interesting_i256() -> Vec<I256> {
    vec![
        I256::ZERO,
        I256::ONE,
        I256::MINUS_ONE,
        I256::MAX,
        I256::MIN,
        I256::MIN + I256::ONE,
        I256::MAX - I256::ONE,
        // Small values
        I256::unchecked_from(127i64),
        I256::unchecked_from(-128i64),
        I256::unchecked_from(32767i64),
        I256::unchecked_from(-32768i64),
        // i64 boundaries
        I256::unchecked_from(i64::MAX),
        I256::unchecked_from(i64::MIN),
        // i128 boundaries
        I256::unchecked_from(i128::MAX),
        I256::unchecked_from(i128::MIN),
    ]
}

// ============================================================================
// Mutable Trait Definition
// ============================================================================

/// Trait for in-place mutation of values during fuzzing.
///
/// The `mutate` method modifies `self` in-place and returns a boolean.
/// The return value is used for Option<T> handling:
/// - `false`: Normal operation, keep value as-is
/// - `true`: Signal to parent to set Option to None (25% of the time for Option fields)
///
/// This design allows compositional mutations where complex types
/// delegate to their fields, which delegate to primitives.
pub trait Mutable {
    /// Mutate self in-place using the provided RNG.
    ///
    /// Returns `true` to signal Option<T> removal, `false` otherwise.
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool;
}

// ============================================================================
// Mutation Strategy Enums (fuzztools pattern)
// ============================================================================

/// Mutation strategies for unsigned integers
#[derive(Clone, Copy, Debug)]
enum UintMutation {
    // Bit-level
    FlipBit,
    SwapAdjacentBits,
    ReverseBits,
    RotateLeft,
    RotateRight,
    ShiftLeft,
    ShiftRight,

    // Arithmetic (saturating)
    AddSmall,
    SubSmall,
    AddRandom,
    SubRandom,
    MulSmall,
    DivSmall,

    // Boundary
    SetZero,
    SetOne,
    SetMax,
    SetInteresting,

    // Bitwise
    Xor,
    And,
    Or,
    Not,

    // Delta (Echidna-style)
    DeltaMutation,

    // Scale down by percentage (for burn amount adjustment)
    ScaleDown,
}

impl UintMutation {
    fn random<R: Rng>(rng: &mut R) -> Self {
        match rng.gen_range(0..23) {
            0 => UintMutation::FlipBit,
            1 => UintMutation::SwapAdjacentBits,
            2 => UintMutation::ReverseBits,
            3 => UintMutation::RotateLeft,
            4 => UintMutation::RotateRight,
            5 => UintMutation::ShiftLeft,
            6 => UintMutation::ShiftRight,
            7 => UintMutation::AddSmall,
            8 => UintMutation::SubSmall,
            9 => UintMutation::AddRandom,
            10 => UintMutation::SubRandom,
            11 => UintMutation::MulSmall,
            12 => UintMutation::DivSmall,
            13 => UintMutation::SetZero,
            14 => UintMutation::SetOne,
            15 => UintMutation::SetMax,
            16 => UintMutation::SetInteresting,
            17 => UintMutation::Xor,
            18 => UintMutation::And,
            19 => UintMutation::Or,
            20 => UintMutation::Not,
            21 => UintMutation::DeltaMutation,
            _ => UintMutation::ScaleDown,
        }
    }
}

/// Mutation strategies for byte vectors
#[derive(Clone, Copy, Debug)]
enum BytesMutation {
    // Element ops
    PushRandom,
    PopRandom,
    SwapElements,
    MutateElement,

    // Bulk ops
    Shuffle,
    Reverse,
    RotateLeft,
    RotateRight,

    // Pattern injection
    SetAllZero,
    SetAllMax,
    SetPattern,

    // Slice ops
    DuplicateSlice,
    DeleteSlice,

    // Array mutation (Echidna-style)
    ArrayMutation,
}

impl BytesMutation {
    fn random<R: Rng>(rng: &mut R) -> Self {
        match rng.gen_range(0..14) {
            0 => BytesMutation::PushRandom,
            1 => BytesMutation::PopRandom,
            2 => BytesMutation::SwapElements,
            3 => BytesMutation::MutateElement,
            4 => BytesMutation::Shuffle,
            5 => BytesMutation::Reverse,
            6 => BytesMutation::RotateLeft,
            7 => BytesMutation::RotateRight,
            8 => BytesMutation::SetAllZero,
            9 => BytesMutation::SetAllMax,
            10 => BytesMutation::SetPattern,
            11 => BytesMutation::DuplicateSlice,
            12 => BytesMutation::DeleteSlice,
            _ => BytesMutation::ArrayMutation,
        }
    }
}

/// Mutation strategies for vectors/arrays of values
#[derive(Clone, Copy, Debug)]
enum VecMutation {
    Push,
    Remove,
    Replace,
    Swap,
    Shuffle,
    Reverse,
    Duplicate,
    MutateElement,
    MutateMultiple,
}

impl VecMutation {
    fn random<R: Rng>(rng: &mut R) -> Self {
        match rng.gen_range(0..9) {
            0 => VecMutation::Push,
            1 => VecMutation::Remove,
            2 => VecMutation::Replace,
            3 => VecMutation::Swap,
            4 => VecMutation::Shuffle,
            5 => VecMutation::Reverse,
            6 => VecMutation::Duplicate,
            7 => VecMutation::MutateElement,
            _ => VecMutation::MutateMultiple,
        }
    }
}

// ============================================================================
// Primitive Type Implementations
// ============================================================================

impl Mutable for bool {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 25% chance to signal None for Option<bool>
        if rng.gen_ratio(1, 4) {
            return true;
        }
        // Flip the boolean
        *self = !*self;
        false
    }
}

impl Mutable for u8 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        match UintMutation::random(rng) {
            UintMutation::FlipBit => {
                let bit = rng.gen_range(0..8);
                *self ^= 1 << bit;
            }
            UintMutation::SwapAdjacentBits => {
                let even = *self & 0x55;
                let odd = *self & 0xAA;
                *self = (even << 1) | (odd >> 1);
            }
            UintMutation::ReverseBits => {
                *self = self.reverse_bits();
            }
            UintMutation::RotateLeft => {
                let amount = rng.gen_range(1..8);
                *self = self.rotate_left(amount);
            }
            UintMutation::RotateRight => {
                let amount = rng.gen_range(1..8);
                *self = self.rotate_right(amount);
            }
            UintMutation::ShiftLeft => {
                let amount = rng.gen_range(1..8);
                *self = self.wrapping_shl(amount);
            }
            UintMutation::ShiftRight => {
                let amount = rng.gen_range(1..8);
                *self = self.wrapping_shr(amount);
            }
            UintMutation::AddSmall => {
                let delta: u8 = rng.gen_range(1..=16);
                *self = self.saturating_add(delta);
            }
            UintMutation::SubSmall => {
                let delta: u8 = rng.gen_range(1..=16);
                *self = self.saturating_sub(delta);
            }
            UintMutation::AddRandom => {
                let delta: u8 = rng.gen();
                *self = self.saturating_add(delta);
            }
            UintMutation::SubRandom => {
                let delta: u8 = rng.gen();
                *self = self.saturating_sub(delta);
            }
            UintMutation::MulSmall => {
                let factor: u8 = rng.gen_range(2..=4);
                *self = self.saturating_mul(factor);
            }
            UintMutation::DivSmall => {
                let divisor: u8 = rng.gen_range(2..=4);
                *self = self.saturating_div(divisor);
            }
            UintMutation::SetZero => {
                *self = 0;
            }
            UintMutation::SetOne => {
                *self = 1;
            }
            UintMutation::SetMax => {
                *self = u8::MAX;
            }
            UintMutation::SetInteresting => {
                *self = INTERESTING_U8[rng.gen_range(0..INTERESTING_U8.len())];
            }
            UintMutation::Xor => {
                let mask: u8 = rng.gen();
                *self ^= mask;
            }
            UintMutation::And => {
                let mask: u8 = rng.gen();
                *self &= mask;
            }
            UintMutation::Or => {
                let mask: u8 = rng.gen();
                *self |= mask;
            }
            UintMutation::Not => {
                *self = !*self;
            }
            UintMutation::DeltaMutation => {
                if *self == 0 {
                    *self = rng.gen_range(0..=16);
                } else {
                    let max_delta = (*self).max(1);
                    let delta: u8 = rng.gen_range(0..=max_delta);
                    if rng.gen() {
                        *self = self.saturating_add(delta);
                    } else {
                        *self = self.saturating_sub(delta);
                    }
                }
            }
            UintMutation::ScaleDown => {
                // Scale down by percentage
                if *self > 0 {
                    let scale_pcts = [90u8, 95, 99];
                    let scale = scale_pcts[rng.gen_range(0..scale_pcts.len())];
                    *self = (*self as u16 * scale as u16 / 100) as u8;
                }
            }
        }
        false
    }
}

// Macro to implement Mutable for larger unsigned integers
macro_rules! impl_mutable_uint {
    ($type:ty, $interesting:expr) => {
        impl Mutable for $type {
            fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
                match UintMutation::random(rng) {
                    UintMutation::FlipBit => {
                        let bits = std::mem::size_of::<$type>() * 8;
                        let bit = rng.gen_range(0..bits);
                        *self ^= 1 << bit;
                    }
                    UintMutation::SwapAdjacentBits => {
                        let even = *self & ((<$type>::MAX / 3) as $type);
                        let odd = *self & (((<$type>::MAX / 3) * 2) as $type);
                        *self = (even << 1) | (odd >> 1);
                    }
                    UintMutation::ReverseBits => {
                        *self = self.reverse_bits();
                    }
                    UintMutation::RotateLeft => {
                        let bits = std::mem::size_of::<$type>() * 8;
                        let amount = rng.gen_range(1..bits as u32);
                        *self = self.rotate_left(amount);
                    }
                    UintMutation::RotateRight => {
                        let bits = std::mem::size_of::<$type>() * 8;
                        let amount = rng.gen_range(1..bits as u32);
                        *self = self.rotate_right(amount);
                    }
                    UintMutation::ShiftLeft => {
                        let bits = std::mem::size_of::<$type>() * 8;
                        let amount = rng.gen_range(1..bits as u32);
                        *self = self.wrapping_shl(amount);
                    }
                    UintMutation::ShiftRight => {
                        let bits = std::mem::size_of::<$type>() * 8;
                        let amount = rng.gen_range(1..bits as u32);
                        *self = self.wrapping_shr(amount);
                    }
                    UintMutation::AddSmall => {
                        let delta = rng.gen_range(1..=16) as $type;
                        *self = self.saturating_add(delta);
                    }
                    UintMutation::SubSmall => {
                        let delta = rng.gen_range(1..=16) as $type;
                        *self = self.saturating_sub(delta);
                    }
                    UintMutation::AddRandom => {
                        let delta: $type = rng.gen();
                        *self = self.saturating_add(delta);
                    }
                    UintMutation::SubRandom => {
                        let delta: $type = rng.gen();
                        *self = self.saturating_sub(delta);
                    }
                    UintMutation::MulSmall => {
                        let factor = rng.gen_range(2..=4) as $type;
                        *self = self.saturating_mul(factor);
                    }
                    UintMutation::DivSmall => {
                        let divisor = rng.gen_range(2..=4) as $type;
                        if divisor != 0 {
                            *self /= divisor;
                        }
                    }
                    UintMutation::SetZero => {
                        *self = 0;
                    }
                    UintMutation::SetOne => {
                        *self = 1;
                    }
                    UintMutation::SetMax => {
                        *self = <$type>::MAX;
                    }
                    UintMutation::SetInteresting => {
                        let interesting = $interesting;
                        *self = interesting[rng.gen_range(0..interesting.len())] as $type;
                    }
                    UintMutation::Xor => {
                        let mask: $type = rng.gen();
                        *self ^= mask;
                    }
                    UintMutation::And => {
                        let mask: $type = rng.gen();
                        *self &= mask;
                    }
                    UintMutation::Or => {
                        let mask: $type = rng.gen();
                        *self |= mask;
                    }
                    UintMutation::Not => {
                        *self = !*self;
                    }
                    UintMutation::DeltaMutation => {
                        if *self == 0 {
                            *self = rng.gen_range(0..=16) as $type;
                        } else {
                            let max_delta = (*self).min(<$type>::MAX / 2);
                            if max_delta > 0 {
                                let delta: $type = rng.gen_range(0..=max_delta);
                                if rng.gen() {
                                    *self = self.saturating_add(delta);
                                } else {
                                    *self = self.saturating_sub(delta);
                                }
                            }
                        }
                    }
                    UintMutation::ScaleDown => {
                        // Scale down by percentage
                        if *self > 0 {
                            let scale_pcts = [90u64, 95, 99, 999];
                            let scale = scale_pcts[rng.gen_range(0..scale_pcts.len())];
                            let divisor = if scale == 999 { 1000u64 } else { 100u64 };
                            *self = ((*self as u128 * scale as u128) / divisor as u128) as $type;
                        }
                    }
                }
                false
            }
        }
    };
}

impl_mutable_uint!(u16, INTERESTING_U16);
impl_mutable_uint!(u32, INTERESTING_U32);
impl_mutable_uint!(u64, INTERESTING_U64);
impl_mutable_uint!(u128, INTERESTING_U64); // Use u64 interesting values for u128

// ============================================================================
// Alloy Primitive Type Implementations
// ============================================================================

impl Mutable for U256 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% chance of mutation
        if rng.gen_ratio(9, 10) {
            return false;
        }

        match UintMutation::random(rng) {
            UintMutation::FlipBit => {
                let bit = rng.gen_range(0..256);
                *self ^= U256::from(1u64) << bit;
            }
            UintMutation::SwapAdjacentBits => {
                // Swap adjacent bits using masks
                let mut bytes = self.to_be_bytes::<32>();
                for byte in bytes.iter_mut() {
                    let even = *byte & 0x55;
                    let odd = *byte & 0xAA;
                    *byte = (even << 1) | (odd >> 1);
                }
                *self = U256::from_be_bytes(bytes);
            }
            UintMutation::ReverseBits => {
                let mut bytes = self.to_be_bytes::<32>();
                bytes.reverse();
                for byte in bytes.iter_mut() {
                    *byte = byte.reverse_bits();
                }
                *self = U256::from_be_bytes(bytes);
            }
            UintMutation::RotateLeft | UintMutation::ShiftLeft => {
                let amount = rng.gen_range(1..256);
                *self = *self << amount;
            }
            UintMutation::RotateRight | UintMutation::ShiftRight => {
                let amount = rng.gen_range(1..256);
                *self = *self >> amount;
            }
            UintMutation::AddSmall => {
                let delta = U256::from(rng.gen_range(1u64..=16));
                *self = self.saturating_add(delta);
            }
            UintMutation::SubSmall => {
                let delta = U256::from(rng.gen_range(1u64..=16));
                *self = self.saturating_sub(delta);
            }
            UintMutation::AddRandom => {
                let random_bytes: [u8; 32] = rng.gen();
                let delta = U256::from_be_bytes(random_bytes);
                *self = self.saturating_add(delta);
            }
            UintMutation::SubRandom => {
                let random_bytes: [u8; 32] = rng.gen();
                let delta = U256::from_be_bytes(random_bytes);
                *self = self.saturating_sub(delta);
            }
            UintMutation::MulSmall => {
                let factor = U256::from(rng.gen_range(2u64..=4));
                *self = self.saturating_mul(factor);
            }
            UintMutation::DivSmall => {
                let divisor = U256::from(rng.gen_range(2u64..=4));
                if !divisor.is_zero() {
                    *self = *self / divisor;
                }
            }
            UintMutation::SetZero => {
                *self = U256::ZERO;
            }
            UintMutation::SetOne => {
                *self = U256::from(1u64);
            }
            UintMutation::SetMax => {
                *self = U256::MAX;
            }
            UintMutation::SetInteresting => {
                let interesting = interesting_u256();
                *self = interesting[rng.gen_range(0..interesting.len())];
            }
            UintMutation::Xor => {
                let random_bytes: [u8; 32] = rng.gen();
                let mask = U256::from_be_bytes(random_bytes);
                *self ^= mask;
            }
            UintMutation::And => {
                let random_bytes: [u8; 32] = rng.gen();
                let mask = U256::from_be_bytes(random_bytes);
                *self &= mask;
            }
            UintMutation::Or => {
                let random_bytes: [u8; 32] = rng.gen();
                let mask = U256::from_be_bytes(random_bytes);
                *self |= mask;
            }
            UintMutation::Not => {
                *self = !*self;
            }
            UintMutation::DeltaMutation => {
                if self.is_zero() {
                    *self = U256::from(rng.gen_range(0u64..=16));
                } else {
                    let max_delta = (*self).min(U256::MAX / U256::from(2u64));
                    if !max_delta.is_zero() {
                        let random_bytes: [u8; 32] = rng.gen();
                        let delta = U256::from_be_bytes(random_bytes) % (max_delta + U256::from(1u64));
                        if rng.gen() {
                            *self = self.saturating_add(delta);
                        } else {
                            *self = self.saturating_sub(delta);
                        }
                    }
                }
            }
            UintMutation::ScaleDown => {
                // Scale down by common percentages (90%, 95%, 99%, 99.9%)
                // Useful for adjusting burn amounts after swap_in reduces pair balance
                if !self.is_zero() {
                    let scale_pcts = [90u64, 95, 99, 999]; // 999 = 99.9%
                    let scale = scale_pcts[rng.gen_range(0..scale_pcts.len())];
                    let divisor = if scale == 999 { 1000u64 } else { 100u64 };
                    *self = (*self * U256::from(scale)) / U256::from(divisor);
                }
            }
        }
        false
    }
}

impl Mutable for I256 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% chance of mutation
        if rng.gen_ratio(9, 10) {
            return false;
        }

        // For signed integers, we use a subset of strategies
        match rng.gen_range(0..8) {
            0 => {
                // Add small
                let delta = I256::unchecked_from(rng.gen_range(1i64..=16));
                *self = self.saturating_add(delta);
            }
            1 => {
                // Sub small
                let delta = I256::unchecked_from(rng.gen_range(1i64..=16));
                *self = self.saturating_sub(delta);
            }
            2 => {
                // Negate
                *self = self.saturating_neg();
            }
            3 => {
                // Set zero
                *self = I256::ZERO;
            }
            4 => {
                // Set one
                *self = I256::ONE;
            }
            5 => {
                // Set negative one
                *self = I256::MINUS_ONE;
            }
            6 => {
                // Set interesting
                let interesting = interesting_i256();
                *self = interesting[rng.gen_range(0..interesting.len())];
            }
            _ => {
                let abs_x = self.unsigned_abs();
                if abs_x.is_zero() {
                    *self = I256::unchecked_from(rng.gen_range(-16i64..=16));
                } else {
                    let max_delta = abs_x.min(U256::MAX / U256::from(2u64));
                    if !max_delta.is_zero() {
                        let random_bytes: [u8; 32] = rng.gen();
                        let delta_u = U256::from_be_bytes(random_bytes) % (max_delta + U256::from(1u64));
                        // PERF: Use from_raw - delta_u <= max_delta <= U256::MAX/2 = I256::MAX
                        let delta = I256::from_raw(delta_u);
                        if rng.gen() {
                            *self = self.saturating_add(delta);
                        } else {
                            *self = self.saturating_sub(delta);
                        }
                    }
                }
            }
        }
        false
    }
}

/// Interesting addresses for mutation (Ethereum precompiles, system addresses, etc.)
pub fn interesting_addresses() -> Vec<Address> {
    vec![
        // Zero address
        Address::ZERO,
        // Dead address (burn address)
        "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap(),
        // Precompiles (1-9)
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])), // ecrecover
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ])), // sha256
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3,
        ])), // ripemd160
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4,
        ])), // identity
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 5,
        ])), // modexp
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 6,
        ])), // ecadd
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 7,
        ])), // ecmul
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 8,
        ])), // ecpairing
        Address::from_word(alloy_primitives::B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 9,
        ])), // blake2f
        // EIP-4788 beacon block root (Dencun)
        "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02"
            .parse()
            .unwrap(),
        // System address
        "0xfffffffffffffffffffffffffffffffffffffffe"
            .parse()
            .unwrap(),
        // Common test addresses from pregen_addresses
        Address::from_word(U256::from(0xffffffff_u64).into()),
        Address::from_word(U256::from(0x1fffffffe_u64).into()),
        Address::from_word(U256::from(0x2fffffffd_u64).into()),
    ]
}

/// Mutation strategies for addresses
#[derive(Clone, Copy, Debug)]
enum AddressMutation {
    /// Pick from interesting addresses (precompiles, etc.)
    SetInteresting,
    /// Pick from pregen addresses
    SetPregen,
    /// Set to zero address
    SetZero,
    /// Mutate a single byte
    MutateByte,
    /// Flip a bit
    FlipBit,
    /// Generate random address
    Random,
}

impl AddressMutation {
    fn random<R: Rng>(rng: &mut R) -> Self {
        // Weighted selection: 40% interesting, 20% pregen, 10% zero, 20% byte mutate, 5% bit flip, 5% random
        match rng.gen_range(0..20) {
            0..=7 => AddressMutation::SetInteresting,  // 40%
            8..=11 => AddressMutation::SetPregen,      // 20%
            12..=13 => AddressMutation::SetZero,       // 10%
            14..=17 => AddressMutation::MutateByte,    // 20%
            18 => AddressMutation::FlipBit,            // 5%
            _ => AddressMutation::Random,              // 5%
        }
    }
}

impl Mutable for Address {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% mutation rate 
        if rng.gen_ratio(9, 10) {
            return false;
        }

        match AddressMutation::random(rng) {
            AddressMutation::SetInteresting => {
                let addrs = interesting_addresses();
                *self = addrs[rng.gen_range(0..addrs.len())];
            }
            AddressMutation::SetPregen => {
                let addrs = super::gen::pregen_addresses();
                *self = addrs[rng.gen_range(0..addrs.len())];
            }
            AddressMutation::SetZero => {
                *self = Address::ZERO;
            }
            AddressMutation::MutateByte => {
                let mut bytes = self.0 .0;
                let idx = rng.gen_range(0..20);
                bytes[idx] = rng.gen();
                *self = Address::from(bytes);
            }
            AddressMutation::FlipBit => {
                let mut bytes = self.0 .0;
                let byte_idx = rng.gen_range(0..20);
                let bit_idx = rng.gen_range(0..8);
                bytes[byte_idx] ^= 1 << bit_idx;
                *self = Address::from(bytes);
            }
            AddressMutation::Random => {
                let bytes: [u8; 20] = rng.gen();
                *self = Address::from(bytes);
            }
        }
        false
    }
}

impl Mutable for Bytes {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        let mut vec = self.to_vec();
        let result = vec.mutate(rng);
        *self = Bytes::from(vec);
        result
    }
}

impl<const N: usize> Mutable for FixedBytes<N> {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // Mutate as byte array
        let mut bytes = self.0;
        bytes.mutate(rng);
        *self = FixedBytes::from(bytes);
        false
    }
}

// ============================================================================
// Additional Alloy Primitive Types
// ============================================================================

// Note: B64, B128, B256, B512 are type aliases for FixedBytes<N>
// They automatically get the Mutable implementation from FixedBytes<N>

// Bloom is FixedBytes<256>, also gets impl automatically

// Unsigned integer types (Uint<BITS, LIMBS>)

impl Mutable for U64 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% chance of mutation
        if rng.gen_ratio(9, 10) {
            return false;
        }

        let mut val: u64 = self.to::<u64>();
        val.mutate(rng);
        *self = U64::from(val);
        false
    }
}

impl Mutable for U128 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% chance of mutation
        if rng.gen_ratio(9, 10) {
            return false;
        }

        let mut val: u128 = self.to::<u128>();
        val.mutate(rng);
        *self = U128::from(val);
        false
    }
}

impl Mutable for U512 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% chance of mutation
        if rng.gen_ratio(9, 10) {
            return false;
        }

        // Convert to bytes, mutate, convert back
        let mut bytes = self.to_be_bytes::<64>();

        match UintMutation::random(rng) {
            UintMutation::FlipBit => {
                let bit = rng.gen_range(0..512);
                let byte_idx = bit / 8;
                let bit_in_byte = bit % 8;
                bytes[byte_idx] ^= 1 << bit_in_byte;
            }
            UintMutation::SetZero => {
                bytes.fill(0);
            }
            UintMutation::SetMax => {
                bytes.fill(0xFF);
            }
            UintMutation::AddSmall => {
                // Add small value to last 8 bytes
                let last_u64 = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
                let new_val = last_u64.saturating_add(rng.gen_range(1..=16));
                bytes[56..64].copy_from_slice(&new_val.to_be_bytes());
            }
            UintMutation::SubSmall => {
                let last_u64 = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
                let new_val = last_u64.saturating_sub(rng.gen_range(1..=16));
                bytes[56..64].copy_from_slice(&new_val.to_be_bytes());
            }
            _ => {
                // Random byte mutation
                let idx = rng.gen_range(0..64);
                bytes[idx].mutate(rng);
            }
        }

        *self = U512::from_be_bytes(bytes);
        false
    }
}

// Signed integer types

impl Mutable for I64 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% chance of mutation
        if rng.gen_ratio(9, 10) {
            return false;
        }

        match rng.gen_range(0..6) {
            0 => {
                // Add small
                let delta = I64::try_from(rng.gen_range(1i64..=16)).unwrap();
                *self = self.saturating_add(delta);
            }
            1 => {
                // Sub small
                let delta = I64::try_from(rng.gen_range(1i64..=16)).unwrap();
                *self = self.saturating_sub(delta);
            }
            2 => {
                // Negate
                *self = self.saturating_neg();
            }
            3 => {
                // Set zero
                *self = I64::ZERO;
            }
            4 => {
                // Set boundary
                *self = if rng.gen() { I64::MAX } else { I64::MIN };
            }
            _ => {
                // Random within range
                let random_bytes: [u8; 8] = rng.gen();
                *self = I64::from_be_bytes(random_bytes);
            }
        }
        false
    }
}

impl Mutable for I128 {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // 10% chance of mutation
        if rng.gen_ratio(9, 10) {
            return false;
        }

        match rng.gen_range(0..6) {
            0 => {
                // Add small
                let delta = I128::try_from(rng.gen_range(1i128..=16)).unwrap();
                *self = self.saturating_add(delta);
            }
            1 => {
                // Sub small
                let delta = I128::try_from(rng.gen_range(1i128..=16)).unwrap();
                *self = self.saturating_sub(delta);
            }
            2 => {
                // Negate
                *self = self.saturating_neg();
            }
            3 => {
                // Set zero
                *self = I128::ZERO;
            }
            4 => {
                // Set boundary
                *self = if rng.gen() { I128::MAX } else { I128::MIN };
            }
            _ => {
                // Random within range
                let random_bytes: [u8; 16] = rng.gen();
                *self = I128::from_be_bytes(random_bytes);
            }
        }
        false
    }
}

// ============================================================================
// Array and Slice Implementations
// ============================================================================

impl<const N: usize> Mutable for [u8; N] {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        if N == 0 {
            return false;
        }

        match BytesMutation::random(rng) {
            BytesMutation::PushRandom | BytesMutation::PopRandom => {
                // Can't change size of fixed array, mutate random element instead
                let idx = rng.gen_range(0..N);
                self[idx].mutate(rng);
            }
            BytesMutation::SwapElements => {
                if N >= 2 {
                    let i = rng.gen_range(0..N);
                    let j = rng.gen_range(0..N);
                    self.swap(i, j);
                }
            }
            BytesMutation::MutateElement => {
                let idx = rng.gen_range(0..N);
                self[idx].mutate(rng);
            }
            BytesMutation::Shuffle => {
                // Fisher-Yates shuffle
                for i in (1..N).rev() {
                    let j = rng.gen_range(0..=i);
                    self.swap(i, j);
                }
            }
            BytesMutation::Reverse => {
                self.reverse();
            }
            BytesMutation::RotateLeft => {
                let amount = rng.gen_range(1..N.max(2));
                self.rotate_left(amount);
            }
            BytesMutation::RotateRight => {
                let amount = rng.gen_range(1..N.max(2));
                self.rotate_right(amount);
            }
            BytesMutation::SetAllZero => {
                self.fill(0);
            }
            BytesMutation::SetAllMax => {
                self.fill(0xFF);
            }
            BytesMutation::SetPattern => {
                // Alternating pattern
                for (i, byte) in self.iter_mut().enumerate() {
                    *byte = if i % 2 == 0 { 0x00 } else { 0xFF };
                }
            }
            BytesMutation::DuplicateSlice | BytesMutation::DeleteSlice => {
                // Can't change size, mutate multiple elements instead
                let count = rng.gen_range(1..=N.min(4));
                for _ in 0..count {
                    let idx = rng.gen_range(0..N);
                    self[idx].mutate(rng);
                }
            }
            BytesMutation::ArrayMutation => {
                match rng.gen_range(0..3) {
                    0 => {
                        // Expand (duplicate element)
                        if N >= 2 {
                            let src = rng.gen_range(0..N);
                            let dst = rng.gen_range(0..N);
                            self[dst] = self[src];
                        }
                    }
                    1 => {
                        // Delete (zero out element)
                        let idx = rng.gen_range(0..N);
                        self[idx] = 0;
                    }
                    _ => {
                        // Swap
                        if N >= 2 {
                            let i = rng.gen_range(0..N);
                            let j = rng.gen_range(0..N);
                            self.swap(i, j);
                        }
                    }
                }
            }
        }
        false
    }
}

impl Mutable for Vec<u8> {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        if self.is_empty() {
            if rng.gen_ratio(1, 11) {
                // No-op: stay empty (allows testing data.length == 0 paths)
                return false;
            }
            // Expand: push a random byte
            self.push(rng.gen());
            return false;
        }

        match BytesMutation::random(rng) {
            BytesMutation::PushRandom => {
                if self.len() < 1024 {
                    // Cap at 1KB
                    self.push(rng.gen());
                }
            }
            BytesMutation::PopRandom => {
                // deleteRandList deletes exactly 1 element
                // This CAN produce empty bytes (when len == 1)
                let idx = rng.gen_range(0..self.len());
                self.remove(idx);
            }
            BytesMutation::SwapElements => {
                if self.len() >= 2 {
                    let i = rng.gen_range(0..self.len());
                    let j = rng.gen_range(0..self.len());
                    self.swap(i, j);
                }
            }
            BytesMutation::MutateElement => {
                let idx = rng.gen_range(0..self.len());
                self[idx].mutate(rng);
            }
            BytesMutation::Shuffle => {
                // Fisher-Yates shuffle
                for i in (1..self.len()).rev() {
                    let j = rng.gen_range(0..=i);
                    self.swap(i, j);
                }
            }
            BytesMutation::Reverse => {
                self.reverse();
            }
            BytesMutation::RotateLeft => {
                if self.len() >= 2 {
                    let amount = rng.gen_range(1..self.len());
                    self.rotate_left(amount);
                }
            }
            BytesMutation::RotateRight => {
                if self.len() >= 2 {
                    let amount = rng.gen_range(1..self.len());
                    self.rotate_right(amount);
                }
            }
            BytesMutation::SetAllZero => {
                self.fill(0);
            }
            BytesMutation::SetAllMax => {
                self.fill(0xFF);
            }
            BytesMutation::SetPattern => {
                for (i, byte) in self.iter_mut().enumerate() {
                    *byte = if i % 2 == 0 { 0x00 } else { 0xFF };
                }
            }
            BytesMutation::DuplicateSlice => {
                if self.len() < 512 {
                    // Cap growth
                    let start = rng.gen_range(0..self.len());
                    let len = rng.gen_range(1..=(self.len() - start).min(32));
                    let slice: Vec<u8> = self[start..start + len].to_vec();
                    let insert_at = rng.gen_range(0..=self.len());
                    for (i, byte) in slice.into_iter().enumerate() {
                        self.insert(insert_at + i, byte);
                    }
                }
            }
            BytesMutation::DeleteSlice => {
                // Allow reducing to empty
                // Remove the len > 1 guard to allow shrinking to 0
                if !self.is_empty() {
                    let start = rng.gen_range(0..self.len());
                    let max_delete = (self.len() - start).min(16);
                    let len = rng.gen_range(1..=max_delete);
                    self.drain(start..start + len);
                }
            }
            BytesMutation::ArrayMutation => {
                *self = super::mutator_array::mutate_ll(rng, None, vec![], self);
            }
        }
        false
    }
}

// ============================================================================
// DynSolValue Implementation (Complex Solidity Types)
// ============================================================================

impl Mutable for DynSolValue {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        match self {
            DynSolValue::Bool(b) => b.mutate(rng),

            DynSolValue::Uint(n, bits) => {
                // 10% chance of mutation
                if rng.gen_ratio(9, 10) {
                    return false;
                }

                let is_full_256 = *bits >= 256;
                let max_val = if is_full_256 {
                    U256::MAX
                } else {
                    (U256::from(1u64) << *bits) - U256::from(1u64)
                };

                // Helper to clamp value to valid range
                let clamp = |val: U256| -> U256 {
                    if is_full_256 {
                        val
                    } else if val > max_val {
                        val & max_val  // Mask to valid bits
                    } else {
                        val
                    }
                };

                // Bit-size-aware mutation strategies
                match rng.gen_range(0..10) {
                    0 => {
                        // Flip a bit within the valid range
                        let bit = rng.gen_range(0..*bits);
                        *n ^= U256::from(1u64) << bit;
                        *n = clamp(*n);
                    }
                    1 => {
                        // Set to zero
                        *n = U256::ZERO;
                    }
                    2 => {
                        // Set to max for this bit size
                        *n = max_val;
                    }
                    3 => {
                        // Set to one
                        *n = U256::from(1u64);
                    }
                    4 => {
                        // Set to interesting value (clamped to bit size)
                        let interesting = interesting_u256();
                        let val = interesting[rng.gen_range(0..interesting.len())];
                        *n = clamp(val);
                    }
                    5 => {
                        // Add small delta
                        let delta = U256::from(rng.gen_range(1u64..=16));
                        *n = n.saturating_add(delta);
                        *n = clamp(*n);
                    }
                    6 => {
                        // Sub small delta
                        let delta = U256::from(rng.gen_range(1u64..=16));
                        *n = n.saturating_sub(delta);
                    }
                    7 => {
                        // Power of 2 within range
                        let power = rng.gen_range(0..(*bits).min(256));
                        *n = U256::from(1u64) << power;
                    }
                    8 => {
                        // Power of 2 minus 1 (all 1s up to that bit)
                        let power = rng.gen_range(1..=(*bits).min(255));
                        *n = (U256::from(1u64) << power) - U256::from(1u64);
                    }
                    _ => {
                        // Random value within valid range
                        let random_bytes: [u8; 32] = rng.gen();
                        let val = U256::from_be_bytes(random_bytes);
                        *n = clamp(val);
                    }
                }
                false
            }

            DynSolValue::Int(n, bits) => {
                // 10% chance of mutation
                if rng.gen_ratio(9, 10) {
                    return false;
                }

                let (min_val, max_val) = if *bits >= 256 {
                    (I256::MIN, I256::MAX)
                } else {
                    let max = (I256::ONE << (*bits - 1)) - I256::ONE;
                    let min = -max - I256::ONE;
                    (min, max)
                };

                // Bit-size-aware mutation strategies
                match rng.gen_range(0..8) {
                    0 => {
                        // Set to zero
                        *n = I256::ZERO;
                    }
                    1 => {
                        // Set to max for this bit size
                        *n = max_val;
                    }
                    2 => {
                        // Set to min for this bit size
                        *n = min_val;
                    }
                    3 => {
                        // Set to one or negative one
                        *n = if rng.gen() { I256::ONE } else { I256::MINUS_ONE };
                    }
                    4 => {
                        // Set to interesting value (clamped to bit size)
                        let interesting = interesting_i256();
                        let val = interesting[rng.gen_range(0..interesting.len())];
                        *n = val.max(min_val).min(max_val);
                    }
                    5 => {
                        // Add small delta
                        let delta = I256::unchecked_from(rng.gen_range(1i64..=16));
                        *n = n.saturating_add(delta);
                        if *n > max_val {
                            *n = max_val;
                        }
                    }
                    6 => {
                        // Sub small delta
                        let delta = I256::unchecked_from(rng.gen_range(1i64..=16));
                        *n = n.saturating_sub(delta);
                        if *n < min_val {
                            *n = min_val;
                        }
                    }
                    _ => {
                        // Negate
                        *n = n.saturating_neg();
                        *n = (*n).max(min_val).min(max_val);
                    }
                }

                // Final clamp
                *n = (*n).max(min_val).min(max_val);
                false
            }

            DynSolValue::Address(addr) => {
                // Mutate addresses using interesting addresses and dictionary
                addr.mutate(rng)
            }

            DynSolValue::Bytes(b) => {
                let mut vec = b.clone();
                let result = vec.mutate(rng);
                *b = vec;
                result
            }

            DynSolValue::String(s) => {
                // Mutate as bytes, then convert back
                let mut bytes = s.as_bytes().to_vec();
                let result = bytes.mutate(rng);
                *s = String::from_utf8_lossy(&bytes).to_string();
                result
            }

            DynSolValue::FixedBytes(b, size) => {
                // Size-aware mutation for fixed bytes
                let mut bytes = b.0;

                match rng.gen_range(0..10) {
                    0 => {
                        // Set all relevant bytes to zero
                        for i in 0..*size {
                            bytes[i] = 0;
                        }
                    }
                    1 => {
                        // Set all relevant bytes to 0xFF
                        for i in 0..*size {
                            bytes[i] = 0xFF;
                        }
                    }
                    2 => {
                        // Flip a single bit within the relevant bytes
                        let byte_idx = rng.gen_range(0..*size);
                        let bit_idx = rng.gen_range(0..8);
                        bytes[byte_idx] ^= 1 << bit_idx;
                    }
                    3 => {
                        // Mutate a single byte
                        let idx = rng.gen_range(0..*size);
                        bytes[idx] = rng.gen();
                    }
                    4 => {
                        // Swap two bytes (if size >= 2)
                        if *size >= 2 {
                            let i = rng.gen_range(0..*size);
                            let j = rng.gen_range(0..*size);
                            bytes.swap(i, j);
                        }
                    }
                    5 => {
                        // Reverse the bytes
                        bytes[0..*size].reverse();
                    }
                    6 => {
                        // Set to incrementing pattern (0x00, 0x01, 0x02, ...)
                        for i in 0..*size {
                            bytes[i] = i as u8;
                        }
                    }
                    7 => {
                        // Set to alternating pattern
                        for i in 0..*size {
                            bytes[i] = if i % 2 == 0 { 0x00 } else { 0xFF };
                        }
                    }
                    8 => {
                        // Mutate multiple bytes (for larger sizes)
                        let count = rng.gen_range(1..=(*size).min(4));
                        for _ in 0..count {
                            let idx = rng.gen_range(0..*size);
                            bytes[idx].mutate(rng);
                        }
                    }
                    _ => {
                        // Randomize all relevant bytes
                        for i in 0..*size {
                            bytes[i] = rng.gen();
                        }
                    }
                }

                *b = FixedBytes::from(bytes);
                false
            }

            DynSolValue::Array(elements) => {
                if elements.is_empty() {
                    return false;
                }

                match VecMutation::random(rng) {
                    VecMutation::Push => {
                        if elements.len() < 64 {
                            // Cap array size
                            // Clone a random element
                            let idx = rng.gen_range(0..elements.len());
                            let new_elem = elements[idx].clone();
                            elements.push(new_elem);
                        }
                    }
                    VecMutation::Remove => {
                        if elements.len() > 1 {
                            let idx = rng.gen_range(0..elements.len());
                            elements.remove(idx);
                        }
                    }
                    VecMutation::Replace => {
                        // Replace with mutated version
                        let idx = rng.gen_range(0..elements.len());
                        elements[idx].mutate(rng);
                    }
                    VecMutation::Swap => {
                        if elements.len() >= 2 {
                            let i = rng.gen_range(0..elements.len());
                            let j = rng.gen_range(0..elements.len());
                            elements.swap(i, j);
                        }
                    }
                    VecMutation::Shuffle => {
                        for i in (1..elements.len()).rev() {
                            let j = rng.gen_range(0..=i);
                            elements.swap(i, j);
                        }
                    }
                    VecMutation::Reverse => {
                        elements.reverse();
                    }
                    VecMutation::Duplicate => {
                        if elements.len() < 64 {
                            let idx = rng.gen_range(0..elements.len());
                            let elem = elements[idx].clone();
                            let insert_at = rng.gen_range(0..=elements.len());
                            elements.insert(insert_at, elem);
                        }
                    }
                    VecMutation::MutateElement => {
                        let idx = rng.gen_range(0..elements.len());
                        elements[idx].mutate(rng);
                    }
                    VecMutation::MutateMultiple => {
                        let count = rng.gen_range(1..=elements.len().min(4));
                        for _ in 0..count {
                            let idx = rng.gen_range(0..elements.len());
                            elements[idx].mutate(rng);
                        }
                    }
                }
                false
            }

            DynSolValue::FixedArray(elements) => {
                if elements.is_empty() {
                    return false;
                }

                // Fixed arrays can't change size, so we use a subset of mutations
                match rng.gen_range(0..5) {
                    0 => {
                        // Swap
                        if elements.len() >= 2 {
                            let i = rng.gen_range(0..elements.len());
                            let j = rng.gen_range(0..elements.len());
                            elements.swap(i, j);
                        }
                    }
                    1 => {
                        // Shuffle
                        for i in (1..elements.len()).rev() {
                            let j = rng.gen_range(0..=i);
                            elements.swap(i, j);
                        }
                    }
                    2 => {
                        // Reverse
                        elements.reverse();
                    }
                    3 => {
                        // Mutate single element
                        let idx = rng.gen_range(0..elements.len());
                        elements[idx].mutate(rng);
                    }
                    _ => {
                        // Mutate multiple elements
                        let count = rng.gen_range(1..=elements.len().min(4));
                        for _ in 0..count {
                            let idx = rng.gen_range(0..elements.len());
                            elements[idx].mutate(rng);
                        }
                    }
                }
                false
            }

            DynSolValue::Tuple(elements) => {
                if elements.is_empty() {
                    return false;
                }

                // For tuples (structs), mutate a random field
                // but we make it more targeted
                match rng.gen_range(0..3) {
                    0 => {
                        // Mutate single field
                        let idx = rng.gen_range(0..elements.len());
                        elements[idx].mutate(rng);
                    }
                    1 => {
                        // Mutate multiple fields
                        let count = rng.gen_range(1..=elements.len().min(3));
                        for _ in 0..count {
                            let idx = rng.gen_range(0..elements.len());
                            elements[idx].mutate(rng);
                        }
                    }
                    _ => {
                        // Mutate all fields
                        for elem in elements.iter_mut() {
                            elem.mutate(rng);
                        }
                    }
                }
                false
            }

            DynSolValue::Function(f) => {
                // Mutate as fixed bytes
                let mut bytes = f.0;
                bytes.mutate(rng);
                *f = alloy_primitives::Function::from(bytes);
                false
            }
        }
    }
}

// ============================================================================
// Transaction Delay Implementation
// ============================================================================

/// Mutable implementation for (time_delay, block_delay) tuples
impl Mutable for (u64, u64) {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        // Choose which component to mutate
        match rng.gen_range(0..4) {
            0 => {
                // Mutate time only
                self.0.mutate(rng);
            }
            1 => {
                // Mutate block only
                self.1.mutate(rng);
            }
            2 => {
                // Mutate both
                self.0.mutate(rng);
                self.1.mutate(rng);
            }
            _ => {
                // Set both to zero (level function behavior)
                if rng.gen_ratio(1, 4) {
                    *self = (0, 0);
                } else {
                    // Random small values
                    self.0 = rng.gen_range(0..=86400); // Up to 1 day
                    self.1 = rng.gen_range(0..=1000); // Up to 1000 blocks
                }
            }
        }

        // Apply level function: if one is zero, both are zero
        if self.0 == 0 || self.1 == 0 {
            *self = (0, 0);
        }

        false
    }
}

// ============================================================================
// Vec<DynSolValue> Implementation (for call arguments)
// ============================================================================

impl Mutable for Vec<DynSolValue> {
    fn mutate<R: Rng>(&mut self, rng: &mut R) -> bool {
        if self.is_empty() {
            return false;
        }

        // Mutate exactly one argument
        // This matches mutate_call behavior
        let idx = rng.gen_range(0..self.len());
        self[idx].mutate(rng);

        false
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Mutate a call's arguments using the new Mutable trait
/// This is a bridge function that matches the existing mutate_call signature
pub fn mutate_call_mutable<R: Rng>(
    rng: &mut R,
    name: &str,
    args: &[DynSolValue],
) -> (String, Vec<DynSolValue>) {
    if args.is_empty() {
        return (name.to_string(), vec![]);
    }

    let mut new_args = args.to_vec();

    // Mutate exactly one argument
    let idx = rng.gen_range(0..args.len());
    new_args[idx].mutate(rng);

    (name.to_string(), new_args)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_u256_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut value = U256::from(1000u64);

        // Run many mutations, some should change the value
        let original = value;
        let mut changed = false;
        for _ in 0..100 {
            value.mutate(&mut rng);
            if value != original {
                changed = true;
                break;
            }
        }
        assert!(changed, "U256 should mutate eventually");
    }

    #[test]
    fn test_bool_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut value = true;

        // Run mutations, should flip at least once
        let mut flipped = false;
        for _ in 0..100 {
            value.mutate(&mut rng);
            if !value {
                flipped = true;
                break;
            }
        }
        assert!(flipped, "Bool should flip eventually");
    }

    #[test]
    fn test_bytes_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut value = vec![1u8, 2, 3, 4, 5];

        let original = value.clone();
        let mut changed = false;
        for _ in 0..100 {
            value.mutate(&mut rng);
            if value != original {
                changed = true;
                break;
            }
        }
        assert!(changed, "Bytes should mutate");
    }

    #[test]
    fn test_bytes_mutation_can_produce_empty() {
        // Mutation should be able to produce empty bytes
        // This is critical for testing paths like `if (data.length > 0) callback(...)`
        let mut found_empty = false;

        // Try many times starting from small vectors
        for seed in 0..1000 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let mut value = vec![1u8]; // Start with 1 byte

            for _ in 0..50 {
                value.mutate(&mut rng);
                if value.is_empty() {
                    found_empty = true;
                    break;
                }
            }
            if found_empty {
                break;
            }
        }
        assert!(found_empty, "Mutation should eventually produce empty bytes ");
    }

    #[test]
    fn test_empty_bytes_can_stay_empty() {
        // Empty bytes should sometimes stay empty (no-op mutation)
        let mut stayed_empty_count = 0;

        for seed in 0..100 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let mut value: Vec<u8> = vec![];
            value.mutate(&mut rng);
            if value.is_empty() {
                stayed_empty_count += 1;
            }
        }
        // Should stay empty roughly 1/11 of the time (~9%)
        assert!(stayed_empty_count >= 3, "Empty bytes should sometimes stay empty, got {}/100", stayed_empty_count);
        assert!(stayed_empty_count <= 25, "Empty bytes shouldn't stay empty too often, got {}/100", stayed_empty_count);
    }

    #[test]
    fn test_dynsolvalue_uint_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut value = DynSolValue::Uint(U256::from(1000u64), 256);

        let original = value.clone();
        let mut changed = false;
        for _ in 0..100 {
            value.mutate(&mut rng);
            if value != original {
                changed = true;
                break;
            }
        }
        assert!(changed, "DynSolValue::Uint should mutate");
    }

    #[test]
    fn test_dynsolvalue_tuple_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut value = DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(100u64), 256),
            DynSolValue::Bool(true),
            DynSolValue::Address(Address::ZERO),
        ]);

        // Mutate several times
        for _ in 0..10 {
            value.mutate(&mut rng);
        }

        // Tuple should still have 3 elements
        if let DynSolValue::Tuple(elems) = &value {
            assert_eq!(elems.len(), 3, "Tuple should still have 3 elements");
        }
    }

    #[test]
    fn test_address_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut addr = Address::ZERO;

        // Run many mutations, should eventually change
        let mut changed = false;
        for _ in 0..100 {
            addr.mutate(&mut rng);
            if addr != Address::ZERO {
                changed = true;
                break;
            }
        }
        assert!(changed, "Address should mutate eventually");
    }

    #[test]
    fn test_interesting_addresses() {
        let addrs = interesting_addresses();
        assert!(addrs.len() >= 10, "Should have many interesting addresses");
        assert!(addrs.contains(&Address::ZERO), "Should contain zero address");
    }

    #[test]
    fn test_dynsolvalue_array_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut value = DynSolValue::Array(vec![
            DynSolValue::Uint(U256::from(1u64), 256),
            DynSolValue::Uint(U256::from(2u64), 256),
            DynSolValue::Uint(U256::from(3u64), 256),
        ]);

        let original_len = if let DynSolValue::Array(arr) = &value {
            arr.len()
        } else {
            0
        };

        // Mutate many times - length might change
        for _ in 0..50 {
            value.mutate(&mut rng);
        }

        if let DynSolValue::Array(arr) = &value {
            // Array might have grown or shrunk
            assert!(arr.len() >= 1, "Array should have at least 1 element");
            println!(
                "Array length changed from {} to {}",
                original_len,
                arr.len()
            );
        }
    }

    #[test]
    fn test_delay_mutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut delay = (100u64, 10u64);

        let original = delay;
        let mut changed = false;
        for _ in 0..100 {
            delay.mutate(&mut rng);
            if delay != original {
                changed = true;
                break;
            }
        }
        assert!(changed, "Delay should mutate");

        // Check level function behavior
        delay = (0, 10);
        delay.mutate(&mut rng);
        // After mutation, if one is zero, both should be zero
        // (this is probabilistic due to mutation)
    }

    #[test]
    fn test_interesting_values() {
        let interesting = interesting_u256();
        assert!(interesting.len() >= 20, "Should have many interesting U256 values");

        let interesting_signed = interesting_i256();
        assert!(
            interesting_signed.len() >= 10,
            "Should have many interesting I256 values"
        );
    }
}
