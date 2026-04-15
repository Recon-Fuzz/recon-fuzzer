//! Global constants used throughout the fuzzer
//!
//! These constants define the EVM environment and fuzzing parameters.

use alloy_primitives::Address;

// =============================================================================
// EVM Constants
// =============================================================================

/// Maximum gas per block (Ethereum mainnet)
pub const MAX_GAS_PER_BLOCK: u64 = 30_000_000;

/// Initial timestamp
pub const INITIAL_TIMESTAMP: u64 = 1524785992;

/// Initial block number (Byzantium fork)
pub const INITIAL_BLOCK_NUMBER: u64 = 4370000;

/// HEVM cheatcode contract address
/// 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D
pub const HEVM_ADDRESS: Address = Address::new([
    0x71, 0x09, 0x70, 0x9E, 0xCf, 0xa9, 0x1a, 0x80, 0x62, 0x6f, 0xF3, 0x98, 0x9D, 0x68, 0xf6, 0x7F,
    0x5b, 0x1D, 0xD1, 0x2D,
]);

// =============================================================================
// Delay Constants
// =============================================================================

/// Default time delay between transactions (1 week in seconds)
pub const DEFAULT_TIME_DELAY: u64 = 604800;

/// Default block delay between transactions
pub const DEFAULT_BLOCK_DELAY: u64 = 60480;

/// Extended time delay for reaching distant timestamps (10 years in seconds)
/// Used when smart delta detection finds timestamps that need large jumps
pub const EXTENDED_TIME_DELAY: u64 = 315360000; // 10 years

/// Extended block delay for reaching distant block numbers (10 years at 12s/block)
pub const EXTENDED_BLOCK_DELAY: u64 = 26280000; // ~10 years at 12s/block

// =============================================================================
// Type Size Constants
// =============================================================================

/// Common integer bit sizes used in Solidity
pub const COMMON_TYPE_SIZES: &[usize] = &[
    8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168,
    176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256,
];

// =============================================================================
// Default Values
// =============================================================================

/// Default balance for test accounts (very large)
pub const DEFAULT_BALANCE: u128 = 0xffffffffffffffffffffffffffffffff;

/// Default gas price
pub const DEFAULT_GAS_PRICE: u64 = 0;

/// Maximum transaction value (100 ETH in wei)
pub const DEFAULT_MAX_VALUE: u128 = 100_000_000_000_000_000_000;
