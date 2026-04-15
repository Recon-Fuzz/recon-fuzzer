//! Transaction configuration
//!

use alloy_primitives::U256;
use primitives::{DEFAULT_BLOCK_DELAY, DEFAULT_TIME_DELAY, MAX_GAS_PER_BLOCK};
use serde::{Deserialize, Serialize};

/// Transaction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TxConf {
    /// Gas for property evaluation
    pub prop_gas: u64,

    /// Gas for generated transactions
    pub tx_gas: u64,

    /// Maximum gas price
    #[serde(with = "u256_serde")]
    pub max_gasprice: U256,

    /// Maximum time delay (seconds)
    pub max_time_delay: u64,

    /// Maximum block delay
    pub max_block_delay: u64,

    /// Maximum transaction value
    #[serde(with = "u256_serde")]
    pub max_value: U256,
}

impl Default for TxConf {
    fn default() -> Self {
        Self {
            prop_gas: MAX_GAS_PER_BLOCK,
            tx_gas: MAX_GAS_PER_BLOCK,
            max_gasprice: U256::ZERO,
            max_time_delay: DEFAULT_TIME_DELAY,
            max_block_delay: DEFAULT_BLOCK_DELAY,
            max_value: U256::from(100_000_000_000_000_000_000u128), // 100 ETH
        }
    }
}

/// Serde helper for U256
mod u256_serde {
    use alloy_primitives::U256;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if let Some(hex) = s.strip_prefix("0x") {
            U256::from_str_radix(hex, 16).map_err(serde::de::Error::custom)
        } else {
            s.parse().map_err(serde::de::Error::custom)
        }
    }
}
