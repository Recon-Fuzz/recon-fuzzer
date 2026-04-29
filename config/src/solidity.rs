//! Solidity/compilation configuration
//!
//! Configuration for contract deployment and testing.

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// Test mode for the fuzzer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TestMode {
    /// Property testing (echidna_* functions returning bool)
    #[default]
    Property,
    /// Assertion testing (check for assertion failures)
    Assertion,
    /// Optimization testing (maximize return value)
    Optimization,
    /// Exploration mode (maximize coverage)
    Exploration,
}

impl TestMode {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "property" => Some(Self::Property),
            "assertion" => Some(Self::Assertion),
            "optimization" => Some(Self::Optimization),
            "exploration" => Some(Self::Exploration),
            _ => None,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Property => "property",
            Self::Assertion => "assertion",
            Self::Optimization => "optimization",
            Self::Exploration => "exploration",
        }
    }
}

impl std::fmt::Display for TestMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Solidity/compilation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SolConf {
    /// Contract address for main contract
    pub contract_addr: Address,

    /// Deployer address
    pub deployer: Address,

    /// Sender addresses
    pub sender: Vec<Address>,

    /// Test function prefix
    pub prefix: String,

    /// Quiet mode (less output)
    pub quiet: bool,

    /// Test mode
    pub test_mode: TestMode,

    /// Generate calls to all deployed contracts
    pub all_contracts: bool,

    /// Only fuzz state-mutating functions (exclude pure/view)
    pub mutable_only: bool,

    /// Initial ETH balance funded into deployer and each sender address.
    /// Mirrors echidna's `balanceAddr` (default 0xffffffff = ~4.29e9 wei).
    /// When None, recon's existing default funding (U256::MAX/2) is used.
    pub balance_addr: Option<U256>,

    /// Initial ETH balance of the deployed test contract.
    /// Mirrors echidna's `balanceContract` (default 0). Sent as msg.value
    /// during the constructor call, so `address(this).balance` reflects it.
    pub balance_contract: U256,

    /// Default chain id for the EVM. Mirrors echidna's `chainId` knob.
    /// `None` means: use 1 (mainnet) in non-fork mode, or the fork's actual
    /// chain id in fork mode. Setting it forces every tx to run with this
    /// chain id (overrides the fork value). Can also be changed at runtime
    /// via `vm.chainId(uint256)`.
    pub chain_id: Option<u64>,
}

impl Default for SolConf {
    fn default() -> Self {
        // Echidna's default contract address: 0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496
        let contract_addr = Address::from_slice(&hex_literal::hex!(
            "7FA9385bE102ac3EAc297483Dd6233D62b3e1496"
        ));
        // Default deployer: 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38
        let deployer = Address::from_slice(&hex_literal::hex!(
            "1804c8AB1F12E6bbf3894d4083f33e07309d1f38"
        ));

        Self {
            contract_addr,
            deployer,
            sender: primitives::default_senders(),
            prefix: "echidna_".to_string(),
            quiet: false,
            test_mode: TestMode::Property,
            all_contracts: false,
            mutable_only: false,
            balance_addr: None,
            balance_contract: U256::ZERO,
            chain_id: None,
        }
    }
}
