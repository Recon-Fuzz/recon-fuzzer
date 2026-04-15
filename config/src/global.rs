//! Global configuration
//!
//! Top-level configuration container

use serde::{Deserialize, Serialize};

use crate::{campaign::CampaignConf, solidity::SolConf, transaction::TxConf};

/// Global configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EConfig {
    pub campaign_conf: CampaignConf,
    pub tx_conf: TxConf,
    pub sol_conf: SolConf,
    pub rpc_url: Option<String>,
    pub rpc_block: Option<u64>,
    pub project_name: Option<String>,
}

impl EConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_campaign(mut self, conf: CampaignConf) -> Self {
        self.campaign_conf = conf;
        self
    }

    pub fn with_tx(mut self, conf: TxConf) -> Self {
        self.tx_conf = conf;
        self
    }

    pub fn with_sol(mut self, conf: SolConf) -> Self {
        self.sol_conf = conf;
        self
    }

    pub fn with_rpc(mut self, url: impl Into<String>, block: Option<u64>) -> Self {
        self.rpc_url = Some(url.into());
        self.rpc_block = block;
        self
    }
}
