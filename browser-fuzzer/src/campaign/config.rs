use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EConfig {
    pub seed: u64,
    pub seq_len: usize,
    pub test_limit: u64,
    pub shrink_limit: i32,
    pub max_value: String,
    pub max_time_delay: u64,
    pub max_block_delay: u64,
}

impl Default for EConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            seq_len: 100,
            test_limit: 50000,
            shrink_limit: 5000,
            max_value: "0xffffffffffffffffffffffffffffffff".to_string(),
            max_time_delay: 604800,
            max_block_delay: 60480,
        }
    }
}
