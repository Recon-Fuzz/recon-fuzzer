//! Fork error types

use thiserror::Error;

/// Errors from fork operations
#[derive(Error, Debug)]
pub enum ForkError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Invalid RPC URL: {0}")]
    InvalidUrl(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Rate limited")]
    RateLimited,
}

// Implement DBErrorMarker so ForkError can be used as Database::Error
impl revm::database::DBErrorMarker for ForkError {}
