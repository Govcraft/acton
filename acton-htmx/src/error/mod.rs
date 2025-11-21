//! Error types and error handling

#![allow(dead_code)]

use thiserror::Error;

/// Framework error type
#[derive(Debug, Error)]
pub enum ActonHtmxError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
}
