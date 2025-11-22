//! Error types and error handling

#![allow(dead_code)]

use thiserror::Error;

/// Framework error type
#[derive(Debug, Error)]
pub enum ActonHtmxError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Bad request error
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Server error
    #[error("Server error: {0}")]
    ServerError(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// OAuth2 error
    #[error("OAuth2 error: {0}")]
    OAuth(#[from] crate::oauth2::types::OAuthError),

    /// Session error
    #[error("Session error: {0}")]
    SessionError(#[from] crate::auth::SessionError),
}
