//! CSRF Manager Agent
//!
//! Actor-based CSRF token management using acton-reactive.
//! Implements per-session token generation, validation, and rotation.
//!
//! This module provides two styles of CSRF operations:
//! 1. **Agent-to-Agent**: Using `reply_envelope` for inter-agent communication
//! 2. **Web Handler**: Using oneshot channels for request-reply from Axum handlers
//!
//! CSRF tokens are:
//! - Cryptographically secure (32 bytes of randomness)
//! - Stored per-session (one active token per session)
//! - Automatically rotated on successful validation
//! - Validated against POST/PUT/DELETE/PATCH requests

use crate::auth::session::SessionId;
use acton_reactive::prelude::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

// Type alias for the ManagedAgent builder type
type CsrfAgentBuilder = ManagedAgent<Idle, CsrfManagerAgent>;

/// CSRF token string (base64url-encoded 32-byte random value)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CsrfToken(String);

impl CsrfToken {
    /// Generate a new cryptographically secure CSRF token
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Get the token as a string slice
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Create a token from a string (for validation)
    #[must_use]
    pub const fn from_string(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// CSRF token data stored per session
#[derive(Clone, Debug)]
struct CsrfTokenData {
    /// The actual token
    token: CsrfToken,
    /// When the token expires (24 hours by default)
    expires_at: DateTime<Utc>,
}

impl CsrfTokenData {
    /// Create new token data with default expiration (24 hours)
    #[must_use]
    fn new(token: CsrfToken) -> Self {
        let expires_at = Utc::now() + Duration::hours(24);
        Self { token, expires_at }
    }

    /// Check if the token has expired
    #[must_use]
    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// CSRF manager agent model
#[derive(Debug, Default, Clone)]
pub struct CsrfManagerAgent {
    /// Token storage per session
    tokens: HashMap<SessionId, CsrfTokenData>,
}

// ============================================================================
// Web Handler Messages (with oneshot response channels)
// ============================================================================

/// Wrapper for oneshot sender that satisfies Clone + Debug
pub type ResponseChannel<T> = Arc<Mutex<Option<oneshot::Sender<T>>>>;

/// Request to get or create a CSRF token for a session
#[derive(Clone, Debug)]
pub struct GetOrCreateTokenRequest {
    /// The session ID to get/create token for
    pub session_id: SessionId,
    /// Response channel (wrapped for Clone compatibility)
    pub response_tx: ResponseChannel<CsrfToken>,
}

impl GetOrCreateTokenRequest {
    /// Create a new get-or-create token request with response channel
    #[must_use]
    pub fn new(session_id: SessionId) -> (Self, oneshot::Receiver<CsrfToken>) {
        let (tx, rx) = oneshot::channel();
        let request = Self {
            session_id,
            response_tx: Arc::new(Mutex::new(Some(tx))),
        };
        (request, rx)
    }
}

/// Request to validate a CSRF token
#[derive(Clone, Debug)]
pub struct ValidateTokenRequest {
    /// The session ID to validate against
    pub session_id: SessionId,
    /// The token to validate
    pub token: CsrfToken,
    /// Response channel for validation result
    pub response_tx: ResponseChannel<bool>,
}

impl ValidateTokenRequest {
    /// Create a new validate token request with response channel
    #[must_use]
    pub fn new(session_id: SessionId, token: CsrfToken) -> (Self, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        let request = Self {
            session_id,
            token,
            response_tx: Arc::new(Mutex::new(Some(tx))),
        };
        (request, rx)
    }
}

/// Request to delete a CSRF token (on session cleanup)
#[derive(Clone, Debug)]
pub struct DeleteTokenRequest {
    /// The session ID to delete token for
    pub session_id: SessionId,
}

impl DeleteTokenRequest {
    /// Create a new delete token request (fire-and-forget)
    #[must_use]
    pub const fn new(session_id: SessionId) -> Self {
        Self { session_id }
    }
}

// ============================================================================
// Agent-to-Agent Messages (using reply_envelope)
// ============================================================================

/// Message to get or create a CSRF token (agent-to-agent)
#[derive(Clone, Debug)]
pub struct GetOrCreateToken {
    /// The session ID to get/create token for
    pub session_id: SessionId,
}

/// Response message containing the CSRF token
#[derive(Clone, Debug)]
pub struct TokenResponse {
    /// The CSRF token
    pub token: CsrfToken,
}

/// Message to validate a CSRF token (agent-to-agent)
#[derive(Clone, Debug)]
pub struct ValidateToken {
    /// The session ID to validate against
    pub session_id: SessionId,
    /// The token to validate
    pub token: CsrfToken,
}

/// Response message for token validation
#[derive(Clone, Debug)]
pub struct ValidationResponse {
    /// Whether the token is valid
    pub valid: bool,
}

/// Message to delete a CSRF token
#[derive(Clone, Debug)]
pub struct DeleteToken {
    /// The session ID to delete token for
    pub session_id: SessionId,
}

/// Message to cleanup expired tokens
#[derive(Clone, Debug)]
pub struct CleanupExpired;

impl CsrfManagerAgent {
    /// Spawn CSRF manager agent
    ///
    /// # Errors
    ///
    /// Returns error if agent initialization fails
    pub async fn spawn(runtime: &mut AgentRuntime) -> anyhow::Result<AgentHandle> {
        let config = AgentConfig::new(Ern::with_root("csrf_manager")?, None, None)?;
        let builder = runtime.new_agent_with_config::<Self>(config).await;
        Self::configure_handlers(builder).await
    }

    /// Configure all message handlers for the CSRF manager
    async fn configure_handlers(mut builder: CsrfAgentBuilder) -> anyhow::Result<AgentHandle> {
        Self::configure_web_handlers(&mut builder);
        Self::configure_agent_handlers(&mut builder);
        Self::configure_cleanup_handler(&mut builder);

        Ok(builder.start().await)
    }

    /// Configure web handler messages (oneshot channel responses)
    fn configure_web_handlers(builder: &mut CsrfAgentBuilder) {
        builder
            .mutate_on::<GetOrCreateTokenRequest>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let response_tx = envelope.message().response_tx.clone();

                let token = Self::get_or_create_token_internal(&mut agent.model, &session_id);

                AgentReply::from_async(async move {
                    Self::send_token_response(response_tx, token).await;
                })
            })
            .mutate_on::<ValidateTokenRequest>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let token = envelope.message().token.clone();
                let response_tx = envelope.message().response_tx.clone();

                let valid = Self::validate_and_rotate_token(&mut agent.model, &session_id, &token);

                AgentReply::from_async(async move {
                    Self::send_validation_response(response_tx, valid).await;
                })
            })
            .mutate_on::<DeleteTokenRequest>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                agent.model.tokens.remove(&session_id);
                AgentReply::immediate()
            });
    }

    /// Configure agent-to-agent messages (reply_envelope responses)
    fn configure_agent_handlers(builder: &mut CsrfAgentBuilder) {
        builder
            .mutate_on::<GetOrCreateToken>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let reply_envelope = envelope.reply_envelope();

                let token = Self::get_or_create_token_internal(&mut agent.model, &session_id);

                AgentReply::from_async(async move {
                    let _: () = reply_envelope.send(TokenResponse { token }).await;
                })
            })
            .mutate_on::<ValidateToken>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let token = envelope.message().token.clone();
                let reply_envelope = envelope.reply_envelope();

                let valid = Self::validate_and_rotate_token(&mut agent.model, &session_id, &token);

                AgentReply::from_async(async move {
                    let _: () = reply_envelope.send(ValidationResponse { valid }).await;
                })
            })
            .mutate_on::<DeleteToken>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                agent.model.tokens.remove(&session_id);
                AgentReply::immediate()
            });
    }

    /// Configure cleanup handler
    fn configure_cleanup_handler(builder: &mut CsrfAgentBuilder) {
        builder.mutate_on::<CleanupExpired>(|agent, _envelope| {
            agent.model.tokens.retain(|_session_id, data| !data.is_expired());
            tracing::debug!(
                "Cleaned up expired CSRF tokens, {} tokens remaining",
                agent.model.tokens.len()
            );
            AgentReply::immediate()
        });
    }

    /// Pure function: Get or create a CSRF token
    fn get_or_create_token_internal(model: &mut Self, session_id: &SessionId) -> CsrfToken {
        if let Some(data) = model.tokens.get(session_id) {
            if !data.is_expired() {
                return data.token.clone();
            }
        }

        // Create new token
        let new_token = CsrfToken::generate();
        model
            .tokens
            .insert(session_id.clone(), CsrfTokenData::new(new_token.clone()));
        new_token
    }

    /// Pure function: Validate token and rotate on success
    fn validate_and_rotate_token(
        model: &mut Self,
        session_id: &SessionId,
        token: &CsrfToken,
    ) -> bool {
        let valid = model
            .tokens
            .get(session_id)
            .filter(|data| !data.is_expired() && &data.token == token)
            .is_some();

        if valid {
            let new_token = CsrfToken::generate();
            model
                .tokens
                .insert(session_id.clone(), CsrfTokenData::new(new_token));
        }

        valid
    }

    /// Send token response via oneshot channel
    async fn send_token_response(response_tx: ResponseChannel<CsrfToken>, token: CsrfToken) {
        let mut guard = response_tx.lock().await;
        if let Some(tx) = guard.take() {
            let _ = tx.send(token);
        }
    }

    /// Send validation response via oneshot channel
    async fn send_validation_response(response_tx: ResponseChannel<bool>, valid: bool) {
        let mut guard = response_tx.lock().await;
        if let Some(tx) = guard.take() {
            let _ = tx.send(valid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token_generation() {
        let token1 = CsrfToken::generate();
        let token2 = CsrfToken::generate();

        // Tokens should be unique
        assert_ne!(token1, token2);

        // Tokens should be base64url encoded (44 chars for 32 bytes)
        assert_eq!(token1.as_str().len(), 43); // 32 bytes = 43 base64url chars without padding
    }

    #[test]
    fn test_csrf_token_display() {
        let token = CsrfToken::generate();
        let as_string = format!("{token}");
        assert_eq!(as_string, token.as_str());
    }

    #[test]
    fn test_csrf_token_from_string() {
        let original = "test_token_value";
        let token = CsrfToken::from_string(original.to_string());
        assert_eq!(token.as_str(), original);
    }

    #[test]
    fn test_csrf_token_data_creation() {
        let token = CsrfToken::generate();
        let data = CsrfTokenData::new(token.clone());

        assert_eq!(data.token, token);
        assert!(!data.is_expired());
        assert!(data.expires_at > Utc::now());
    }

    #[test]
    fn test_csrf_token_data_expiration() {
        let token = CsrfToken::generate();
        let mut data = CsrfTokenData::new(token);

        // Manually set expiration to the past
        data.expires_at = Utc::now() - Duration::hours(1);

        assert!(data.is_expired());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_csrf_manager_spawn() {
        let mut runtime = ActonApp::launch();
        let result = CsrfManagerAgent::spawn(&mut runtime).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_or_create_token() {
        let mut runtime = ActonApp::launch();
        let handle = CsrfManagerAgent::spawn(&mut runtime).await.unwrap();

        let session_id = SessionId::generate();
        let (request, rx) = GetOrCreateTokenRequest::new(session_id.clone());

        handle.send(request).await;

        let token1 = rx.await.expect("Failed to receive token");

        // Request again - should get the same token
        let (request2, rx2) = GetOrCreateTokenRequest::new(session_id);
        handle.send(request2).await;

        let token2 = rx2.await.expect("Failed to receive token");

        assert_eq!(token1, token2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_validate_token_success() {
        let mut runtime = ActonApp::launch();
        let handle = CsrfManagerAgent::spawn(&mut runtime).await.unwrap();

        let session_id = SessionId::generate();

        // Get a token
        let (request, rx) = GetOrCreateTokenRequest::new(session_id.clone());
        handle.send(request).await;
        let token = rx.await.expect("Failed to receive token");

        // Validate it
        let (validate_request, validate_rx) =
            ValidateTokenRequest::new(session_id.clone(), token.clone());
        handle.send(validate_request).await;
        let valid = validate_rx.await.expect("Failed to receive validation result");

        assert!(valid);

        // After validation, token should be rotated - old token should be invalid
        let (validate_request2, validate_rx2) = ValidateTokenRequest::new(session_id, token);
        handle.send(validate_request2).await;
        let valid2 = validate_rx2
            .await
            .expect("Failed to receive validation result");

        assert!(!valid2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_validate_token_failure() {
        let mut runtime = ActonApp::launch();
        let handle = CsrfManagerAgent::spawn(&mut runtime).await.unwrap();

        let session_id = SessionId::generate();

        // Get a token
        let (request, rx) = GetOrCreateTokenRequest::new(session_id.clone());
        handle.send(request).await;
        let _token = rx.await.expect("Failed to receive token");

        // Try to validate with wrong token
        let wrong_token = CsrfToken::generate();
        let (validate_request, validate_rx) = ValidateTokenRequest::new(session_id, wrong_token);
        handle.send(validate_request).await;
        let valid = validate_rx.await.expect("Failed to receive validation result");

        assert!(!valid);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_delete_token() {
        let mut runtime = ActonApp::launch();
        let handle = CsrfManagerAgent::spawn(&mut runtime).await.unwrap();

        let session_id = SessionId::generate();

        // Get a token
        let (request, rx) = GetOrCreateTokenRequest::new(session_id.clone());
        handle.send(request).await;
        let token = rx.await.expect("Failed to receive token");

        // Delete the token
        let delete_request = DeleteTokenRequest::new(session_id.clone());
        handle.send(delete_request).await;

        // Try to validate - should fail
        let (validate_request, validate_rx) = ValidateTokenRequest::new(session_id, token);
        handle.send(validate_request).await;
        let valid = validate_rx.await.expect("Failed to receive validation result");

        assert!(!valid);
    }
}
