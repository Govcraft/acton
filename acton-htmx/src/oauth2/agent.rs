//! OAuth2 state management agent
//!
//! This module provides an acton-reactive agent for managing OAuth2 state tokens
//! and preventing CSRF attacks during the OAuth2 flow.

use acton_reactive::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{oneshot, Mutex};

use super::types::{OAuthProvider, OAuthState};

/// Type alias for response channels (web handler pattern)
pub type ResponseChannel<T> = Arc<Mutex<Option<oneshot::Sender<T>>>>;

/// OAuth2 state management agent
///
/// This agent stores and validates OAuth2 state tokens to prevent CSRF attacks.
/// State tokens are ephemeral and expire after 10 minutes.
#[derive(Debug, Default, Clone)]
pub struct OAuth2Agent {
    /// Map of state tokens to their metadata
    states: HashMap<String, OAuthState>,
}

impl OAuth2Agent {
    /// Clean up expired state tokens
    fn cleanup_expired(&mut self) {
        let now = SystemTime::now();
        self.states.retain(|_, state| state.expires_at > now);
    }
}

/// Message to generate a new OAuth2 state token (web handler)
#[derive(Debug, Clone)]
pub struct GenerateState {
    /// Provider for this state
    pub provider: OAuthProvider,
    /// Response channel
    pub response_tx: ResponseChannel<OAuthState>,
}

impl GenerateState {
    /// Create a new generate state request with response channel
    #[must_use]
    pub fn new(provider: OAuthProvider) -> (Self, oneshot::Receiver<OAuthState>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                provider,
                response_tx: Arc::new(Mutex::new(Some(tx))),
            },
            rx,
        )
    }
}

/// Message to validate an OAuth2 state token (web handler)
#[derive(Debug, Clone)]
pub struct ValidateState {
    /// State token to validate
    pub token: String,
    /// Response channel
    pub response_tx: ResponseChannel<Option<OAuthState>>,
}

impl ValidateState {
    /// Create a new validate state request with response channel
    #[must_use]
    pub fn new(token: String) -> (Self, oneshot::Receiver<Option<OAuthState>>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                token,
                response_tx: Arc::new(Mutex::new(Some(tx))),
            },
            rx,
        )
    }
}

/// Message to remove a state token (after successful use)
#[derive(Debug, Clone)]
pub struct RemoveState {
    /// State token to remove
    pub token: String,
}

/// Message to clean up expired state tokens
#[derive(Debug, Clone)]
pub struct CleanupExpired;

impl OAuth2Agent {
    /// Spawn OAuth2 manager agent
    ///
    /// # Errors
    ///
    /// Returns error if agent configuration or spawning fails
    pub async fn spawn(runtime: &mut AgentRuntime) -> anyhow::Result<AgentHandle> {
        let config = AgentConfig::new(Ern::with_root("oauth2_manager")?, None, None)?;

        let mut builder = runtime.new_agent_with_config::<Self>(config).await;

        // Configure handlers using mutate_on (all operations mutate state)
        builder
            .mutate_on::<GenerateState>(|agent, envelope| {
                let response_tx = envelope.message().response_tx.clone();
                let provider = envelope.message().provider;

                // Clean up expired tokens periodically
                agent.model.cleanup_expired();

                // Generate and store state token
                let state = OAuthState::generate(provider);
                agent.model.states.insert(state.token.clone(), state.clone());

                tracing::debug!(
                    provider = ?provider,
                    token = %state.token,
                    "Generated OAuth2 state token"
                );

                AgentReply::from_async(async move {
                    let mut guard = response_tx.lock().await;
                    if let Some(tx) = guard.take() {
                        let _ = tx.send(state);
                    }
                })
            })
            .mutate_on::<ValidateState>(|agent, envelope| {
                let token = envelope.message().token.clone();
                let response_tx = envelope.message().response_tx.clone();

                // Clean up expired tokens
                agent.model.cleanup_expired();

                // Validate state token
                let state = agent.model.states.get(&token).and_then(|state| {
                    if !state.is_expired() {
                        tracing::debug!(
                            token = %token,
                            provider = ?state.provider,
                            "Validated OAuth2 state token"
                        );
                        Some(state.clone())
                    } else {
                        tracing::warn!(token = %token, "OAuth2 state token expired");
                        None
                    }
                });

                AgentReply::from_async(async move {
                    let mut guard = response_tx.lock().await;
                    if let Some(tx) = guard.take() {
                        let _ = tx.send(state);
                    }
                })
            })
            .mutate_on::<RemoveState>(|agent, envelope| {
                let token = envelope.message().token.clone();

                if agent.model.states.remove(&token).is_some() {
                    tracing::debug!(token = %token, "Removed OAuth2 state token");
                }

                AgentReply::immediate()
            })
            .mutate_on::<CleanupExpired>(|agent, _envelope| {
                let before = agent.model.states.len();
                agent.model.cleanup_expired();
                let removed = before - agent.model.states.len();

                if removed > 0 {
                    tracing::debug!(
                        removed = removed,
                        remaining = agent.model.states.len(),
                        "Cleaned up expired OAuth2 state tokens"
                    );
                }

                AgentReply::immediate()
            })
            .after_start(|_agent| async {
                tracing::info!("OAuth2 manager agent started");
            })
            .after_stop(|agent| {
                let token_count = agent.model.states.len();
                async move {
                    tracing::info!(
                        tokens = token_count,
                        "OAuth2 manager agent stopped"
                    );
                }
            });

        Ok(builder.start().await)
    }
}
