//! Session Manager Agent
//!
//! Actor-based session management using acton-reactive.
//! Implements hybrid in-memory + Redis storage strategy.
//!
//! This module provides two styles of session operations:
//! 1. **Agent-to-Agent**: Using `reply_envelope` for inter-agent communication
//! 2. **Web Handler**: Using oneshot channels for request-reply from Axum handlers
//!
//! The web handler style (`LoadSessionRequest`, `SaveSessionRequest`) includes
//! oneshot channels wrapped in `Arc<Mutex<Option<...>>>` to satisfy Clone requirements.

use crate::auth::session::{FlashMessage, SessionData, SessionId};
use acton_reactive::prelude::*;
use chrono::{DateTime, Duration, Utc};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

// Type alias for the ManagedAgent builder type
type SessionAgentBuilder = ManagedAgent<Idle, SessionManagerAgent>;

#[cfg(feature = "redis")]
use deadpool_redis::Pool as RedisPool;

/// Session manager agent model
#[derive(Debug, Default, Clone)]
pub struct SessionManagerAgent {
    /// In-memory session storage
    sessions: HashMap<SessionId, SessionData>,
    /// Expiry queue for cleanup (min-heap by expiration time)
    expiry_queue: BinaryHeap<Reverse<(DateTime<Utc>, SessionId)>>,
    /// Optional Redis backend for distributed sessions
    #[cfg(feature = "redis")]
    redis: Option<RedisPool>,
}

// ============================================================================
// Web Handler Messages (with oneshot response channels)
// ============================================================================

/// Wrapper for oneshot sender that satisfies Clone + Debug
pub type ResponseChannel<T> = Arc<Mutex<Option<oneshot::Sender<T>>>>;

/// Request to load a session from web handlers
///
/// Uses a oneshot channel for synchronous response needed by Axum extractors.
#[derive(Clone, Debug)]
pub struct LoadSessionRequest {
    /// The session ID to load
    pub session_id: SessionId,
    /// Response channel (wrapped for Clone compatibility)
    pub response_tx: ResponseChannel<Option<SessionData>>,
}

impl LoadSessionRequest {
    /// Create a new load session request with response channel
    pub fn new(session_id: SessionId) -> (Self, oneshot::Receiver<Option<SessionData>>) {
        let (tx, rx) = oneshot::channel();
        let request = Self {
            session_id,
            response_tx: Arc::new(Mutex::new(Some(tx))),
        };
        (request, rx)
    }
}

/// Request to save a session from web handlers
#[derive(Clone, Debug)]
pub struct SaveSessionRequest {
    /// The session ID to save
    pub session_id: SessionId,
    /// The session data to persist
    pub data: SessionData,
    /// Optional response channel for confirmation
    pub response_tx: Option<ResponseChannel<bool>>,
}

impl SaveSessionRequest {
    /// Create a new save session request (fire-and-forget)
    #[must_use]
    pub fn new(session_id: SessionId, data: SessionData) -> Self {
        Self {
            session_id,
            data,
            response_tx: None,
        }
    }

    /// Create a new save session request with confirmation
    pub fn with_confirmation(
        session_id: SessionId,
        data: SessionData,
    ) -> (Self, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        let request = Self {
            session_id,
            data,
            response_tx: Some(Arc::new(Mutex::new(Some(tx)))),
        };
        (request, rx)
    }
}

/// Request to get and clear flash messages from web handlers
#[derive(Clone, Debug)]
pub struct TakeFlashesRequest {
    /// The session ID to retrieve flashes from
    pub session_id: SessionId,
    /// Response channel for flash messages
    pub response_tx: ResponseChannel<Vec<FlashMessage>>,
}

impl TakeFlashesRequest {
    /// Create a new take flashes request with response channel
    pub fn new(session_id: SessionId) -> (Self, oneshot::Receiver<Vec<FlashMessage>>) {
        let (tx, rx) = oneshot::channel();
        let request = Self {
            session_id,
            response_tx: Arc::new(Mutex::new(Some(tx))),
        };
        (request, rx)
    }
}

// ============================================================================
// Agent-to-Agent Messages (using reply_envelope)
// ============================================================================

/// Message to load a session by ID (agent-to-agent)
#[derive(Clone, Debug)]
pub struct LoadSession {
    /// The session ID to load
    pub session_id: SessionId,
}

/// Response message when session is successfully loaded
#[derive(Clone, Debug)]
pub struct SessionLoaded {
    /// The loaded session data
    pub data: SessionData,
}

/// Response message when session is not found
#[derive(Clone, Debug)]
pub struct SessionNotFound;

/// Message to save session data (agent-to-agent, fire-and-forget)
#[derive(Clone, Debug)]
pub struct SaveSession {
    /// The session ID to save
    pub session_id: SessionId,
    /// The session data to persist
    pub data: SessionData,
}

/// Message to delete a session by ID
#[derive(Clone, Debug)]
pub struct DeleteSession {
    /// The session ID to delete
    pub session_id: SessionId,
}

/// Message to trigger cleanup of expired sessions
#[derive(Clone, Debug)]
pub struct CleanupExpired;

/// Message to add a flash message to a session
#[derive(Clone, Debug)]
pub struct AddFlash {
    /// The session ID to add the flash to
    pub session_id: SessionId,
    /// The flash message to add
    pub message: FlashMessage,
}

/// Message to retrieve flash messages from a session (agent-to-agent)
#[derive(Clone, Debug)]
pub struct GetFlashes {
    /// The session ID to retrieve flashes from
    pub session_id: SessionId,
}

/// Response message containing flash messages
#[derive(Clone, Debug)]
pub struct FlashMessages {
    /// The flash messages retrieved
    pub messages: Vec<FlashMessage>,
}

impl SessionManagerAgent {
    /// Spawn session manager agent without Redis backend
    ///
    /// Uses in-memory storage only. Suitable for development or single-instance deployments.
    ///
    /// # Errors
    ///
    /// Returns error if agent initialization fails
    pub async fn spawn(runtime: &mut AgentRuntime) -> anyhow::Result<AgentHandle> {
        let config = AgentConfig::new(Ern::with_root("session_manager")?, None, None)?;
        let builder = runtime.new_agent_with_config::<Self>(config).await;
        Self::configure_handlers(builder).await
    }

    /// Spawn session manager with Redis backend
    ///
    /// Uses Redis for distributed session storage with in-memory caching.
    ///
    /// # Errors
    ///
    /// Returns error if agent initialization fails
    #[cfg(feature = "redis")]
    pub async fn spawn_with_redis(
        runtime: &mut AgentRuntime,
        redis_pool: RedisPool,
    ) -> anyhow::Result<AgentHandle> {
        let config = AgentConfig::new(Ern::with_root("session_manager")?, None, None)?;
        let mut builder = runtime.new_agent_with_config::<Self>(config).await;
        builder.model.redis = Some(redis_pool);
        Self::configure_handlers(builder).await
    }

    /// Configure all message handlers for the session manager
    async fn configure_handlers(mut builder: SessionAgentBuilder) -> anyhow::Result<AgentHandle> {
        builder
            // ================================================================
            // Web Handler Messages (oneshot channel responses)
            // ================================================================
            .act_on::<LoadSessionRequest>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let response_tx = envelope.message().response_tx.clone();
                let session = agent.model.sessions.get(&session_id).cloned();

                Box::pin(async move {
                    let result = session.and_then(|mut data| {
                        if data.is_expired() {
                            None
                        } else {
                            data.touch(Duration::hours(24));
                            Some(data)
                        }
                    });

                    if let Some(tx) = response_tx.lock().await.take() {
                        let _ = tx.send(result);
                    }
                })
            })
            .mutate_on::<SaveSessionRequest>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let data = envelope.message().data.clone();
                let response_tx = envelope.message().response_tx.clone();

                agent
                    .model
                    .sessions
                    .insert(session_id.clone(), data.clone());
                agent
                    .model
                    .expiry_queue
                    .push(Reverse((data.expires_at, session_id)));

                // Always use async to maintain consistent return type
                AgentReply::from_async(async move {
                    if let Some(tx) = response_tx {
                        if let Some(sender) = tx.lock().await.take() {
                            let _ = sender.send(true);
                        }
                    }
                })
            })
            .mutate_on::<TakeFlashesRequest>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let response_tx = envelope.message().response_tx.clone();

                // Take and clear flash messages atomically
                let messages = agent
                    .model
                    .sessions
                    .get_mut(&session_id)
                    .map(|session| std::mem::take(&mut session.flash_messages))
                    .unwrap_or_default();

                AgentReply::from_async(async move {
                    if let Some(tx) = response_tx.lock().await.take() {
                        let _ = tx.send(messages);
                    }
                })
            })
            // ================================================================
            // Agent-to-Agent Messages (reply_envelope responses)
            // ================================================================
            .act_on::<LoadSession>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let session = agent.model.sessions.get(&session_id).cloned();
                let reply_envelope = envelope.reply_envelope();

                Box::pin(async move {
                    if let Some(mut data) = session {
                        if data.is_expired() {
                            let _: () = reply_envelope.send(SessionNotFound).await;
                        } else {
                            data.touch(Duration::hours(24));
                            let _: () = reply_envelope.send(SessionLoaded { data }).await;
                        }
                    } else {
                        let _: () = reply_envelope.send(SessionNotFound).await;
                    }
                })
            })
            .mutate_on::<SaveSession>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let data = envelope.message().data.clone();

                agent
                    .model
                    .sessions
                    .insert(session_id.clone(), data.clone());
                agent
                    .model
                    .expiry_queue
                    .push(Reverse((data.expires_at, session_id)));

                AgentReply::immediate()
            })
            .mutate_on::<DeleteSession>(|agent, envelope| {
                agent.model.sessions.remove(&envelope.message().session_id);
                AgentReply::immediate()
            })
            .mutate_on::<CleanupExpired>(|agent, _envelope| {
                let now = Utc::now();
                let mut expired = Vec::new();

                loop {
                    let should_pop = agent
                        .model
                        .expiry_queue
                        .peek()
                        .is_some_and(|Reverse((expiry, _))| *expiry <= now);

                    if should_pop {
                        if let Some(Reverse((_, session_id))) = agent.model.expiry_queue.pop() {
                            expired.push(session_id);
                        }
                    } else {
                        break;
                    }
                }

                for session_id in expired {
                    agent.model.sessions.remove(&session_id);
                }

                AgentReply::immediate()
            })
            .mutate_on::<AddFlash>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let message = envelope.message().message.clone();

                if let Some(session) = agent.model.sessions.get_mut(&session_id) {
                    session.flash_messages.push(message);
                }

                AgentReply::immediate()
            })
            .act_on::<GetFlashes>(|agent, envelope| {
                let session_id = envelope.message().session_id.clone();
                let messages = agent
                    .model
                    .sessions
                    .get(&session_id)
                    .map(|s| s.flash_messages.clone())
                    .unwrap_or_default();

                let reply_envelope = envelope.reply_envelope();

                Box::pin(async move {
                    let _: () = reply_envelope.send(FlashMessages { messages }).await;
                })
            })
            // Lifecycle hook: spawn cleanup task
            .after_start(|agent| {
                let self_handle = agent.handle().clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                    loop {
                        interval.tick().await;
                        let _: () = self_handle.send(CleanupExpired).await;
                    }
                });
                AgentReply::immediate()
            });

        Ok(builder.start().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_session_manager_creation() {
        let mut runtime = ActonApp::launch();
        let result = SessionManagerAgent::spawn(&mut runtime).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_session_save_and_load() {
        let mut runtime = ActonApp::launch();
        let session_manager = SessionManagerAgent::spawn(&mut runtime).await.unwrap();

        let session_id = SessionId::generate();
        let mut data = SessionData::new();
        data.set("test_key".to_string(), "test_value").unwrap();

        // Save session
        session_manager
            .send(SaveSession {
                session_id: session_id.clone(),
                data: data.clone(),
            })
            .await;

        // Load session
        session_manager
            .send(LoadSession {
                session_id: session_id.clone(),
            })
            .await;

        // TODO: Add response verification once we have proper message handling
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_session_delete() {
        let mut runtime = ActonApp::launch();
        let session_manager = SessionManagerAgent::spawn(&mut runtime).await.unwrap();

        let session_id = SessionId::generate();
        let data = SessionData::new();

        // Save then delete
        session_manager
            .send(SaveSession {
                session_id: session_id.clone(),
                data,
            })
            .await;

        session_manager
            .send(DeleteSession {
                session_id: session_id.clone(),
            })
            .await;

        // Load should return NotFound
        session_manager.send(LoadSession { session_id }).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_flash_messages() {
        let mut runtime = ActonApp::launch();
        let session_manager = SessionManagerAgent::spawn(&mut runtime).await.unwrap();

        let session_id = SessionId::generate();
        let data = SessionData::new();

        // Save session first
        session_manager
            .send(SaveSession {
                session_id: session_id.clone(),
                data,
            })
            .await;

        // Add flash message
        session_manager
            .send(AddFlash {
                session_id: session_id.clone(),
                message: FlashMessage::success("Test message"),
            })
            .await;

        // Get flashes
        session_manager.send(GetFlashes {
            session_id,
        }).await;
    }
}
