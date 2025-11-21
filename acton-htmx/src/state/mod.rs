//! Application state management
//!
//! Combines acton-service infrastructure with acton-reactive actors and
//! HTMX-specific components.

use crate::agents::{CsrfManagerAgent, SessionManagerAgent};
use crate::{config::ActonHtmxConfig, observability::ObservabilityConfig};
use acton_reactive::prelude::{AgentHandle, AgentRuntime};
use std::sync::Arc;

/// Application state for acton-htmx applications
///
/// Combines:
/// - Configuration (from acton-service)
/// - Observability (from acton-service)
/// - Session management agent (from acton-reactive)
/// - CSRF protection agent (from acton-reactive)
/// - Database pools (from acton-service) - TODO
/// - Redis cache (from acton-service) - TODO
/// - Additional agents (jobs) - TODO
/// - Template registry - TODO
///
/// # Example
///
/// ```rust,ignore
/// use acton_htmx::state::ActonHtmxState;
/// use acton_reactive::prelude::ActonApp;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // Launch the Acton runtime - keep ownership in main
///     let mut runtime = ActonApp::launch();
///
///     // Create application state with agents
///     let state = ActonHtmxState::new(&mut runtime).await?;
///
///     // Build Axum router with state
///     let app = axum::Router::new()
///         .route("/", axum::routing::get(|| async { "Hello!" }))
///         .with_state(state);
///
///     // ... run server with graceful shutdown ...
///
///     // Shutdown the agent runtime after server stops
///     runtime.shutdown_all().await?;
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct ActonHtmxState {
    /// Application configuration
    config: Arc<ActonHtmxConfig>,

    /// Observability configuration
    observability: Arc<ObservabilityConfig>,

    /// Session manager agent handle
    ///
    /// Clone this freely - `AgentHandle` is designed for concurrent access
    session_manager: AgentHandle,

    /// CSRF manager agent handle
    ///
    /// Clone this freely - `AgentHandle` is designed for concurrent access
    csrf_manager: AgentHandle,
}

impl ActonHtmxState {
    /// Create new application state with defaults
    ///
    /// Spawns the session manager agent with in-memory storage.
    ///
    /// # Arguments
    ///
    /// * `runtime` - Mutable reference to the Acton runtime. The caller retains
    ///   ownership for shutdown orchestration.
    ///
    /// # Errors
    ///
    /// Returns error if agent spawning fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use acton_htmx::state::ActonHtmxState;
    /// use acton_reactive::prelude::ActonApp;
    ///
    /// let mut runtime = ActonApp::launch();
    /// let state = ActonHtmxState::new(&mut runtime).await?;
    /// ```
    pub async fn new(runtime: &mut AgentRuntime) -> anyhow::Result<Self> {
        let config = ActonHtmxConfig::default();
        let observability = ObservabilityConfig::default();
        let session_manager = SessionManagerAgent::spawn(runtime).await?;
        let csrf_manager = CsrfManagerAgent::spawn(runtime).await?;

        Ok(Self {
            config: Arc::new(config),
            observability: Arc::new(observability),
            session_manager,
            csrf_manager,
        })
    }

    /// Create application state with custom configuration
    ///
    /// # Arguments
    ///
    /// * `runtime` - Mutable reference to the Acton runtime
    /// * `config` - Custom configuration for the application
    ///
    /// # Errors
    ///
    /// Returns error if agent spawning fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use acton_htmx::{config::ActonHtmxConfig, state::ActonHtmxState};
    /// use acton_reactive::prelude::ActonApp;
    ///
    /// let mut runtime = ActonApp::launch();
    /// let config = ActonHtmxConfig::load_for_service("my-app")?;
    /// let state = ActonHtmxState::with_config(&mut runtime, config).await?;
    /// ```
    pub async fn with_config(
        runtime: &mut AgentRuntime,
        config: ActonHtmxConfig,
    ) -> anyhow::Result<Self> {
        let observability = ObservabilityConfig::new("acton-htmx");
        let session_manager = SessionManagerAgent::spawn(runtime).await?;
        let csrf_manager = CsrfManagerAgent::spawn(runtime).await?;

        Ok(Self {
            config: Arc::new(config),
            observability: Arc::new(observability),
            session_manager,
            csrf_manager,
        })
    }

    /// Get configuration reference
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use acton_htmx::state::ActonHtmxState;
    ///
    /// let state = ActonHtmxState::new(&mut runtime).await?;
    /// let config = state.config();
    /// let timeout = config.htmx.request_timeout_ms;
    /// ```
    #[must_use]
    pub fn config(&self) -> &ActonHtmxConfig {
        &self.config
    }

    /// Get observability configuration
    #[must_use]
    pub fn observability(&self) -> &ObservabilityConfig {
        &self.observability
    }

    /// Get the session manager agent handle
    ///
    /// Use this to send session-related messages directly to the agent.
    /// For most use cases, prefer using the `SessionExtractor` in handlers.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use acton_htmx::agents::{LoadSessionRequest, SaveSessionRequest};
    ///
    /// async fn handler(State(state): State<ActonHtmxState>) {
    ///     let (request, rx) = LoadSessionRequest::new(session_id);
    ///     state.session_manager().send(request).await;
    ///     let session_data = rx.await.ok().flatten();
    /// }
    /// ```
    #[must_use]
    pub fn session_manager(&self) -> &AgentHandle {
        &self.session_manager
    }

    /// Get the CSRF manager agent handle
    ///
    /// Use this to send CSRF-related messages directly to the agent.
    /// For most use cases, prefer using the `CsrfMiddleware` and extractors.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use acton_htmx::agents::{GetOrCreateTokenRequest, ValidateTokenRequest};
    ///
    /// async fn handler(State(state): State<ActonHtmxState>) {
    ///     let (request, rx) = GetOrCreateTokenRequest::new(session_id);
    ///     state.csrf_manager().send(request).await;
    ///     let token = rx.await.ok();
    /// }
    /// ```
    #[must_use]
    pub const fn csrf_manager(&self) -> &AgentHandle {
        &self.csrf_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_reactive::prelude::ActonApp;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_new_state() {
        let mut runtime = ActonApp::launch();
        let state = ActonHtmxState::new(&mut runtime)
            .await
            .expect("Failed to create state");
        assert_eq!(state.config().htmx.request_timeout_ms, 5000);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_with_config() {
        let mut runtime = ActonApp::launch();
        let mut config = ActonHtmxConfig::default();
        config.htmx.request_timeout_ms = 10000;

        let state = ActonHtmxState::with_config(&mut runtime, config)
            .await
            .expect("Failed to create state");

        assert_eq!(state.config().htmx.request_timeout_ms, 10000);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_clone_state() {
        let mut runtime = ActonApp::launch();
        let state = ActonHtmxState::new(&mut runtime)
            .await
            .expect("Failed to create state");
        let cloned = state.clone();

        // Both should reference the same Arc for config
        assert!(Arc::ptr_eq(&state.config, &cloned.config));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_session_manager_accessible() {
        let mut runtime = ActonApp::launch();
        let state = ActonHtmxState::new(&mut runtime)
            .await
            .expect("Failed to create state");

        // Should be able to get the session manager handle
        let _handle = state.session_manager();
    }
}
