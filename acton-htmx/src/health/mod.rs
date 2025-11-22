//! Health check endpoints and handlers
//!
//! Provides comprehensive health checks for application monitoring, including:
//! - Liveness probe: Is the application running?
//! - Readiness probe: Is the application ready to serve traffic?
//! - Database connection health
//! - Redis connection health (if enabled)
//! - Background job system health
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use acton_htmx::health::{health_check, liveness, readiness};
//!
//! let app = Router::new()
//!     .route("/health", get(health_check))
//!     .route("/health/live", get(liveness))
//!     .route("/health/ready", get(readiness));
//! ```

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Health check status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy and ready
    Healthy,
    /// Service is degraded but operational
    Degraded,
    /// Service is unhealthy
    Unhealthy,
}

/// Individual component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status
    pub status: HealthStatus,
    /// Optional message with details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Response time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,
}

impl ComponentHealth {
    /// Create a healthy component
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: None,
            response_time_ms: None,
        }
    }

    /// Create a healthy component with message
    #[must_use]
    pub fn healthy_with_message(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: Some(message.into()),
            response_time_ms: None,
        }
    }

    /// Create a degraded component
    #[must_use]
    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: Some(message.into()),
            response_time_ms: None,
        }
    }

    /// Create an unhealthy component
    #[must_use]
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
            response_time_ms: None,
        }
    }

    /// Add response time
    #[must_use]
    pub const fn with_response_time(mut self, ms: u64) -> Self {
        self.response_time_ms = Some(ms);
        self
    }
}

/// Overall health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Overall status
    pub status: HealthStatus,
    /// Application version
    pub version: String,
    /// Timestamp of health check (Unix epoch)
    pub timestamp: u64,
    /// Individual component healths
    pub components: HashMap<String, ComponentHealth>,
}

impl HealthCheckResponse {
    /// Create new health check response
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Healthy,
            version: version.into(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            components: HashMap::new(),
        }
    }

    /// Add component health
    pub fn add_component(&mut self, name: impl Into<String>, health: ComponentHealth) {
        self.components.insert(name.into(), health);
        self.recalculate_status();
    }

    /// Recalculate overall status based on components
    fn recalculate_status(&mut self) {
        if self.components.values().any(|c| c.status == HealthStatus::Unhealthy) {
            self.status = HealthStatus::Unhealthy;
        } else if self.components.values().any(|c| c.status == HealthStatus::Degraded) {
            self.status = HealthStatus::Degraded;
        } else {
            self.status = HealthStatus::Healthy;
        }
    }

    /// Get HTTP status code based on health
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        match self.status {
            HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK, // Still operational
            HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for HealthCheckResponse {
    fn into_response(self) -> Response {
        let status = self.status_code();
        (status, Json(self)).into_response()
    }
}

/// Liveness probe handler
///
/// Returns 200 OK if the application is running.
/// This is a simple check that the process is alive.
///
/// # Example
///
/// ```rust,no_run
/// use axum::{Router, routing::get};
/// use acton_htmx::health::liveness;
///
/// let app = Router::new()
///     .route("/health/live", get(liveness));
/// ```
#[allow(clippy::unused_async)]
pub async fn liveness() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Readiness probe handler
///
/// Returns 200 OK if the application is ready to serve traffic.
/// This is a simple default implementation that always returns ready.
/// Override with custom readiness checks in your application.
///
/// # Example
///
/// ```rust,no_run
/// use axum::{Router, routing::get};
/// use acton_htmx::health::readiness;
///
/// let app = Router::new()
///     .route("/health/ready", get(readiness));
/// ```
#[allow(clippy::unused_async)]
pub async fn readiness() -> impl IntoResponse {
    let mut response = HealthCheckResponse::new(env!("CARGO_PKG_VERSION"));
    response.add_component("application", ComponentHealth::healthy());
    response
}

/// Comprehensive health check handler
///
/// Returns detailed health information about all components.
/// This is the default implementation that checks application health only.
/// Override with custom health checks in your application.
///
/// # Example
///
/// ```rust,no_run
/// use axum::{Router, routing::get};
/// use acton_htmx::health::health_check;
///
/// let app = Router::new()
///     .route("/health", get(health_check));
/// ```
#[allow(clippy::unused_async)]
pub async fn health_check() -> impl IntoResponse {
    let mut response = HealthCheckResponse::new(env!("CARGO_PKG_VERSION"));
    response.add_component("application", ComponentHealth::healthy());
    response
}

/// Create a custom health check with state
///
/// # Example
///
/// ```rust,no_run
/// use acton_htmx::health::{health_check_with_state, ComponentHealth, HealthCheckResponse};
/// use acton_htmx::state::ActonHtmxState;
/// use axum::extract::State;
///
/// async fn custom_health(State(state): State<ActonHtmxState>) -> HealthCheckResponse {
///     health_check_with_state(&state).await
/// }
/// ```
#[allow(clippy::unused_async)]
pub async fn health_check_with_state<S: Send + Sync>(_state: &S) -> HealthCheckResponse {
    let mut response = HealthCheckResponse::new(env!("CARGO_PKG_VERSION"));
    response.add_component("application", ComponentHealth::healthy());

    // Add more component checks here as needed
    // Example: database, redis, job queue, etc.

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_health_healthy() {
        let health = ComponentHealth::healthy();
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(health.message.is_none());
        assert!(health.response_time_ms.is_none());
    }

    #[test]
    fn test_component_health_with_message() {
        let health = ComponentHealth::healthy_with_message("All good");
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.message, Some("All good".to_string()));
    }

    #[test]
    fn test_component_health_degraded() {
        let health = ComponentHealth::degraded("High latency");
        assert_eq!(health.status, HealthStatus::Degraded);
        assert_eq!(health.message, Some("High latency".to_string()));
    }

    #[test]
    fn test_component_health_unhealthy() {
        let health = ComponentHealth::unhealthy("Connection failed");
        assert_eq!(health.status, HealthStatus::Unhealthy);
        assert_eq!(health.message, Some("Connection failed".to_string()));
    }

    #[test]
    fn test_component_health_with_response_time() {
        let health = ComponentHealth::healthy().with_response_time(150);
        assert_eq!(health.response_time_ms, Some(150));
    }

    #[test]
    fn test_health_check_response_new() {
        let response = HealthCheckResponse::new("1.0.0");
        assert_eq!(response.status, HealthStatus::Healthy);
        assert_eq!(response.version, "1.0.0");
        assert!(response.components.is_empty());
    }

    #[test]
    fn test_health_check_response_add_component() {
        let mut response = HealthCheckResponse::new("1.0.0");
        response.add_component("database", ComponentHealth::healthy());
        assert_eq!(response.components.len(), 1);
        assert_eq!(response.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_health_check_response_degraded_status() {
        let mut response = HealthCheckResponse::new("1.0.0");
        response.add_component("app", ComponentHealth::healthy());
        response.add_component("cache", ComponentHealth::degraded("High latency"));
        assert_eq!(response.status, HealthStatus::Degraded);
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    #[test]
    fn test_health_check_response_unhealthy_status() {
        let mut response = HealthCheckResponse::new("1.0.0");
        response.add_component("app", ComponentHealth::healthy());
        response.add_component("database", ComponentHealth::unhealthy("Connection failed"));
        assert_eq!(response.status, HealthStatus::Unhealthy);
        assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_liveness_handler() {
        let response = liveness().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readiness_handler() {
        let response = readiness().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_handler() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
