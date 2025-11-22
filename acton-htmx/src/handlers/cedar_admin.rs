//! Cedar policy administration handlers
//!
//! This module provides HTTP handlers for managing Cedar policies at runtime.
//! These handlers should be protected with admin-only authorization.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use acton_htmx::handlers::cedar_admin;
//! use axum::Router;
//!
//! let admin_routes = Router::new()
//!     .route("/admin/cedar/reload", post(cedar_admin::reload_policies))
//!     .route("/admin/cedar/status", get(cedar_admin::policy_status));
//! ```

#[cfg(feature = "cedar")]
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[cfg(feature = "cedar")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "cedar")]
use crate::{
    auth::{user::User, Authenticated},
    middleware::cedar::CedarAuthz,
};

/// Response for policy reload endpoint
#[cfg(feature = "cedar")]
#[derive(Debug, Serialize, Deserialize)]
pub struct ReloadPolicyResponse {
    /// Whether the reload was successful
    pub success: bool,

    /// Success or error message
    pub message: String,

    /// Timestamp of reload (ISO 8601)
    pub timestamp: String,
}

/// Response for policy status endpoint
#[cfg(feature = "cedar")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyStatusResponse {
    /// Whether Cedar authorization is enabled
    pub enabled: bool,

    /// Path to the policy file
    pub policy_path: String,

    /// Whether hot-reload is enabled
    pub hot_reload: bool,

    /// Failure mode (open or closed)
    pub failure_mode: String,

    /// Whether policy caching is enabled
    pub cache_enabled: bool,
}

/// Reload Cedar policies from file
///
/// This endpoint allows administrators to reload Cedar policies without restarting the server.
/// It should be protected with admin-only authorization.
///
/// # Requirements
///
/// - User must be authenticated
/// - User must have "admin" role
///
/// # Example
///
/// ```bash
/// POST /admin/cedar/reload
/// ```
///
/// Response:
/// ```json
/// {
///   "success": true,
///   "message": "Cedar policies reloaded successfully",
///   "timestamp": "2025-11-22T10:30:00Z"
/// }
/// ```
#[cfg(feature = "cedar")]
pub async fn reload_policies(
    State(cedar): State<CedarAuthz>,
    Authenticated(user): Authenticated<User>,
) -> Result<Response, StatusCode> {
    // Verify user is admin
    if !user.roles.contains(&"admin".to_string()) {
        tracing::warn!(
            user_id = user.id,
            email = %user.email,
            "Non-admin user attempted to reload Cedar policies"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Attempt to reload policies
    match cedar.reload_policies().await {
        Ok(()) => {
            let response = ReloadPolicyResponse {
                success: true,
                message: "Cedar policies reloaded successfully".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };

            tracing::info!(
                user_id = user.id,
                email = %user.email,
                "Cedar policies reloaded by admin"
            );

            Ok((StatusCode::OK, Json(response)).into_response())
        }
        Err(e) => {
            tracing::error!(
                error = ?e,
                user_id = user.id,
                "Failed to reload Cedar policies"
            );

            let response = ReloadPolicyResponse {
                success: false,
                message: format!("Failed to reload policies: {e}"),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };

            Ok((StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response())
        }
    }
}

/// Get Cedar policy status
///
/// Returns information about the current Cedar configuration.
/// This endpoint should be protected with admin-only authorization.
///
/// # Example
///
/// ```bash
/// GET /admin/cedar/status
/// ```
///
/// Response:
/// ```json
/// {
///   "enabled": true,
///   "policy_path": "policies/app.cedar",
///   "hot_reload": false,
///   "failure_mode": "closed",
///   "cache_enabled": true
/// }
/// ```
#[cfg(feature = "cedar")]
pub async fn policy_status(
    State(cedar): State<CedarAuthz>,
    Authenticated(user): Authenticated<User>,
) -> Result<Response, StatusCode> {
    // Verify user is admin
    if !user.roles.contains(&"admin".to_string()) {
        tracing::warn!(
            user_id = user.id,
            email = %user.email,
            "Non-admin user attempted to view Cedar policy status"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Get policy status from config
    let config = cedar.config();

    let response = PolicyStatusResponse {
        enabled: config.enabled,
        policy_path: config.policy_path.display().to_string(),
        hot_reload: config.hot_reload,
        failure_mode: format!("{:?}", config.failure_mode).to_lowercase(),
        cache_enabled: config.cache_enabled,
    };

    tracing::debug!(
        user_id = user.id,
        email = %user.email,
        "Cedar policy status requested by admin"
    );

    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
#[cfg(feature = "cedar")]
mod tests {
    use super::*;

    #[test]
    fn test_reload_response_serialization() {
        let response = ReloadPolicyResponse {
            success: true,
            message: "Policies reloaded".to_string(),
            timestamp: "2025-11-22T10:30:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("Policies reloaded"));
    }

    #[test]
    fn test_status_response_serialization() {
        let response = PolicyStatusResponse {
            enabled: true,
            policy_path: "policies/app.cedar".to_string(),
            hot_reload: false,
            failure_mode: "closed".to_string(),
            cache_enabled: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("policies/app.cedar"));
    }
}
