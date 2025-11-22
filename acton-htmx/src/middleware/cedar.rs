//! Cedar authorization middleware for acton-htmx
//!
//! This middleware integrates AWS Cedar policy-based authorization into acton-htmx.
//! It validates authorization requests against Cedar policies after session authentication.
//!
//! # Key Differences from acton-service
//!
//! - **Session-based auth**: Extracts principal from User (via session), not JWT claims
//! - **HTMX responses**: Returns HTMX partials for 403 errors instead of full pages
//! - **Template integration**: Provides helpers for authorization checks in templates
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use acton_htmx::middleware::cedar::CedarAuthz;
//! use acton_htmx::config::CedarConfig;
//!
//! let cedar = CedarAuthz::from_config(cedar_config).await?;
//!
//! let app = Router::new()
//!     .route("/posts/:id", put(update_post))
//!     .layer(axum::middleware::from_fn_with_state(cedar.clone(), CedarAuthz::middleware));
//! ```

#[cfg(feature = "cedar")]
use axum::{
    body::Body,
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

#[cfg(feature = "cedar")]
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request as CedarRequest,
};

#[cfg(feature = "cedar")]
use chrono::{Datelike, Timelike};

#[cfg(feature = "cedar")]
use serde_json::json;

#[cfg(feature = "cedar")]
use std::sync::Arc;

#[cfg(feature = "cedar")]
use tokio::sync::RwLock;

#[cfg(feature = "cedar")]
use crate::{auth::user::User, config::{CedarConfig, FailureMode}};

#[cfg(feature = "cedar")]
use thiserror::Error;

/// Cedar authorization errors
#[cfg(feature = "cedar")]
#[derive(Debug, Error)]
pub enum CedarError {
    /// Configuration error
    #[error("Cedar configuration error: {0}")]
    Config(String),

    /// Policy file error
    #[error("Policy file error: {0}")]
    PolicyFile(String),

    /// Policy parsing error
    #[error("Policy parsing error: {0}")]
    PolicyParsing(String),

    /// Authorization denied
    #[error("Authorization denied: {0}")]
    Forbidden(String),

    /// Unauthorized (not authenticated)
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Join error
    #[error("Task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

#[cfg(feature = "cedar")]
impl IntoResponse for CedarError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Forbidden(_) => (
                StatusCode::FORBIDDEN,
                "Access denied. You do not have permission to perform this action.",
            ),
            Self::Unauthorized(_) => (
                StatusCode::UNAUTHORIZED,
                "Authentication required. Please sign in.",
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal error occurred.",
            ),
        };

        tracing::error!(error = ?self, "Cedar authorization error");

        // For HTMX requests, return partial with HxRedirect to login
        // For regular requests, return status code with message
        (status, message).into_response()
    }
}

/// Builder for Cedar authorization middleware
///
/// Use this to construct a `CedarAuthz` instance with custom configuration.
///
/// # Examples
///
/// Simple case (defaults):
/// ```rust,ignore
/// let cedar = CedarAuthz::builder(cedar_config)
///     .build()
///     .await?;
/// ```
///
/// With custom path normalizer:
/// ```rust,ignore
/// let cedar = CedarAuthz::builder(cedar_config)
///     .with_path_normalizer(normalize_fn)
///     .build()
///     .await?;
/// ```
#[cfg(feature = "cedar")]
pub struct CedarAuthzBuilder {
    config: CedarConfig,
    path_normalizer: Option<fn(&str) -> String>,
}

#[cfg(feature = "cedar")]
impl CedarAuthzBuilder {
    /// Create a new builder with the given configuration
    #[must_use]
    pub fn new(config: CedarConfig) -> Self {
        Self {
            config,
            path_normalizer: None,
        }
    }

    /// Set a custom path normalizer
    ///
    /// By default, Cedar uses a generic path normalizer that replaces UUIDs and numeric IDs
    /// with `{id}` placeholders. Use this method to provide custom normalization logic for
    /// your application's specific path patterns.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn custom_normalizer(path: &str) -> String {
    ///     // Example: /articles/my-article-slug-123 -> /articles/{slug}
    ///     path.replace("/articles/", "/articles/{slug}/")
    /// }
    ///
    /// let cedar = CedarAuthz::builder(cedar_config)
    ///     .with_path_normalizer(custom_normalizer)
    ///     .build()
    ///     .await?;
    /// ```
    #[must_use]
    pub fn with_path_normalizer(mut self, normalizer: fn(&str) -> String) -> Self {
        self.path_normalizer = Some(normalizer);
        self
    }

    /// Build the CedarAuthz instance (async)
    ///
    /// This loads the Cedar policies from the configured file path.
    pub async fn build(self) -> Result<CedarAuthz, CedarError> {
        // Load policies from file (using spawn_blocking for file I/O)
        let path = self.config.policy_path.clone();
        let policies = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path))
            .await??;

        let policy_set: PolicySet = policies
            .parse()
            .map_err(|e| CedarError::PolicyParsing(format!("Failed to parse Cedar policies: {e}")))?;

        Ok(CedarAuthz {
            authorizer: Arc::new(Authorizer::new()),
            policy_set: Arc::new(RwLock::new(policy_set)),
            config: Arc::new(self.config),
            path_normalizer: self.path_normalizer,
        })
    }
}

/// Cedar authorization middleware state
#[cfg(feature = "cedar")]
#[derive(Clone)]
pub struct CedarAuthz {
    /// Cedar authorizer (stateless evaluator)
    authorizer: Arc<Authorizer>,

    /// Cedar policy set (policies loaded from file)
    policy_set: Arc<RwLock<PolicySet>>,

    /// Configuration
    config: Arc<CedarConfig>,

    /// Custom path normalizer (optional, defaults to normalize_path_generic)
    path_normalizer: Option<fn(&str) -> String>,
}

#[cfg(feature = "cedar")]
impl CedarAuthz {
    /// Create a builder for CedarAuthz
    ///
    /// This is the recommended way to construct CedarAuthz instances.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let cedar = CedarAuthz::builder(cedar_config)
    ///     .with_path_normalizer(normalize_fn)
    ///     .build()
    ///     .await?;
    /// ```
    #[must_use]
    pub fn builder(config: CedarConfig) -> CedarAuthzBuilder {
        CedarAuthzBuilder::new(config)
    }

    /// Create CedarAuthz from config with defaults (convenience method)
    ///
    /// This is a shortcut for `CedarAuthz::builder(config).build().await`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let cedar = CedarAuthz::from_config(cedar_config).await?;
    /// ```
    pub async fn from_config(config: CedarConfig) -> Result<Self, CedarError> {
        Self::builder(config).build().await
    }

    /// Middleware function to evaluate Cedar policies
    ///
    /// This middleware:
    /// 1. Skips if Cedar is disabled
    /// 2. Skips health/ready endpoints
    /// 3. Extracts User from session (inserted by session middleware)
    /// 4. Builds Cedar principal, action, context
    /// 5. Evaluates policies
    /// 6. Returns 403 if denied, continues if allowed
    pub async fn middleware(
        State(authz): State<Self>,
        request: Request<Body>,
        next: Next,
    ) -> Result<Response, CedarError> {
        // Skip if Cedar is disabled
        if !authz.config.enabled {
            return Ok(next.run(request).await);
        }

        // Skip authorization for health and readiness endpoints
        let path = request.uri().path();
        if path == "/health" || path == "/ready" {
            return Ok(next.run(request).await);
        }

        // Extract User from request extensions (inserted by session middleware)
        let user = request.extensions().get::<User>().ok_or_else(|| {
            CedarError::Unauthorized(
                "Missing user session. Ensure session middleware runs before Cedar middleware."
                    .to_string(),
            )
        })?;

        // Extract request information
        let method = request.method().clone();

        // Build Cedar authorization request
        let principal = build_principal(user)?;
        let action = build_action_http(&method, &request, authz.path_normalizer)?;
        let context = build_context_http(request.headers(), user)?;

        // Build resource (generic default for now)
        let resource = build_resource()?;

        let cedar_request = CedarRequest::new(
            principal.clone(),
            action.clone(),
            resource.clone(),
            context,
            None, // Schema: None (optional)
        )
        .map_err(|e| CedarError::Internal(format!("Failed to build Cedar request: {e}")))?;

        // Evaluate policies
        let entities = build_entities(user)?;
        let response = {
            let policy_set = authz.policy_set.read().await;
            authz
                .authorizer
                .is_authorized(&cedar_request, &policy_set, &entities)
        };

        // Handle decision
        match response.decision() {
            Decision::Allow => {
                // Allow request to proceed
                Ok(next.run(request).await)
            }
            Decision::Deny => {
                tracing::warn!(
                    principal = ?principal,
                    action = ?action,
                    user_id = user.id,
                    "Cedar policy denied request"
                );

                if authz.config.failure_mode == FailureMode::Open {
                    tracing::warn!("Cedar policy denied but failure_mode=Open, allowing request");
                    Ok(next.run(request).await)
                } else {
                    Err(CedarError::Forbidden(
                        "Access denied by policy".to_string(),
                    ))
                }
            }
        }
    }

    /// Reload policies from file (for hot-reload support)
    pub async fn reload_policies(&self) -> Result<(), CedarError> {
        let path = self.config.policy_path.clone();
        let policies = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path)).await??;

        let new_policy_set: PolicySet = policies
            .parse()
            .map_err(|e| CedarError::PolicyParsing(format!("Failed to parse policies: {e}")))?;

        {
            let mut policy_set = self.policy_set.write().await;
            *policy_set = new_policy_set;
        }

        tracing::info!(
            "Cedar policies reloaded from {}",
            self.config.policy_path.display()
        );
        Ok(())
    }
}

/// Build Cedar resource entity
///
/// Returns a generic default resource for authorization checks.
/// Most authorization policies can be implemented using just the principal (user/roles)
/// and action (HTTP method + path), without needing typed resources.
///
/// For applications that need typed resources with attributes (e.g., Post::"123"
/// with author_id for ownership checks), this can be extended in the future.
#[cfg(feature = "cedar")]
fn build_resource() -> Result<EntityUid, CedarError> {
    r#"Resource::"default""#
        .parse()
        .map_err(|e| CedarError::Internal(format!("Failed to parse resource: {e}")))
}

/// Build Cedar principal from User (session-based auth)
///
/// Extracts principal from authenticated User, not JWT claims.
/// Principal format: User::"123" (user ID)
#[cfg(feature = "cedar")]
fn build_principal(user: &User) -> Result<EntityUid, CedarError> {
    let principal_str = format!(r#"User::"{}""#, user.id);

    let principal: EntityUid = principal_str
        .parse()
        .map_err(|e| CedarError::Internal(format!("Invalid principal: {e}")))?;

    Ok(principal)
}

/// Build Cedar action from HTTP method and request
///
/// Uses Axum's MatchedPath to get the route pattern (most accurate).
/// Falls back to path normalization (custom or default) if MatchedPath is not available.
#[cfg(feature = "cedar")]
fn build_action_http(
    method: &Method,
    request: &Request<Body>,
    path_normalizer: Option<fn(&str) -> String>,
) -> Result<EntityUid, CedarError> {
    // Try to get Axum's matched path first (e.g., "/posts/:id")
    let normalized_path = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(
            || {
                // Use custom normalizer if provided, otherwise use default
                path_normalizer.map_or_else(
                    || normalize_path_generic(request.uri().path()),
                    |normalizer| normalizer(request.uri().path()),
                )
            },
            |matched| matched.as_str().to_string(),
        );

    let action_str = format!(r#"Action::"{method} {normalized_path}""#);

    let action: EntityUid = action_str
        .parse()
        .map_err(|e| CedarError::Internal(format!("Invalid action: {e}")))?;

    // Debug logging to see what action was generated
    tracing::debug!(
        method = %method,
        path = %request.uri().path(),
        normalized = %normalized_path,
        action = %action,
        "Built Cedar action"
    );

    Ok(action)
}

/// Normalize path by replacing common ID patterns with placeholders
///
/// This is a generic fallback used when Axum's MatchedPath is not available.
/// It handles the most common ID patterns:
/// - UUIDs: replaced with {id}
/// - Numeric IDs: replaced with {id}
#[cfg(feature = "cedar")]
fn normalize_path_generic(path: &str) -> String {
    // Replace UUIDs with {id}
    let uuid_pattern =
        regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("Invalid regex");
    let path = uuid_pattern.replace_all(path, "{id}");

    // Replace numeric IDs at end of path segments
    let numeric_pattern = regex::Regex::new(r"/(\d+)(?:/|$)").expect("Invalid regex");
    let path = numeric_pattern.replace_all(&path, "/{id}");

    path.to_string()
}

/// Build Cedar context from HTTP headers and user
#[cfg(feature = "cedar")]
fn build_context_http(headers: &HeaderMap, user: &User) -> Result<Context, CedarError> {
    let mut context_map = serde_json::Map::new();

    // Add user roles
    context_map.insert("roles".to_string(), json!(user.roles));

    // Add user permissions
    context_map.insert("permissions".to_string(), json!(user.permissions));

    // Add user email
    context_map.insert("email".to_string(), json!(user.email.as_str()));

    // Add user ID
    context_map.insert("user_id".to_string(), json!(user.id));

    // Add email verification status
    context_map.insert("verified".to_string(), json!(user.email_verified));

    // Add timestamp
    let now = chrono::Utc::now();
    context_map.insert(
        "timestamp".to_string(),
        json!({
            "unix": now.timestamp(),
            "hour": now.hour(),
            "dayOfWeek": now.weekday().to_string(),
        }),
    );

    // Add IP address (from X-Forwarded-For or X-Real-IP)
    if let Some(ip) = extract_client_ip(headers) {
        context_map.insert("ip".to_string(), json!(ip));
    }

    // Add request ID if present
    if let Some(request_id) = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
    {
        context_map.insert("requestId".to_string(), json!(request_id));
    }

    // Add user-agent if present
    if let Some(user_agent) = headers.get("user-agent").and_then(|v| v.to_str().ok()) {
        context_map.insert("userAgent".to_string(), json!(user_agent));
    }

    Context::from_json_value(serde_json::Value::Object(context_map), None)
        .map_err(|e| CedarError::Internal(format!("Failed to build context: {e}")))
}

/// Extract client IP from headers
#[cfg(feature = "cedar")]
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Try X-Forwarded-For header first (for proxied requests)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take first IP in comma-separated list
            return xff_str.split(',').next().map(|s| s.trim().to_string());
        }
    }

    // Try X-Real-IP header
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(xri_str) = xri.to_str() {
            return Some(xri_str.to_string());
        }
    }

    None
}

/// Build entity hierarchy from user
///
/// Creates the principal entity (User) with roles and permissions.
#[cfg(feature = "cedar")]
fn build_entities(user: &User) -> Result<Entities, CedarError> {
    use serde_json::Value;

    // Create principal entity (User) with attributes
    let entity = json!({
        "uid": {
            "type": "User",
            "id": user.id.to_string()
        },
        "attrs": {
            "email": user.email.as_str(),
            "roles": user.roles.clone(),
            "permissions": user.permissions.clone(),
            "id": user.id,
            "verified": user.email_verified,
        },
        "parents": []
    });

    Entities::from_json_value(Value::Array(vec![entity]), None)
        .map_err(|e| CedarError::Internal(format!("Failed to build entities: {e}")))
}

#[cfg(test)]
#[cfg(feature = "cedar")]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_generic() {
        assert_eq!(
            normalize_path_generic("/api/v1/posts/123"),
            "/api/v1/posts/{id}"
        );
        assert_eq!(
            normalize_path_generic("/api/v1/posts/550e8400-e29b-41d4-a716-446655440000"),
            "/api/v1/posts/{id}"
        );
        assert_eq!(normalize_path_generic("/api/v1/posts"), "/api/v1/posts");
    }
}
