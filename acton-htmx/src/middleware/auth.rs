//! Authentication middleware for protecting routes
//!
//! This module provides middleware for requiring authentication on routes
//! and extractors for accessing the authenticated user.
//!
//! # Example
//!
//! ```rust,no_run
//! use acton_htmx::middleware::AuthMiddleware;
//! use acton_htmx::auth::Authenticated;
//! use axum::{Router, routing::get, middleware, extract::State};
//!
//! async fn protected_handler(
//!     Authenticated(user): Authenticated<acton_htmx::auth::User>,
//! ) -> String {
//!     format!("Hello, {}!", user.email)
//! }
//!
//! # async fn example() {
//! let app = Router::new()
//!     .route("/protected", get(protected_handler))
//!     .layer(middleware::from_fn(AuthMiddleware::handle));
//! # }
//! ```

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

/// Middleware that requires authentication for routes
///
/// If the user is not authenticated, they will be redirected to the login page.
/// For HTMX requests, returns a 401 Unauthorized status with HX-Redirect header.
#[derive(Clone)]
pub struct AuthMiddleware {
    #[allow(dead_code)] // TODO: Use this field when implementing custom login path
    login_path: String,
}

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self {
            login_path: "/login".to_string(),
        }
    }
}

impl AuthMiddleware {
    /// Create a new authentication middleware with default settings
    ///
    /// By default, redirects to `/login` for unauthenticated requests.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create authentication middleware with custom login path
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::middleware::AuthMiddleware;
    ///
    /// let middleware = AuthMiddleware::with_login_path("/auth/login");
    /// ```
    #[must_use]
    pub fn with_login_path(login_path: impl Into<String>) -> Self {
        Self {
            login_path: login_path.into(),
        }
    }

    /// Middleware handler that checks for authentication
    ///
    /// This is the actual middleware function that gets invoked for each request.
    pub async fn handle(
        request: Request,
        next: Next,
    ) -> Result<Response, AuthMiddlewareError> {
        // Check if user is authenticated by looking for user_id in session
        let (parts, body) = request.into_parts();

        // Get session from request extensions
        let session = parts.extensions.get::<crate::auth::Session>().cloned();

        let is_authenticated = session
            .as_ref()
            .and_then(|s| s.user_id())
            .is_some();

        if !is_authenticated {
            // Check if this is an HTMX request
            let is_htmx = parts.headers
                .get("HX-Request")
                .and_then(|v| v.to_str().ok())
                == Some("true");

            if is_htmx {
                // For HTMX requests, return 401 with HX-Redirect header
                return Err(AuthMiddlewareError::Unauthorized);
            } else {
                // For regular requests, redirect to login
                return Err(AuthMiddlewareError::RedirectToLogin);
            }
        }

        // User is authenticated, continue with the request
        let request = Request::from_parts(parts, body);
        Ok(next.run(request).await)
    }
}

/// Authentication middleware errors
#[derive(Debug)]
pub enum AuthMiddlewareError {
    /// User is not authenticated (HTMX request)
    Unauthorized,
    /// Redirect to login page (regular request)
    RedirectToLogin,
}

impl IntoResponse for AuthMiddlewareError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => {
                // Return 401 with HX-Redirect header for HTMX
                (
                    StatusCode::UNAUTHORIZED,
                    [("HX-Redirect", "/login")],
                    "Unauthorized",
                )
                    .into_response()
            }
            Self::RedirectToLogin => {
                // Regular HTTP redirect
                Redirect::to("/login").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Session, SessionData, SessionId};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn protected_handler() -> &'static str {
        "Protected content"
    }

    #[tokio::test]
    async fn test_unauthenticated_regular_request_redirects() {
        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(middleware::from_fn(AuthMiddleware::handle));

        let request = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should redirect to login
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/login"
        );
    }

    #[tokio::test]
    async fn test_unauthenticated_htmx_request_returns_401() {
        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(middleware::from_fn(AuthMiddleware::handle));

        let request = Request::builder()
            .uri("/protected")
            .header("HX-Request", "true")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should return 401 with HX-Redirect header
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("HX-Redirect").unwrap(),
            "/login"
        );
    }

    #[tokio::test]
    async fn test_authenticated_request_proceeds() {
        let app = Router::new()
            .route("/protected", get(protected_handler))
            .layer(middleware::from_fn(AuthMiddleware::handle));

        let mut request = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        // Add authenticated session to request extensions
        let session_id = SessionId::generate();
        let mut session_data = SessionData::new();
        session_data.user_id = Some(1);
        let session = Session::new(session_id, session_data);

        request.extensions_mut().insert(session);

        let response = app.oneshot(request).await.unwrap();

        // Should proceed to handler
        assert_eq!(response.status(), StatusCode::OK);
    }
}
