//! Middleware layers for acton-htmx
//!
//! Provides middleware for:
//! - Session management (cookie-based sessions with agent backend)
//! - Authentication (route protection)
//! - CSRF protection (token-based CSRF validation)
//! - Security headers (TODO)
//! - Rate limiting (TODO)

pub mod auth;
pub mod csrf;
pub mod session;

// Re-exports are intentionally public even if not used within the crate itself
#[allow(unused_imports)]
pub use auth::{AuthMiddleware, AuthMiddlewareError};
#[allow(unused_imports)]
pub use csrf::{
    CsrfConfig, CsrfLayer, CsrfMiddleware, CSRF_FORM_FIELD, CSRF_HEADER_NAME,
};
#[allow(unused_imports)]
pub use session::{SameSite, SessionConfig, SessionLayer, SessionMiddleware, SESSION_COOKIE_NAME};
