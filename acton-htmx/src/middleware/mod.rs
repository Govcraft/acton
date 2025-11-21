//! Middleware layers for acton-htmx
//!
//! Provides middleware for:
//! - Session management (cookie-based sessions with agent backend)
//! - CSRF protection (TODO)
//! - Security headers (TODO)
//! - Rate limiting (TODO)

pub mod session;

// Re-exports are intentionally public even if not used within the crate itself
#[allow(unused_imports)]
pub use session::{SameSite, SessionConfig, SessionLayer, SessionMiddleware, SESSION_COOKIE_NAME};
