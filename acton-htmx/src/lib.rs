//! acton-htmx: Opinionated Rust web framework for HTMX applications
//!
//! This framework builds on battle-tested components from the Acton ecosystem:
//! - **acton-service**: Configuration, observability, middleware, connection pools
//! - **acton-reactive**: Actor-based background jobs, sessions, and real-time features
//!
//! # Design Principles
//!
//! 1. **Convention Over Configuration**: Smart defaults everywhere
//! 2. **Security by Default**: CSRF, secure sessions, security headers enabled
//! 3. **HTMX-First Architecture**: Response helpers and patterns for hypermedia
//! 4. **Type Safety Without Ceremony**: Compile-time guarantees via Rust's type system
//! 5. **Idiomatic Excellence**: Generated code exemplifies Rust best practices
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use acton_htmx::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialize application state
//!     let state = ActonHtmxState::new().await?;
//!
//!     // Build router with HTMX handlers
//!     let app = axum::Router::new()
//!         .route("/", axum::routing::get(index))
//!         .with_state(state);
//!
//!     // Start server
//!     let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
//!     axum::serve(listener, app).await?;
//!
//!     Ok(())
//! }
//!
//! async fn index() -> &'static str {
//!     "Hello, HTMX!"
//! }
//! ```
//!
//! # Features
//!
//! - `postgres` - PostgreSQL database support (default)
//! - `sqlite` - SQLite database support
//! - `mysql` - MySQL database support
//! - `redis` - Redis session and cache support (default)
//! - `otel-metrics` - OpenTelemetry metrics collection
//!
//! # Architecture
//!
//! See the [architecture overview](../../../.claude/architecture-overview.md) for details.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]
// Allow specific lints where justified
#![allow(clippy::module_name_repetitions)] // Clear naming is more important than brevity
#![allow(clippy::missing_errors_doc)] // TODO: Add comprehensive error docs before 1.0

// Public modules (exported in public API)
pub mod auth;
pub mod config;
pub mod error;
pub mod extractors;
pub mod forms;
pub mod htmx;
pub mod state;
pub mod template;

// Internal modules (not re-exported, implementation details)
mod agents;
mod cache;
mod database;
mod health;
mod middleware;
mod observability;
mod security;

#[cfg(test)]
pub mod testing;

/// Convenience re-exports for common types and traits
pub mod prelude {
    //! Commonly used types and traits for building HTMX applications
    //!
    //! # Examples
    //!
    //! ```rust
    //! use acton_htmx::prelude::*;
    //! ```

    // HTMX response types
    pub use crate::htmx::{
        HxRedirect, HxRequest, HxResponse, HxReswap, HxRetarget, HxSwapOob, HxTrigger,
    };

    // Template traits
    pub use crate::template::{HxTemplate, TemplateRegistry};

    // Form handling
    pub use crate::forms::FormBuilder;

    // Authentication extractors
    pub use crate::auth::{Authenticated, OptionalAuth, Session};

    // Extractors
    pub use crate::extractors::{FlashExtractor, SessionExtractor};

    // Error types
    pub use crate::error::ActonHtmxError;

    // Application state
    pub use crate::state::ActonHtmxState;

    // Re-export key dependencies
    pub use askama;
    pub use axum;
    pub use validator;

    // Convenience for JSON responses
    pub use serde_json::json;

    // Macros from acton-htmx-macros crate
    // TODO: Implement these macros
    // pub use acton_htmx_macros::{AskamaForm, Policy, ModelBinding};
}
