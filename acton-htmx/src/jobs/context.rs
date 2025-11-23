//! Job execution context with access to application services.
//!
//! The `JobContext` provides jobs with access to shared services like email senders,
//! database pools, and file storage. This follows the acton-reactive pattern of storing
//! context in the agent's model field and passing it to jobs at execution time.
//!
//! # Architecture
//!
//! Based on acton-reactive patterns:
//! - JobContext stored in `JobAgent.model` as `Arc<JobContext>`
//! - Cheap Arc clones passed to job execution
//! - Jobs remain serializable (context not stored in job data)
//! - Services wrapped in Arc for thread-safe sharing
//!
//! # Example
//!
//! ```rust
//! use acton_htmx::jobs::{Job, JobContext, JobResult};
//! use async_trait::async_trait;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub struct SendEmailJob {
//!     to: String,
//!     subject: String,
//!     body: String,
//! }
//!
//! #[async_trait]
//! impl Job for SendEmailJob {
//!     type Result = ();
//!
//!     async fn execute(&self, ctx: &JobContext) -> JobResult<Self::Result> {
//!         // Access email sender from context
//!         if let Some(email_sender) = ctx.email_sender() {
//!             let email = acton_htmx::email::Email::new()
//!                 .to(&self.to)
//!                 .subject(&self.subject)
//!                 .text(&self.body);
//!
//!             email_sender.send(email).await
//!                 .map_err(|e| acton_htmx::jobs::JobError::ExecutionFailed(e.to_string()))?;
//!         }
//!         Ok(())
//!     }
//! }
//! ```

use crate::email::EmailSender;
use crate::storage::FileStorage;
use sqlx::PgPool;
use std::sync::Arc;

#[cfg(feature = "redis")]
use deadpool_redis::Pool as RedisPool;

/// Context provided to jobs during execution.
///
/// Contains references to shared application services that jobs may need:
/// - Email sender for sending transactional emails
/// - Database pool for database queries
/// - File storage for file operations
/// - Redis pool for caching (optional, feature-gated)
///
/// All fields are optional to support different deployment scenarios.
/// Jobs should gracefully handle missing services.
#[derive(Clone)]
pub struct JobContext {
    /// Email sender for sending emails from jobs
    email_sender: Option<Arc<dyn EmailSender>>,

    /// Database connection pool for queries
    database_pool: Option<Arc<PgPool>>,

    /// File storage backend for file operations
    file_storage: Option<Arc<dyn FileStorage>>,

    /// Redis connection pool (optional, for caching and distributed operations)
    #[cfg(feature = "redis")]
    redis_pool: Option<RedisPool>,
}

impl JobContext {
    /// Create a new job context with all services disabled.
    ///
    /// Use the builder methods to add services as needed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            email_sender: None,
            database_pool: None,
            file_storage: None,
            #[cfg(feature = "redis")]
            redis_pool: None,
        }
    }

    /// Set the email sender for this context.
    #[must_use]
    pub fn with_email_sender(mut self, sender: Arc<dyn EmailSender>) -> Self {
        self.email_sender = Some(sender);
        self
    }

    /// Set the database pool for this context.
    #[must_use]
    pub fn with_database_pool(mut self, pool: Arc<PgPool>) -> Self {
        self.database_pool = Some(pool);
        self
    }

    /// Set the file storage backend for this context.
    #[must_use]
    pub fn with_file_storage(mut self, storage: Arc<dyn FileStorage>) -> Self {
        self.file_storage = Some(storage);
        self
    }

    /// Set the Redis pool for this context.
    #[cfg(feature = "redis")]
    #[must_use]
    pub fn with_redis_pool(mut self, pool: RedisPool) -> Self {
        self.redis_pool = Some(pool);
        self
    }

    /// Get the email sender if available.
    #[must_use]
    pub fn email_sender(&self) -> Option<&Arc<dyn EmailSender>> {
        self.email_sender.as_ref()
    }

    /// Get the database pool if available.
    #[must_use]
    pub const fn database_pool(&self) -> Option<&Arc<PgPool>> {
        self.database_pool.as_ref()
    }

    /// Get the file storage backend if available.
    #[must_use]
    pub fn file_storage(&self) -> Option<&Arc<dyn FileStorage>> {
        self.file_storage.as_ref()
    }

    /// Get the Redis pool if available.
    #[cfg(feature = "redis")]
    #[must_use]
    pub const fn redis_pool(&self) -> Option<&RedisPool> {
        self.redis_pool.as_ref()
    }
}

impl Default for JobContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for JobContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("JobContext");
        debug_struct
            .field("email_sender", &self.email_sender.is_some())
            .field("database_pool", &self.database_pool.is_some())
            .field("file_storage", &self.file_storage.is_some());

        #[cfg(feature = "redis")]
        debug_struct.field("redis_pool", &self.redis_pool.is_some());

        debug_struct.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_context_new() {
        let ctx = JobContext::new();
        assert!(ctx.email_sender().is_none());
        assert!(ctx.database_pool().is_none());
        assert!(ctx.file_storage().is_none());
    }

    #[test]
    fn test_job_context_default() {
        let ctx = JobContext::default();
        assert!(ctx.email_sender().is_none());
        assert!(ctx.database_pool().is_none());
        assert!(ctx.file_storage().is_none());
    }

    #[test]
    fn test_job_context_debug() {
        let ctx = JobContext::new();
        let debug_output = format!("{ctx:?}");
        assert!(debug_output.contains("JobContext"));
        assert!(debug_output.contains("email_sender"));
    }
}
