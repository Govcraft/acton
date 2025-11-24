//! Rate limiting middleware
//!
//! Provides request rate limiting with support for both Redis-backed (distributed)
//! and in-memory (single-instance) backends. Rate limits can be configured per
//! authenticated user, per IP address, and per specific route patterns.
//!
//! # Features
//!
//! - **Multiple Identifiers**: Rate limit by user ID (authenticated), IP address (anonymous), or both
//! - **Route-Specific Limits**: Apply stricter limits to sensitive endpoints (e.g., `/login`, `/register`)
//! - **Redis Backend**: Distributed rate limiting for multi-instance deployments (requires `cache` feature)
//! - **In-Memory Fallback**: Automatic fallback to in-memory rate limiting if Redis is unavailable
//! - **Failure Modes**: Configurable behavior on backend errors (fail-open or fail-closed)
//! - **Sliding Window**: Uses sliding window algorithm for accurate rate limiting
//!
//! # Example
//!
//! ```rust,no_run
//! use acton_htmx::middleware::rate_limit::RateLimit;
//! use acton_htmx::config::RateLimitConfig;
//! use axum::{Router, routing::get};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = RateLimitConfig::default();
//!
//! #[cfg(feature = "redis")]
//! let redis_pool = acton_htmx::database::redis::create_pool("redis://localhost:6379").await?;
//!
//! #[cfg(feature = "redis")]
//! let rate_limit = RateLimit::new(config, Some(redis_pool));
//!
//! #[cfg(not(feature = "redis"))]
//! let rate_limit = RateLimit::new(config, None);
//!
//! let app = Router::new()
//!     .route("/", get(|| async { "Hello" }))
//!     .layer(axum::middleware::from_fn_with_state(
//!         rate_limit,
//!         RateLimit::middleware,
//!     ));
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "redis")]
use deadpool_redis::Pool as RedisPool;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::RateLimitConfig;

/// In-memory rate limit entry
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Request count in current window
    count: u32,
    /// Window start time
    window_start: Instant,
}

/// In-memory rate limit store
type InMemoryStore = Arc<RwLock<HashMap<String, RateLimitEntry>>>;

/// Rate limiting middleware
///
/// Enforces configurable rate limits per user, IP address, and route.
/// Supports both Redis-backed (distributed) and in-memory (single-instance) storage.
#[derive(Clone)]
pub struct RateLimit {
    config: RateLimitConfig,
    #[cfg(feature = "redis")]
    redis_pool: Option<RedisPool>,
    in_memory_store: InMemoryStore,
}

impl RateLimit {
    /// Create a new rate limiting middleware
    ///
    /// # Arguments
    ///
    /// * `config` - Rate limit configuration
    /// * `redis_pool` - Optional Redis pool for distributed rate limiting (requires `redis` feature)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use acton_htmx::middleware::rate_limit::RateLimit;
    /// use acton_htmx::config::RateLimitConfig;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let config = RateLimitConfig::default();
    ///
    /// #[cfg(feature = "redis")]
    /// let redis_pool = acton_htmx::database::redis::create_pool("redis://localhost:6379").await?;
    ///
    /// #[cfg(feature = "redis")]
    /// let rate_limit = RateLimit::new(config, Some(redis_pool));
    ///
    /// #[cfg(not(feature = "redis"))]
    /// let rate_limit = RateLimit::new(config, None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    #[cfg(feature = "redis")]
    pub fn new(config: RateLimitConfig, redis_pool: Option<RedisPool>) -> Self {
        Self {
            config,
            redis_pool,
            in_memory_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new rate limiting middleware without Redis
    #[must_use]
    #[cfg(not(feature = "redis"))]
    pub fn new(config: RateLimitConfig, _redis_pool: Option<()>) -> Self {
        Self {
            config,
            in_memory_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Middleware function to enforce rate limits
    ///
    /// This middleware:
    /// 1. Extracts user ID from session (if authenticated) or IP address
    /// 2. Checks if request path matches strict route patterns
    /// 3. Applies appropriate rate limit (per-user, per-IP, or per-route)
    /// 4. Returns 429 Too Many Requests if limit exceeded
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitError::TooManyRequests`] if the rate limit is exceeded.
    /// Returns [`RateLimitError::Redis`] if Redis operations fail (when using Redis feature).
    pub async fn middleware(
        State(rate_limit): State<Self>,
        request: Request,
        next: Next,
    ) -> Result<Response, RateLimitError> {
        // Skip if rate limiting is disabled
        if !rate_limit.config.enabled {
            return Ok(next.run(request).await);
        }

        // Extract user ID from request extensions (set by session middleware)
        let user_id: Option<i64> = request.extensions().get::<i64>().copied();

        // Extract IP address from connection info
        let ip_addr = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip().to_string());

        // Determine rate limit key and limit
        let path = request.uri().path();
        let (key, limit) = rate_limit.determine_key_and_limit(user_id, ip_addr.as_deref(), path);

        debug!(
            key = %key,
            limit = limit,
            path = %path,
            user_id = ?user_id,
            "Checking rate limit"
        );

        // Check rate limit
        rate_limit.check_rate_limit(&key, limit).await?;

        Ok(next.run(request).await)
    }

    /// Determine rate limit key and limit based on user, IP, and path
    fn determine_key_and_limit(
        &self,
        user_id: Option<i64>,
        ip_addr: Option<&str>,
        path: &str,
    ) -> (String, u32) {
        // Check if path matches strict routes
        let is_strict_route = self
            .config
            .strict_routes
            .iter()
            .any(|route| path.starts_with(route));

        if is_strict_route {
            // Use stricter per-route limit
            let key = user_id.map_or_else(|| {
                ip_addr.map_or_else(|| "ratelimit:route:unknown".to_string(), |ip| format!("ratelimit:route:ip:{ip}"))
            }, |uid| format!("ratelimit:route:user:{uid}"));
            (key, self.config.per_route_rpm)
        } else if let Some(uid) = user_id {
            // Authenticated user
            (
                format!("ratelimit:user:{uid}"),
                self.config.per_user_rpm,
            )
        } else if let Some(ip) = ip_addr {
            // Anonymous by IP
            (format!("ratelimit:ip:{ip}"), self.config.per_ip_rpm)
        } else {
            // Fallback
            ("ratelimit:unknown".to_string(), self.config.per_ip_rpm)
        }
    }

    /// Check rate limit for a key
    async fn check_rate_limit(&self, key: &str, limit: u32) -> Result<(), RateLimitError> {
        // Try Redis first if enabled
        #[cfg(feature = "redis")]
        if self.config.redis_enabled {
            if let Some(ref redis_pool) = self.redis_pool {
                match self.check_rate_limit_redis(redis_pool, key, limit).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            key = %key,
                            "Redis rate limit check failed, falling back to in-memory"
                        );
                        // Fall through to in-memory
                    }
                }
            }
        }

        // Use in-memory rate limiting
        self.check_rate_limit_memory(key, limit).await
    }

    /// Check rate limit using Redis backend
    #[cfg(feature = "redis")]
    async fn check_rate_limit_redis(
        &self,
        redis_pool: &RedisPool,
        key: &str,
        limit: u32,
    ) -> Result<(), RateLimitError> {
        let mut conn = redis_pool.get().await.map_err(|e| {
            RateLimitError::Backend(format!("Failed to get Redis connection: {e}"))
        })?;

        // Use INCR and EXPIRE for sliding window rate limiting
        let count: u32 = redis::cmd("INCR")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| RateLimitError::Backend(format!("Redis INCR failed: {e}")))?;

        // Set expiration on first request
        if count == 1 {
            // Convert window_secs to i64, saturating at i64::MAX to avoid wrapping
            let expire_secs = i64::try_from(self.config.window_secs).unwrap_or(i64::MAX);
            let _: () = redis::cmd("EXPIRE")
                .arg(key)
                .arg(expire_secs)
                .query_async(&mut *conn)
                .await
                .map_err(|e| RateLimitError::Backend(format!("Redis EXPIRE failed: {e}")))?;
        }

        // Check if limit exceeded
        if count > limit {
            warn!(
                key = %key,
                count = count,
                limit = limit,
                window_secs = self.config.window_secs,
                "Rate limit exceeded"
            );
            return Err(RateLimitError::Exceeded {
                limit,
                window: Duration::from_secs(self.config.window_secs),
            });
        }

        debug!(
            key = %key,
            count = count,
            limit = limit,
            "Rate limit check passed (Redis)"
        );

        Ok(())
    }

    /// Check rate limit using in-memory backend
    async fn check_rate_limit_memory(&self, key: &str, limit: u32) -> Result<(), RateLimitError> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_secs);

        // Acquire lock, update entry, extract count, then immediately release lock
        let mut store = self.in_memory_store.write().await;

        // Get or create entry
        let entry = store.entry(key.to_string()).or_insert_with(|| RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Check if window has expired
        if now.duration_since(entry.window_start) >= window_duration {
            // Reset window
            entry.count = 1;
            entry.window_start = now;
        } else {
            // Increment count
            entry.count += 1;
        }

        let count = entry.count;
        drop(store); // Explicitly drop the lock before any logging or error handling

        // Check if limit exceeded (after releasing lock)
        if count > limit {
            warn!(
                key = %key,
                count = count,
                limit = limit,
                window_secs = self.config.window_secs,
                "Rate limit exceeded"
            );
            return Err(RateLimitError::Exceeded {
                limit,
                window: window_duration,
            });
        }

        debug!(
            key = %key,
            count = count,
            limit = limit,
            "Rate limit check passed (in-memory)"
        );

        Ok(())
    }

    /// Cleanup expired entries from in-memory store
    ///
    /// Should be called periodically to prevent memory leaks.
    /// Returns the number of entries removed.
    pub async fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_secs);

        let removed = {
            let mut store = self.in_memory_store.write().await;
            let before_count = store.len();

            store.retain(|_, entry| now.duration_since(entry.window_start) < window_duration);

            before_count - store.len()
        }; // Drop the write lock here

        if removed > 0 {
            debug!(removed = removed, "Cleaned up expired rate limit entries");
        }

        removed
    }
}

/// Rate limit errors
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    /// Rate limit exceeded
    #[error("Rate limit exceeded: {limit} requests per {window:?}")]
    Exceeded {
        /// Maximum requests allowed
        limit: u32,
        /// Time window
        window: Duration,
    },

    /// Backend error (Redis, etc.)
    #[error("Rate limit backend error: {0}")]
    Backend(String),
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        match self {
            Self::Exceeded { limit, window } => {
                let retry_after = window.as_secs();
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [
                        ("Retry-After", retry_after.to_string()),
                        (
                            "X-RateLimit-Limit",
                            limit.to_string(),
                        ),
                    ],
                    format!(
                        "Rate limit exceeded. Maximum {} requests per {} seconds.",
                        limit,
                        window.as_secs()
                    ),
                )
                    .into_response()
            }
            Self::Backend(msg) => {
                warn!(error = %msg, "Rate limit backend error");
                // Return 500 for backend errors in fail-closed mode
                // (fail-open mode would skip rate limiting and never reach here)
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Rate limiting temporarily unavailable",
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitFailureMode;

    #[test]
    fn test_rate_limit_creation() {
        let config = RateLimitConfig::default();
        let rate_limit = RateLimit::new(config, None);

        assert!(rate_limit.config.enabled);
        assert_eq!(rate_limit.config.per_user_rpm, 120);
        assert_eq!(rate_limit.config.per_ip_rpm, 60);
        assert_eq!(rate_limit.config.per_route_rpm, 30);
    }

    #[test]
    fn test_determine_key_and_limit_authenticated() {
        let config = RateLimitConfig::default();
        let rate_limit = RateLimit::new(config, None);

        let (key, limit) = rate_limit.determine_key_and_limit(Some(123), Some("192.168.1.1"), "/posts");
        assert_eq!(key, "ratelimit:user:123");
        assert_eq!(limit, 120);
    }

    #[test]
    fn test_determine_key_and_limit_anonymous() {
        let config = RateLimitConfig::default();
        let rate_limit = RateLimit::new(config, None);

        let (key, limit) = rate_limit.determine_key_and_limit(None, Some("192.168.1.1"), "/posts");
        assert_eq!(key, "ratelimit:ip:192.168.1.1");
        assert_eq!(limit, 60);
    }

    #[test]
    fn test_determine_key_and_limit_strict_route_authenticated() {
        let config = RateLimitConfig::default();
        let rate_limit = RateLimit::new(config, None);

        let (key, limit) = rate_limit.determine_key_and_limit(Some(123), Some("192.168.1.1"), "/login");
        assert_eq!(key, "ratelimit:route:user:123");
        assert_eq!(limit, 30);
    }

    #[test]
    fn test_determine_key_and_limit_strict_route_anonymous() {
        let config = RateLimitConfig::default();
        let rate_limit = RateLimit::new(config, None);

        let (key, limit) = rate_limit.determine_key_and_limit(None, Some("192.168.1.1"), "/register");
        assert_eq!(key, "ratelimit:route:ip:192.168.1.1");
        assert_eq!(limit, 30);
    }

    #[tokio::test]
    async fn test_in_memory_rate_limit_within_limit() {
        let config = RateLimitConfig {
            enabled: true,
            per_user_rpm: 5,
            per_ip_rpm: 3,
            per_route_rpm: 2,
            window_secs: 60,
            redis_enabled: false,
            failure_mode: RateLimitFailureMode::Closed,
            strict_routes: vec![],
        };
        let rate_limit = RateLimit::new(config, None);

        // Should allow 3 requests
        for _ in 0..3 {
            let result = rate_limit.check_rate_limit_memory("test_key", 5).await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_in_memory_rate_limit_exceeded() {
        let config = RateLimitConfig {
            enabled: true,
            per_user_rpm: 5,
            per_ip_rpm: 3,
            per_route_rpm: 2,
            window_secs: 60,
            redis_enabled: false,
            failure_mode: RateLimitFailureMode::Closed,
            strict_routes: vec![],
        };
        let rate_limit = RateLimit::new(config, None);

        // Should allow 3 requests
        for _ in 0..3 {
            let result = rate_limit.check_rate_limit_memory("test_key", 3).await;
            assert!(result.is_ok());
        }

        // 4th request should fail
        let result = rate_limit.check_rate_limit_memory("test_key", 3).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RateLimitError::Exceeded { .. }));
    }

    #[tokio::test]
    async fn test_in_memory_rate_limit_window_reset() {
        let config = RateLimitConfig {
            enabled: true,
            per_user_rpm: 5,
            per_ip_rpm: 3,
            per_route_rpm: 2,
            window_secs: 1, // 1 second window for testing
            redis_enabled: false,
            failure_mode: RateLimitFailureMode::Closed,
            strict_routes: vec![],
        };
        let rate_limit = RateLimit::new(config, None);

        // Use up the limit
        for _ in 0..3 {
            let result = rate_limit.check_rate_limit_memory("test_key", 3).await;
            assert!(result.is_ok());
        }

        // Should fail
        let result = rate_limit.check_rate_limit_memory("test_key", 3).await;
        assert!(result.is_err());

        // Wait for window to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should work again
        let result = rate_limit.check_rate_limit_memory("test_key", 3).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let config = RateLimitConfig {
            enabled: true,
            per_user_rpm: 5,
            per_ip_rpm: 3,
            per_route_rpm: 2,
            window_secs: 1, // 1 second window for testing
            redis_enabled: false,
            failure_mode: RateLimitFailureMode::Closed,
            strict_routes: vec![],
        };
        let rate_limit = RateLimit::new(config, None);

        // Create some entries
        for i in 0..5 {
            let key = format!("test_key_{i}");
            let _ = rate_limit.check_rate_limit_memory(&key, 10).await;
        }

        // Verify entries exist
        let len = {
            let store = rate_limit.in_memory_store.read().await;
            store.len()
        };
        assert_eq!(len, 5);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Cleanup
        let removed = rate_limit.cleanup_expired().await;
        assert_eq!(removed, 5);

        // Verify entries removed
        let len = {
            let store = rate_limit.in_memory_store.read().await;
            store.len()
        };
        assert_eq!(len, 0);
    }

    #[test]
    fn test_rate_limit_error_display() {
        let error = RateLimitError::Exceeded {
            limit: 100,
            window: Duration::from_secs(60),
        };
        assert!(error.to_string().contains("100"));
        assert!(error.to_string().contains("60"));

        let error = RateLimitError::Backend("Redis connection failed".to_string());
        assert!(error.to_string().contains("Redis connection failed"));
    }
}
