//! Prometheus metrics collection
//!
//! Provides Prometheus-compatible metrics for monitoring application performance.
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use acton_htmx::observability::metrics::metrics_handler;
//!
//! let app = Router::new()
//!     .route("/metrics", get(metrics_handler));
//! ```

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Prometheus metrics collector
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    /// HTTP request counter
    pub http_requests_total: Arc<AtomicU64>,
    /// HTTP request duration histogram (simplified)
    pub http_request_duration_ms: Arc<AtomicU64>,
    /// Background job counter
    pub jobs_enqueued_total: Arc<AtomicU64>,
    /// Background job success counter
    pub jobs_completed_total: Arc<AtomicU64>,
    /// Background job failure counter
    pub jobs_failed_total: Arc<AtomicU64>,
    /// Active session counter
    pub sessions_active: Arc<AtomicU64>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    /// Create new metrics collector
    #[must_use]
    pub fn new() -> Self {
        Self {
            http_requests_total: Arc::new(AtomicU64::new(0)),
            http_request_duration_ms: Arc::new(AtomicU64::new(0)),
            jobs_enqueued_total: Arc::new(AtomicU64::new(0)),
            jobs_completed_total: Arc::new(AtomicU64::new(0)),
            jobs_failed_total: Arc::new(AtomicU64::new(0)),
            sessions_active: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment HTTP request counter
    pub fn inc_http_requests(&self) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record HTTP request duration
    pub fn record_http_duration(&self, duration_ms: u64) {
        self.http_request_duration_ms.fetch_add(duration_ms, Ordering::Relaxed);
    }

    /// Increment job enqueued counter
    pub fn inc_jobs_enqueued(&self) {
        self.jobs_enqueued_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment job completed counter
    pub fn inc_jobs_completed(&self) {
        self.jobs_completed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment job failed counter
    pub fn inc_jobs_failed(&self) {
        self.jobs_failed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Set active sessions count
    pub fn set_sessions_active(&self, count: u64) {
        self.sessions_active.store(count, Ordering::Relaxed);
    }

    /// Generate Prometheus metrics output
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;

        let mut output = String::new();

        // HTTP metrics
        output.push_str("# HELP http_requests_total Total number of HTTP requests\n");
        output.push_str("# TYPE http_requests_total counter\n");
        let _ = writeln!(output, "http_requests_total {}",
            self.http_requests_total.load(Ordering::Relaxed));
        output.push('\n');

        output.push_str("# HELP http_request_duration_ms_total Total HTTP request duration in milliseconds\n");
        output.push_str("# TYPE http_request_duration_ms_total counter\n");
        let _ = writeln!(output, "http_request_duration_ms_total {}",
            self.http_request_duration_ms.load(Ordering::Relaxed));
        output.push('\n');

        // Job metrics
        output.push_str("# HELP jobs_enqueued_total Total number of jobs enqueued\n");
        output.push_str("# TYPE jobs_enqueued_total counter\n");
        let _ = writeln!(output, "jobs_enqueued_total {}",
            self.jobs_enqueued_total.load(Ordering::Relaxed));
        output.push('\n');

        output.push_str("# HELP jobs_completed_total Total number of jobs completed successfully\n");
        output.push_str("# TYPE jobs_completed_total counter\n");
        let _ = writeln!(output, "jobs_completed_total {}",
            self.jobs_completed_total.load(Ordering::Relaxed));
        output.push('\n');

        output.push_str("# HELP jobs_failed_total Total number of jobs that failed\n");
        output.push_str("# TYPE jobs_failed_total counter\n");
        let _ = writeln!(output, "jobs_failed_total {}",
            self.jobs_failed_total.load(Ordering::Relaxed));
        output.push('\n');

        // Session metrics
        output.push_str("# HELP sessions_active Number of active sessions\n");
        output.push_str("# TYPE sessions_active gauge\n");
        let _ = writeln!(output, "sessions_active {}",
            self.sessions_active.load(Ordering::Relaxed));
        output.push('\n');

        output
    }
}

/// Metrics handler for Prometheus scraping
///
/// Returns Prometheus-formatted metrics in text format.
///
/// # Example
///
/// ```rust,no_run
/// use axum::{Router, routing::get};
/// use acton_htmx::observability::metrics::metrics_handler;
///
/// let app = Router::new()
///     .route("/metrics", get(metrics_handler));
/// ```
#[allow(clippy::unused_async)]
pub async fn metrics_handler() -> impl IntoResponse {
    let collector = MetricsCollector::new();
    metrics_response(&collector)
}

/// Generate metrics response from collector
#[must_use]
pub fn metrics_response(collector: &MetricsCollector) -> Response {
    let body = collector.render();
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_new() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.http_requests_total.load(Ordering::Relaxed), 0);
        assert_eq!(collector.jobs_enqueued_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_inc_http_requests() {
        let collector = MetricsCollector::new();
        collector.inc_http_requests();
        collector.inc_http_requests();
        assert_eq!(collector.http_requests_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_record_http_duration() {
        let collector = MetricsCollector::new();
        collector.record_http_duration(100);
        collector.record_http_duration(200);
        assert_eq!(collector.http_request_duration_ms.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn test_inc_jobs_enqueued() {
        let collector = MetricsCollector::new();
        collector.inc_jobs_enqueued();
        assert_eq!(collector.jobs_enqueued_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_inc_jobs_completed() {
        let collector = MetricsCollector::new();
        collector.inc_jobs_completed();
        assert_eq!(collector.jobs_completed_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_inc_jobs_failed() {
        let collector = MetricsCollector::new();
        collector.inc_jobs_failed();
        assert_eq!(collector.jobs_failed_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_set_sessions_active() {
        let collector = MetricsCollector::new();
        collector.set_sessions_active(42);
        assert_eq!(collector.sessions_active.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn test_render_metrics() {
        let collector = MetricsCollector::new();
        collector.inc_http_requests();
        collector.inc_jobs_enqueued();
        collector.set_sessions_active(5);

        let output = collector.render();

        assert!(output.contains("http_requests_total 1"));
        assert!(output.contains("jobs_enqueued_total 1"));
        assert!(output.contains("sessions_active 5"));
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        let response = metrics_handler().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_metrics_response_content_type() {
        let collector = MetricsCollector::new();
        let response = metrics_response(&collector);

        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");
    }
}
