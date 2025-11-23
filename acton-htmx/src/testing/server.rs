//! Test server utilities using axum-test
//!
//! Provides a thin wrapper around `axum-test::TestServer` with HTMX-specific
//! assertion helpers for integration testing.

use axum::Router;

/// Test server wrapper for integration testing
///
/// This is a thin wrapper around `axum_test::TestServer` that provides
/// HTMX-specific assertion methods for common response patterns.
///
/// # Example
///
/// ```rust,no_run
/// use acton_htmx::testing::TestServer;
/// use axum::{Router, routing::get};
///
/// #[tokio::test]
/// async fn test_homepage() {
///     let app = Router::new().route("/", get(|| async { "Hello" }));
///     let server = TestServer::new(app).unwrap();
///
///     let response = server.get("/").await;
///     response.assert_status_ok();
/// }
/// ```
pub struct TestServer {
    inner: axum_test::TestServer,
}

impl TestServer {
    /// Create a new test server from an Axum router
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be started
    pub fn new(app: Router) -> anyhow::Result<Self> {
        let inner = axum_test::TestServer::new(app)?;
        Ok(Self { inner })
    }

    /// Make a GET request to the server
    pub fn get(&self, path: &str) -> axum_test::TestRequest {
        self.inner.get(path)
    }

    /// Make a POST request to the server
    pub fn post(&self, path: &str) -> axum_test::TestRequest {
        self.inner.post(path)
    }

    /// Make a PUT request to the server
    pub fn put(&self, path: &str) -> axum_test::TestRequest {
        self.inner.put(path)
    }

    /// Make a PATCH request to the server
    pub fn patch(&self, path: &str) -> axum_test::TestRequest {
        self.inner.patch(path)
    }

    /// Make a DELETE request to the server
    pub fn delete(&self, path: &str) -> axum_test::TestRequest {
        self.inner.delete(path)
    }

    /// Get the inner `axum_test::TestServer` for advanced usage
    #[must_use]
    pub const fn inner(&self) -> &axum_test::TestServer {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};

    #[tokio::test]
    async fn test_server_creation() {
        let app = Router::new().route("/", get(|| async { "Hello" }));
        let server = TestServer::new(app).unwrap();
        let response = server.get("/").await;
        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_http_methods() {
        let app = Router::new()
            .route("/", get(|| async { "GET" }))
            .route("/post", axum::routing::post(|| async { "POST" }))
            .route("/put", axum::routing::put(|| async { "PUT" }))
            .route("/patch", axum::routing::patch(|| async { "PATCH" }))
            .route("/delete", axum::routing::delete(|| async { "DELETE" }));

        let server = TestServer::new(app).unwrap();

        server.get("/").await.assert_status_ok();
        server.post("/post").await.assert_status_ok();
        server.put("/put").await.assert_status_ok();
        server.patch("/patch").await.assert_status_ok();
        server.delete("/delete").await.assert_status_ok();
    }
}
