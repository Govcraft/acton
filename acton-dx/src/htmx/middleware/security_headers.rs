//! Security headers middleware
//!
//! Automatically adds security-related HTTP headers to all responses:
//! - X-Frame-Options: Prevent clickjacking
//! - X-Content-Type-Options: Prevent MIME sniffing
//! - X-XSS-Protection: Enable browser XSS protection
//! - Strict-Transport-Security: Enforce HTTPS
//! - Content-Security-Policy: Control resource loading
//! - Referrer-Policy: Control referrer information
//!
//! # Example
//!
//! ```rust,no_run
//! # use acton_htmx::middleware::{SecurityHeadersConfig, SecurityHeadersLayer};
//! # use axum::Router;
//! # #[tokio::main]
//! # async fn main() {
//! let config = SecurityHeadersConfig::strict();
//! let app: Router<()> = Router::new()
//!     .layer(SecurityHeadersLayer::new(config));
//! # }
//! ```

use axum::{
    body::Body,
    http::{header, Request, Response},
    middleware::Next,
    response::IntoResponse,
};
use std::fmt;

/// Configuration for security headers middleware
///
/// Provides preset configurations for different security levels:
/// - `strict()`: Maximum security for production
/// - `development()`: Relaxed security for local development
/// - `custom()`: Full control over each header
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// X-Frame-Options header
    /// - DENY: Prevent all framing
    /// - SAMEORIGIN: Allow framing from same origin
    /// - None: Disable header
    pub frame_options: Option<FrameOptions>,

    /// X-Content-Type-Options header
    /// - true: Set to "nosniff"
    /// - false: Disable header
    pub content_type_options: bool,

    /// X-XSS-Protection header
    /// - Some(true): Enable with mode=block
    /// - Some(false): Enable without mode=block
    /// - None: Disable header (modern browsers use CSP instead)
    pub xss_protection: Option<bool>,

    /// Strict-Transport-Security header
    /// - Some(duration): Enable HSTS with max-age in seconds
    /// - None: Disable header (use for development/HTTP)
    pub hsts: Option<HstsConfig>,

    /// Content-Security-Policy header
    /// - Some(policy): Set CSP policy
    /// - None: Disable header
    pub csp: Option<String>,

    /// Referrer-Policy header
    /// - Some(policy): Set referrer policy
    /// - None: Disable header
    pub referrer_policy: Option<ReferrerPolicy>,
}

/// Frame options for X-Frame-Options header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOptions {
    /// Prevent all framing (DENY)
    Deny,
    /// Allow framing from same origin (SAMEORIGIN)
    SameOrigin,
}

impl fmt::Display for FrameOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => write!(f, "DENY"),
            Self::SameOrigin => write!(f, "SAMEORIGIN"),
        }
    }
}

/// HSTS configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HstsConfig {
    /// Max age in seconds (typically 31536000 = 1 year)
    pub max_age: u32,
    /// Include subdomains
    pub include_subdomains: bool,
    /// Include in browser preload list
    pub preload: bool,
}

impl HstsConfig {
    /// Strict HSTS for production (1 year, subdomains, preload)
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_age: 31_536_000, // 1 year
            include_subdomains: true,
            preload: true,
        }
    }

    /// Moderate HSTS (1 year, no subdomains, no preload)
    #[must_use]
    pub const fn moderate() -> Self {
        Self {
            max_age: 31_536_000, // 1 year
            include_subdomains: false,
            preload: false,
        }
    }
}

impl fmt::Display for HstsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "max-age={}", self.max_age)?;
        if self.include_subdomains {
            write!(f, "; includeSubDomains")?;
        }
        if self.preload {
            write!(f, "; preload")?;
        }
        Ok(())
    }
}

/// Referrer policy options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferrerPolicy {
    /// No referrer information
    NoReferrer,
    /// No referrer on downgrade (HTTPS -> HTTP)
    NoReferrerWhenDowngrade,
    /// Only origin (no path)
    Origin,
    /// Origin on cross-origin, full URL on same-origin
    OriginWhenCrossOrigin,
    /// Same origin only
    SameOrigin,
    /// Full URL on same origin, origin on cross-origin
    StrictOrigin,
    /// Strict origin on downgrade
    StrictOriginWhenCrossOrigin,
    /// Always send full URL
    UnsafeUrl,
}

impl fmt::Display for ReferrerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReferrer => write!(f, "no-referrer"),
            Self::NoReferrerWhenDowngrade => write!(f, "no-referrer-when-downgrade"),
            Self::Origin => write!(f, "origin"),
            Self::OriginWhenCrossOrigin => write!(f, "origin-when-cross-origin"),
            Self::SameOrigin => write!(f, "same-origin"),
            Self::StrictOrigin => write!(f, "strict-origin"),
            Self::StrictOriginWhenCrossOrigin => write!(f, "strict-origin-when-cross-origin"),
            Self::UnsafeUrl => write!(f, "unsafe-url"),
        }
    }
}

impl SecurityHeadersConfig {
    /// Strict security configuration for production
    ///
    /// - X-Frame-Options: DENY
    /// - X-Content-Type-Options: nosniff
    /// - X-XSS-Protection: 1; mode=block
    /// - Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    /// - Content-Security-Policy: default-src 'self'
    /// - Referrer-Policy: strict-origin-when-cross-origin
    #[must_use]
    pub fn strict() -> Self {
        Self {
            frame_options: Some(FrameOptions::Deny),
            content_type_options: true,
            xss_protection: Some(true),
            hsts: Some(HstsConfig::strict()),
            csp: Some("default-src 'self'".to_string()),
            referrer_policy: Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),
        }
    }

    /// Relaxed security configuration for development
    ///
    /// - X-Frame-Options: SAMEORIGIN
    /// - X-Content-Type-Options: nosniff
    /// - X-XSS-Protection: Disabled (rely on CSP)
    /// - Strict-Transport-Security: Disabled (HTTP in dev)
    /// - Content-Security-Policy: Permissive for development (allows CDN scripts)
    /// - Referrer-Policy: strict-origin-when-cross-origin
    #[must_use]
    pub fn development() -> Self {
        Self {
            frame_options: Some(FrameOptions::SameOrigin),
            content_type_options: true,
            xss_protection: None, // Modern browsers use CSP
            hsts: None,           // No HTTPS in development
            csp: Some(
                "default-src 'self' 'unsafe-inline' 'unsafe-eval'; \
                 script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; \
                 img-src 'self' data:"
                    .to_string(),
            ),
            referrer_policy: Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),
        }
    }

    /// Custom security configuration
    ///
    /// Start with all headers disabled, then enable as needed
    #[must_use]
    pub const fn custom() -> Self {
        Self {
            frame_options: None,
            content_type_options: false,
            xss_protection: None,
            hsts: None,
            csp: None,
            referrer_policy: None,
        }
    }

    /// Enable X-Frame-Options header
    #[must_use]
    pub const fn with_frame_options(mut self, options: FrameOptions) -> Self {
        self.frame_options = Some(options);
        self
    }

    /// Enable X-Content-Type-Options: nosniff
    #[must_use]
    pub const fn with_content_type_options(mut self) -> Self {
        self.content_type_options = true;
        self
    }

    /// Enable X-XSS-Protection header
    #[must_use]
    pub const fn with_xss_protection(mut self, block_mode: bool) -> Self {
        self.xss_protection = Some(block_mode);
        self
    }

    /// Enable Strict-Transport-Security header
    #[must_use]
    pub const fn with_hsts(mut self, config: HstsConfig) -> Self {
        self.hsts = Some(config);
        self
    }

    /// Enable Content-Security-Policy header
    #[must_use]
    pub fn with_csp(mut self, policy: String) -> Self {
        self.csp = Some(policy);
        self
    }

    /// Enable Referrer-Policy header
    #[must_use]
    pub const fn with_referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.referrer_policy = Some(policy);
        self
    }
}

/// Security headers middleware layer
///
/// Creates a tower layer that adds security headers to all responses.
///
/// # Example
///
/// ```rust,no_run
/// # use acton_htmx::middleware::{SecurityHeadersConfig, SecurityHeadersLayer};
/// # use axum::Router;
/// # #[tokio::main]
/// # async fn main() {
/// let config = SecurityHeadersConfig::strict();
/// let app: Router<()> = Router::new()
///     .layer(SecurityHeadersLayer::new(config));
/// # }
/// ```
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersLayer {
    /// Create a new security headers layer with the given configuration
    #[must_use]
    pub const fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }
}

impl<S> tower::Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Security headers middleware service
#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
    config: SecurityHeadersConfig,
}

impl<S> tower::Service<Request<Body>> for SecurityHeadersMiddleware<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let config = self.config.clone();
        let future = self.inner.call(request);

        Box::pin(async move {
            let mut response = future.await?;
            add_security_headers(&mut response, &config);
            Ok(response)
        })
    }
}

/// Add security headers to a response
fn add_security_headers(response: &mut Response<Body>, config: &SecurityHeadersConfig) {
    let headers = response.headers_mut();

    // X-Frame-Options
    if let Some(frame_options) = &config.frame_options {
        headers.insert("x-frame-options", frame_options.to_string().parse().unwrap());
    }

    // X-Content-Type-Options
    if config.content_type_options {
        headers.insert(
            "x-content-type-options",
            "nosniff".parse().unwrap(),
        );
    }

    // X-XSS-Protection
    if let Some(block_mode) = config.xss_protection {
        let value = if block_mode {
            "1; mode=block"
        } else {
            "1"
        };
        headers.insert("x-xss-protection", value.parse().unwrap());
    }

    // Strict-Transport-Security
    if let Some(hsts) = &config.hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            hsts.to_string().parse().unwrap(),
        );
    }

    // Content-Security-Policy
    if let Some(csp) = &config.csp {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            csp.parse().unwrap(),
        );
    }

    // Referrer-Policy
    if let Some(referrer_policy) = &config.referrer_policy {
        headers.insert(
            header::REFERER,
            referrer_policy.to_string().parse().unwrap(),
        );
    }
}

/// Axum middleware function for security headers
///
/// Alternative to using the layer directly.
///
/// # Example
///
/// ```rust,no_run
/// # use acton_htmx::middleware::security_headers::{SecurityHeadersConfig, security_headers};
/// # use axum::{Router, middleware};
/// # #[tokio::main]
/// # async fn main() {
/// let config = SecurityHeadersConfig::strict();
/// let app: Router<()> = Router::new()
///     .layer(middleware::from_fn(move |req, next| {
///         security_headers(req, next, config.clone())
///     }));
/// # }
/// ```
pub async fn security_headers(
    request: Request<Body>,
    next: Next,
    config: SecurityHeadersConfig,
) -> impl IntoResponse {
    let mut response = next.run(request).await;
    add_security_headers(&mut response, &config);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler() -> impl IntoResponse {
        (StatusCode::OK, "Hello, World!")
    }

    #[tokio::test]
    async fn test_strict_config_headers() {
        let config = SecurityHeadersConfig::strict();
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(SecurityHeadersLayer::new(config));

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        let headers = response.headers();
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-xss-protection").unwrap(), "1; mode=block");
        assert!(headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn test_development_config_headers() {
        let config = SecurityHeadersConfig::development();
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(SecurityHeadersLayer::new(config));

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        let headers = response.headers();
        assert_eq!(headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert!(!headers.contains_key("x-xss-protection"));
        assert!(!headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn test_custom_config() {
        let config = SecurityHeadersConfig::custom()
            .with_frame_options(FrameOptions::SameOrigin)
            .with_content_type_options()
            .with_referrer_policy(ReferrerPolicy::NoReferrer);

        let app = Router::new()
            .route("/", get(test_handler))
            .layer(SecurityHeadersLayer::new(config));

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        let headers = response.headers();
        assert_eq!(headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert!(!headers.contains_key("x-xss-protection"));
        assert!(!headers.contains_key("strict-transport-security"));
        assert!(!headers.contains_key("content-security-policy"));
    }

    #[test]
    fn test_hsts_config_display() {
        let hsts = HstsConfig::strict();
        assert_eq!(
            hsts.to_string(),
            "max-age=31536000; includeSubDomains; preload"
        );

        let hsts = HstsConfig::moderate();
        assert_eq!(hsts.to_string(), "max-age=31536000");
    }

    #[test]
    fn test_frame_options_display() {
        assert_eq!(FrameOptions::Deny.to_string(), "DENY");
        assert_eq!(FrameOptions::SameOrigin.to_string(), "SAMEORIGIN");
    }

    #[test]
    fn test_referrer_policy_display() {
        assert_eq!(ReferrerPolicy::NoReferrer.to_string(), "no-referrer");
        assert_eq!(
            ReferrerPolicy::StrictOriginWhenCrossOrigin.to_string(),
            "strict-origin-when-cross-origin"
        );
    }

    #[test]
    fn test_config_builder() {
        let config = SecurityHeadersConfig::custom()
            .with_frame_options(FrameOptions::Deny)
            .with_content_type_options()
            .with_xss_protection(true)
            .with_hsts(HstsConfig::strict())
            .with_csp("default-src 'self'".to_string())
            .with_referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin);

        assert_eq!(config.frame_options, Some(FrameOptions::Deny));
        assert!(config.content_type_options);
        assert_eq!(config.xss_protection, Some(true));
        assert!(config.hsts.is_some());
        assert!(config.csp.is_some());
        assert_eq!(
            config.referrer_policy,
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );
    }
}
