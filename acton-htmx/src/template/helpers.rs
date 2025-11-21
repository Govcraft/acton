//! Template helper functions for HTMX applications
//!
//! Provides utility functions that can be used within Askama templates
//! for common HTMX patterns.
//!
//! # HTMX Attribute Helpers
//!
//! These helpers generate proper HTMX attributes for common operations:
//!
//! ```rust
//! use acton_htmx::template::helpers::*;
//!
//! // Generate HTMX POST form attributes
//! let attrs = hx_post("/api/items", "#item-list", "innerHTML");
//! // Result: hx-post="/api/items" hx-target="#item-list" hx-swap="innerHTML"
//! ```

use std::collections::HashMap;
use std::hash::BuildHasher;

/// Generate CSRF token input field
///
/// Returns an HTML hidden input with the CSRF token.
/// Usage in templates: `{{ csrf_token() }}`
#[must_use]
pub fn csrf_token() -> String {
    // TODO: Integrate with actual CSRF middleware in Week 9
    r#"<input type="hidden" name="_csrf_token" value="placeholder">"#.to_string()
}

/// Generate CSRF token input field with a specific token value
///
/// Used when the token is provided from the session.
#[must_use]
pub fn csrf_token_with(token: &str) -> String {
    format!(r#"<input type="hidden" name="_csrf_token" value="{token}">"#)
}

/// Generate flash message HTML
///
/// Renders flash messages with appropriate styling.
/// Usage in templates: `{{ flash_messages() }}`
#[must_use]
pub const fn flash_messages() -> String {
    // TODO: Integrate with actual flash message system in Week 7
    String::new()
}

/// Generate route URL
///
/// Builds a URL for a named route with parameters.
/// Usage in templates: `{{ route("posts.show", {"id": post.id}) }}`
#[must_use]
pub fn route<S: BuildHasher>(_name: &str, _params: HashMap<String, String, S>) -> String {
    // TODO: Implement route generation with named routes
    "/".to_string()
}

/// Generate asset URL with cache busting
///
/// Returns a versioned asset URL for cache busting in production.
/// Usage in templates: `{{ asset("/css/styles.css") }}`
#[must_use]
pub fn asset(path: &str) -> String {
    // TODO: Add cache busting in production (append hash to filename)
    path.to_string()
}

// =============================================================================
// HTMX Attribute Helpers
// =============================================================================

/// Generate hx-post attribute with optional target and swap
///
/// # Examples
///
/// ```rust
/// use acton_htmx::template::helpers::hx_post;
///
/// let attrs = hx_post("/api/items", "#list", "innerHTML");
/// assert!(attrs.contains(r#"hx-post="/api/items""#));
/// ```
#[must_use]
pub fn hx_post(url: &str, target: &str, swap: &str) -> String {
    format!(r#"hx-post="{url}" hx-target="{target}" hx-swap="{swap}""#)
}

/// Generate hx-get attribute with optional target and swap
#[must_use]
pub fn hx_get(url: &str, target: &str, swap: &str) -> String {
    format!(r#"hx-get="{url}" hx-target="{target}" hx-swap="{swap}""#)
}

/// Generate hx-put attribute with optional target and swap
#[must_use]
pub fn hx_put(url: &str, target: &str, swap: &str) -> String {
    format!(r#"hx-put="{url}" hx-target="{target}" hx-swap="{swap}""#)
}

/// Generate hx-delete attribute with optional target and swap
#[must_use]
pub fn hx_delete(url: &str, target: &str, swap: &str) -> String {
    format!(r#"hx-delete="{url}" hx-target="{target}" hx-swap="{swap}""#)
}

/// Generate hx-patch attribute with optional target and swap
#[must_use]
pub fn hx_patch(url: &str, target: &str, swap: &str) -> String {
    format!(r#"hx-patch="{url}" hx-target="{target}" hx-swap="{swap}""#)
}

/// Generate hx-trigger attribute
///
/// # Examples
///
/// ```rust
/// use acton_htmx::template::helpers::hx_trigger;
///
/// let attr = hx_trigger("click");
/// assert_eq!(attr, r#"hx-trigger="click""#);
///
/// let attr = hx_trigger("keyup changed delay:500ms");
/// assert!(attr.contains("keyup"));
/// ```
#[must_use]
pub fn hx_trigger(trigger: &str) -> String {
    format!(r#"hx-trigger="{trigger}""#)
}

/// Generate hx-swap attribute
#[must_use]
pub fn hx_swap(strategy: &str) -> String {
    format!(r#"hx-swap="{strategy}""#)
}

/// Generate hx-target attribute
#[must_use]
pub fn hx_target(selector: &str) -> String {
    format!(r#"hx-target="{selector}""#)
}

/// Generate hx-indicator attribute for loading state
#[must_use]
pub fn hx_indicator(selector: &str) -> String {
    format!(r#"hx-indicator="{selector}""#)
}

/// Generate hx-confirm attribute for confirmation dialogs
#[must_use]
pub fn hx_confirm(message: &str) -> String {
    format!(r#"hx-confirm="{message}""#)
}

/// Generate hx-vals attribute for additional values
///
/// # Examples
///
/// ```rust
/// use acton_htmx::template::helpers::hx_vals;
///
/// let attr = hx_vals(r#"{"key": "value"}"#);
/// assert!(attr.contains("hx-vals"));
/// ```
#[must_use]
pub fn hx_vals(json: &str) -> String {
    format!(r"hx-vals='{json}'")
}

/// Generate hx-headers attribute for additional headers
#[must_use]
pub fn hx_headers(json: &str) -> String {
    format!(r"hx-headers='{json}'")
}

/// Generate hx-push-url attribute
#[must_use]
pub fn hx_push_url(url: &str) -> String {
    format!(r#"hx-push-url="{url}""#)
}

/// Generate hx-select attribute for partial selection
#[must_use]
pub fn hx_select(selector: &str) -> String {
    format!(r#"hx-select="{selector}""#)
}

/// Generate hx-select-oob attribute for out-of-band selection
#[must_use]
pub fn hx_select_oob(selector: &str) -> String {
    format!(r#"hx-select-oob="{selector}""#)
}

/// Generate hx-boost="true" for progressively enhanced links
#[must_use]
pub const fn hx_boost() -> &'static str {
    r#"hx-boost="true""#
}

/// Generate hx-disabled-elt attribute for disabling elements during request
#[must_use]
pub fn hx_disabled_elt(selector: &str) -> String {
    format!(r#"hx-disabled-elt="{selector}""#)
}

// =============================================================================
// HTML Safe Output
// =============================================================================

/// HTML-safe string wrapper
///
/// Marks a string as safe for direct HTML output (already escaped).
/// Use this when you have pre-escaped HTML that shouldn't be double-escaped.
#[derive(Debug, Clone)]
pub struct SafeString(pub String);

impl SafeString {
    /// Create a new `SafeString`
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl std::fmt::Display for SafeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SafeString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SafeString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token() {
        let token = csrf_token();
        assert!(token.contains("_csrf_token"));
        assert!(token.contains("hidden"));
    }

    #[test]
    fn test_csrf_token_with_value() {
        let token = csrf_token_with("abc123");
        assert!(token.contains(r#"value="abc123""#));
    }

    #[test]
    fn test_asset() {
        let path = asset("/css/styles.css");
        assert_eq!(path, "/css/styles.css");
    }

    #[test]
    fn test_hx_post() {
        let attrs = hx_post("/api/items", "#list", "innerHTML");
        assert!(attrs.contains("hx-post=\"/api/items\""));
        assert!(attrs.contains("hx-target=\"#list\""));
        assert!(attrs.contains("hx-swap=\"innerHTML\""));
    }

    #[test]
    fn test_hx_get() {
        let attrs = hx_get("/search", "#results", "outerHTML");
        assert!(attrs.contains(r#"hx-get="/search""#));
    }

    #[test]
    fn test_hx_trigger() {
        let attr = hx_trigger("click");
        assert_eq!(attr, r#"hx-trigger="click""#);
    }

    #[test]
    fn test_hx_confirm() {
        let attr = hx_confirm("Are you sure?");
        assert!(attr.contains("Are you sure?"));
    }

    #[test]
    fn test_hx_boost() {
        assert_eq!(hx_boost(), r#"hx-boost="true""#);
    }

    #[test]
    fn test_safe_string() {
        let safe = SafeString::new("<p>Hello</p>");
        assert_eq!(format!("{safe}"), "<p>Hello</p>");
    }

    #[test]
    fn test_safe_string_from() {
        let safe: SafeString = "test".into();
        assert_eq!(safe.0, "test");
    }
}
