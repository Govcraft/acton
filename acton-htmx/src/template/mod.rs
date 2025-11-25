//! Askama template engine integration with HTMX patterns
//!
//! This module provides:
//! - `HxTemplate` trait for automatic partial/full page detection
//! - Template registry with optional caching
//! - HTMX-aware template helpers
//! - Integration with axum-htmx response types
//!
//! # Examples
//!
//! ```rust
//! use askama::Template;
//! use acton_htmx::template::HxTemplate;
//! use axum_htmx::HxRequest;
//!
//! #[derive(Template)]
//! #[template(source = "<h1>Posts</h1>{% for post in posts %}<p>{{ post }}</p>{% endfor %}", ext = "html")]
//! struct PostsIndexTemplate {
//!     posts: Vec<String>,
//! }
//!
//! async fn index(HxRequest(is_htmx): HxRequest) -> impl axum::response::IntoResponse {
//!     let template = PostsIndexTemplate {
//!         posts: vec!["Post 1".to_string(), "Post 2".to_string()],
//!     };
//!
//!     template.render_htmx(is_htmx)
//! }
//! ```

use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

pub mod extractor;
pub mod framework;
pub mod helpers;
pub mod registry;

pub use extractor::*;
pub use framework::{FrameworkTemplateError, FrameworkTemplates};
pub use helpers::*;
pub use registry::TemplateRegistry;

/// Extension trait for Askama templates with HTMX support
///
/// Automatically renders partial content for HTMX requests and full pages
/// for regular browser requests.
pub trait HxTemplate: Template {
    /// Render template based on HTMX request detection
    ///
    /// Returns partial content if `is_htmx` is true, otherwise returns full page.
    /// The distinction between partial and full is determined by the template's
    /// structure and naming conventions.
    ///
    /// # Errors
    ///
    /// Returns `StatusCode::INTERNAL_SERVER_ERROR` if template rendering fails.
    fn render_htmx(self, is_htmx: bool) -> Response
    where
        Self: Sized,
    {
        match self.render() {
            Ok(html) => {
                if is_htmx {
                    // For HTMX requests, extract and return just the main content
                    let partial = extractor::extract_main_content(&html);
                    Html(partial.into_owned()).into_response()
                } else {
                    // For regular requests, return the full page
                    Html(html).into_response()
                }
            }
            Err(err) => {
                tracing::error!("Template rendering error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Template rendering failed",
                )
                    .into_response()
            }
        }
    }

    /// Render as HTML response
    ///
    /// Always renders the full template regardless of request type.
    ///
    /// # Errors
    ///
    /// Returns `StatusCode::INTERNAL_SERVER_ERROR` if template rendering fails.
    fn render_html(self) -> Response
    where
        Self: Sized,
    {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                tracing::error!("Template rendering error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Template rendering failed",
                )
                    .into_response()
            }
        }
    }

    /// Render partial content only
    ///
    /// Extracts and renders only the main content block without layout.
    /// Useful for HTMX partial updates.
    ///
    /// # Errors
    ///
    /// Returns `StatusCode::INTERNAL_SERVER_ERROR` if template rendering fails.
    fn render_partial(self) -> Response
    where
        Self: Sized,
    {
        match self.render() {
            Ok(html) => {
                let partial = extractor::extract_main_content(&html);
                Html(partial.into_owned()).into_response()
            }
            Err(err) => {
                tracing::error!("Template rendering error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Template rendering failed",
                )
                    .into_response()
            }
        }
    }

    /// Render as out-of-band swap content
    ///
    /// Wraps the template content in an element with `hx-swap-oob="true"`.
    /// Used for updating multiple parts of the page in a single response.
    ///
    /// # Arguments
    ///
    /// * `target_id` - The ID of the element to swap
    /// * `swap_strategy` - The swap strategy (defaults to "true" for innerHTML)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use askama::Template;
    /// use acton_htmx::template::HxTemplate;
    ///
    /// #[derive(Template)]
    /// #[template(source = "<span>Updated: {{ count }}</span>", ext = "html")]
    /// struct CounterTemplate { count: i32 }
    ///
    /// let template = CounterTemplate { count: 42 };
    /// // Returns: <div id="counter" hx-swap-oob="true"><span>Updated: 42</span></div>
    /// let oob_html = template.render_oob("counter", None);
    /// ```
    fn render_oob(self, target_id: &str, swap_strategy: Option<&str>) -> Response
    where
        Self: Sized,
    {
        match self.render() {
            Ok(html) => {
                let swap_attr = swap_strategy.unwrap_or("true");
                let oob_html = format!(
                    r#"<div id="{target_id}" hx-swap-oob="{swap_attr}">{html}</div>"#
                );
                Html(oob_html).into_response()
            }
            Err(err) => {
                tracing::error!("Template rendering error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Template rendering failed",
                )
                    .into_response()
            }
        }
    }

    /// Render as out-of-band swap string (for combining with other content)
    ///
    /// Returns the OOB HTML as a String instead of a Response, allowing
    /// multiple OOB swaps to be combined in a single response.
    ///
    /// # Errors
    ///
    /// Returns [`askama::Error`] if template rendering fails due to:
    /// - Invalid template syntax
    /// - Missing variables or fields
    /// - Template execution errors
    ///
    /// # Examples
    ///
    /// ```rust
    /// use askama::Template;
    /// use acton_htmx::template::HxTemplate;
    ///
    /// #[derive(Template)]
    /// #[template(source = "{{ message }}", ext = "html")]
    /// struct FlashTemplate { message: String }
    ///
    /// let flash = FlashTemplate { message: "Success!".to_string() };
    /// let oob_str = flash.render_oob_str("flash-messages", None);
    /// // Combine with main content for a multi-target response
    /// ```
    fn render_oob_str(self, target_id: &str, swap_strategy: Option<&str>) -> Result<String, askama::Error>
    where
        Self: Sized,
    {
        let html = self.render()?;
        let swap_attr = swap_strategy.unwrap_or("true");
        Ok(format!(
            r#"<div id="{target_id}" hx-swap-oob="{swap_attr}">{html}</div>"#
        ))
    }
}

// Blanket implementation for all Askama templates
impl<T> HxTemplate for T where T: Template {}

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template;

    #[derive(Template)]
    #[template(source = "<h1>{{ title }}</h1>", ext = "html")]
    struct TestTemplate {
        title: String,
    }

    #[test]
    fn test_render_html() {
        let template = TestTemplate {
            title: "Hello".to_string(),
        };

        let response = template.render_html();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_render_htmx_full_page() {
        let template = TestTemplate {
            title: "Hello".to_string(),
        };

        let response = template.render_htmx(false);
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_render_htmx_partial() {
        let template = TestTemplate {
            title: "Hello".to_string(),
        };

        let response = template.render_htmx(true);
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_render_oob() {
        let template = TestTemplate {
            title: "Updated".to_string(),
        };

        let response = template.render_oob("my-element", None);
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_render_oob_with_strategy() {
        let template = TestTemplate {
            title: "Replaced".to_string(),
        };

        let response = template.render_oob("my-element", Some("outerHTML"));
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_render_oob_str() {
        let template = TestTemplate {
            title: "Content".to_string(),
        };

        let oob_str = template.render_oob_str("target-id", None).unwrap();
        assert!(oob_str.contains(r#"id="target-id""#));
        assert!(oob_str.contains(r#"hx-swap-oob="true""#));
        assert!(oob_str.contains("<h1>Content</h1>"));
    }

    #[test]
    fn test_render_oob_str_with_strategy() {
        let template = TestTemplate {
            title: "Content".to_string(),
        };

        let oob_str = template.render_oob_str("target-id", Some("innerHTML")).unwrap();
        assert!(oob_str.contains(r#"hx-swap-oob="innerHTML""#));
    }
}
