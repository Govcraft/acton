//! Framework template system with XDG-compliant storage
//!
//! This module provides runtime-loadable templates for framework-generated HTML
//! (forms, flash messages, validation errors, error pages, etc.).
//!
//! Templates are resolved in order:
//! 1. User customizations in `$XDG_CONFIG_HOME/acton-htmx/templates/framework/`
//! 2. Cached defaults in `$XDG_CACHE_HOME/acton-htmx/templates/framework/`
//! 3. Embedded fallbacks compiled into the binary
//!
//! # Example
//!
//! ```rust,no_run
//! use acton_htmx::template::framework::FrameworkTemplates;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let templates = FrameworkTemplates::new()?;
//!
//! // Render a form input
//! let html = templates.render("forms/input.html", minijinja::context! {
//!     input_type => "text",
//!     name => "email",
//!     id => "email",
//! })?;
//! # Ok(())
//! # }
//! ```

mod loader;

pub use loader::{FrameworkTemplateError, FrameworkTemplates};

/// Names of all framework templates
pub const TEMPLATE_NAMES: &[&str] = &[
    // Forms
    "forms/form.html",
    "forms/field-wrapper.html",
    "forms/input.html",
    "forms/textarea.html",
    "forms/select.html",
    "forms/checkbox.html",
    "forms/radio-group.html",
    "forms/submit-button.html",
    "forms/help-text.html",
    "forms/label.html",
    "forms/csrf-input.html",
    // Validation
    "validation/field-errors.html",
    "validation/validation-summary.html",
    // Flash messages
    "flash/container.html",
    "flash/message.html",
    // HTMX
    "htmx/oob-wrapper.html",
    // Error pages
    "errors/400.html",
    "errors/401.html",
    "errors/403.html",
    "errors/404.html",
    "errors/422.html",
    "errors/500.html",
];
