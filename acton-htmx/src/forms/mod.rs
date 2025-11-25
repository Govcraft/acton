//! Form handling, building, and validation for HTMX applications
//!
//! This module provides a builder-pattern API for creating forms with:
//! - Automatic CSRF token injection
//! - HTMX attribute support
//! - Integration with the `validator` crate
//! - Field-level error rendering
//!
//! # Quick Start
//!
//! ```rust
//! use acton_htmx::forms::{FormBuilder, InputType};
//!
//! let form = FormBuilder::new("/users", "POST")
//!     .csrf_token("abc123")
//!     .field("email", InputType::Email)
//!         .label("Email Address")
//!         .required()
//!         .placeholder("you@example.com")
//!         .done()
//!     .field("password", InputType::Password)
//!         .label("Password")
//!         .required()
//!         .min_length(8)
//!         .done()
//!     .submit("Sign Up")
//!     .htmx_post("/users")
//!     .htmx_target("#result")
//!     .htmx_swap("innerHTML")
//!     .build();
//!
//! println!("{form}");
//! ```
//!
//! # HTMX Integration
//!
//! Forms can be enhanced with HTMX attributes for seamless partial updates:
//!
//! ```rust
//! use acton_htmx::forms::FormBuilder;
//!
//! let form = FormBuilder::new("/search", "GET")
//!     .htmx_get("/search")
//!     .htmx_trigger("keyup changed delay:500ms")
//!     .htmx_target("#results")
//!     .htmx_swap("innerHTML")
//!     .htmx_indicator("#spinner")
//!     .build();
//! ```
//!
//! # Validation Errors
//!
//! Display validation errors alongside fields:
//!
//! ```rust
//! use acton_htmx::forms::{FormBuilder, InputType, ValidationErrors};
//!
//! let mut errors = ValidationErrors::new();
//! errors.add("email", "Invalid email address");
//!
//! let form = FormBuilder::new("/users", "POST")
//!     .errors(&errors)
//!     .field("email", InputType::Email)
//!         .label("Email")
//!         .done()
//!     .build();
//!
//! // Errors are automatically rendered next to the field
//! ```

mod builder;
mod error;
mod field;
mod render;
mod template_render;

pub use builder::{FieldBuilder, FileFieldBuilder, FormBuilder};
pub use error::{FieldError, ValidationErrors};
pub use field::{FileFieldAttrs, FormField, InputType, SelectOption};
pub use render::{FormRenderOptions, FormRenderer};
pub use template_render::{FormRenderError, TemplateFormRenderer};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_form() {
        let form = FormBuilder::new("/login", "POST")
            .field("email", InputType::Email)
            .label("Email")
            .required()
            .done()
            .field("password", InputType::Password)
            .label("Password")
            .required()
            .done()
            .submit("Login")
            .build();

        assert!(form.contains(r#"action="/login""#));
        assert!(form.contains(r#"method="POST""#));
        assert!(form.contains(r#"type="email""#));
        assert!(form.contains(r#"type="password""#));
        assert!(form.contains("Login"));
    }

    #[test]
    fn test_csrf_injection() {
        let form = FormBuilder::new("/users", "POST")
            .csrf_token("test_token_123")
            .build();

        assert!(form.contains(r#"name="_csrf_token""#));
        assert!(form.contains(r#"value="test_token_123""#));
    }

    #[test]
    fn test_htmx_attributes() {
        let form = FormBuilder::new("/search", "GET")
            .htmx_get("/api/search")
            .htmx_target("#results")
            .htmx_swap("innerHTML")
            .htmx_indicator("#spinner")
            .build();

        assert!(form.contains(r#"hx-get="/api/search""#));
        assert!(form.contains(r##"hx-target="#results""##));
        assert!(form.contains(r#"hx-swap="innerHTML""#));
        assert!(form.contains(r##"hx-indicator="#spinner""##));
    }

    #[test]
    fn test_validation_errors() {
        let mut errors = ValidationErrors::new();
        errors.add("email", "is required");

        let form = FormBuilder::new("/users", "POST")
            .errors(&errors)
            .field("email", InputType::Email)
            .label("Email")
            .done()
            .build();

        assert!(form.contains("is required"));
        assert!(form.contains("form-error"));
    }

    #[test]
    fn test_field_attributes() {
        let form = FormBuilder::new("/test", "POST")
            .field("name", InputType::Text)
            .label("Full Name")
            .placeholder("John Doe")
            .required()
            .min_length(2)
            .max_length(100)
            .pattern(r"[A-Za-z\s]+")
            .done()
            .build();

        assert!(form.contains(r#"placeholder="John Doe""#));
        assert!(form.contains("required"));
        assert!(form.contains(r#"minlength="2""#));
        assert!(form.contains(r#"maxlength="100""#));
        assert!(form.contains("pattern="));
    }

    #[test]
    fn test_select_field() {
        let form = FormBuilder::new("/test", "POST")
            .select("country")
            .label("Country")
            .option("us", "United States")
            .option("ca", "Canada")
            .option("mx", "Mexico")
            .selected("us")
            .done()
            .build();

        assert!(form.contains("<select"));
        assert!(form.contains(r#"value="us""#));
        assert!(form.contains("United States"));
        assert!(form.contains("selected"));
    }

    #[test]
    fn test_textarea_field() {
        let form = FormBuilder::new("/test", "POST")
            .textarea("bio")
            .label("Biography")
            .placeholder("Tell us about yourself...")
            .rows(5)
            .cols(40)
            .done()
            .build();

        assert!(form.contains("<textarea"));
        assert!(form.contains(r#"rows="5""#));
        assert!(form.contains(r#"cols="40""#));
    }

    #[test]
    fn test_checkbox_field() {
        let form = FormBuilder::new("/test", "POST")
            .checkbox("terms")
            .label("I agree to the terms")
            .checked()
            .done()
            .build();

        assert!(form.contains(r#"type="checkbox""#));
        assert!(form.contains("checked"));
    }

    #[test]
    fn test_form_id_and_class() {
        let form = FormBuilder::new("/test", "POST")
            .id("my-form")
            .class("form-styled")
            .build();

        assert!(form.contains(r#"id="my-form""#));
        assert!(form.contains(r#"class="form-styled""#));
    }

    #[test]
    fn test_file_upload_field() {
        let form = FormBuilder::new("/upload", "POST")
            .file("avatar")
            .label("Profile Picture")
            .accept("image/png,image/jpeg")
            .max_size_mb(5)
            .required()
            .done()
            .build();

        assert!(form.contains(r#"enctype="multipart/form-data""#));
        assert!(form.contains(r#"type="file""#));
        assert!(form.contains(r#"accept="image/png,image/jpeg""#));
        assert!(form.contains(r#"data-max-size-mb="5""#));
        assert!(form.contains("required"));
    }

    #[test]
    fn test_file_upload_multiple() {
        let form = FormBuilder::new("/upload", "POST")
            .file("attachments")
            .label("Attachments")
            .multiple()
            .done()
            .build();

        assert!(form.contains(r#"enctype="multipart/form-data""#));
        assert!(form.contains("multiple"));
    }

    #[test]
    fn test_file_upload_with_preview() {
        let form = FormBuilder::new("/upload", "POST")
            .file("image")
            .label("Image")
            .show_preview()
            .drag_drop()
            .done()
            .build();

        assert!(form.contains(r#"data-preview="true""#));
        assert!(form.contains(r#"data-drag-drop="true""#));
    }

    #[test]
    fn test_file_upload_with_progress_endpoint() {
        let form = FormBuilder::new("/upload", "POST")
            .file("large_file")
            .label("Large File")
            .progress_endpoint("/upload/progress")
            .done()
            .build();

        assert!(form.contains(r#"data-progress-endpoint="/upload/progress""#));
    }

    #[test]
    fn test_multipart_auto_set() {
        let form = FormBuilder::new("/upload", "POST")
            .file("file1")
            .done()
            .build();

        // Enctype should be automatically set when file() is called
        assert!(form.contains(r#"enctype="multipart/form-data""#));
    }

    #[test]
    fn test_file_upload_with_help_text() {
        let form = FormBuilder::new("/upload", "POST")
            .file("avatar")
            .label("Avatar")
            .help("Maximum size: 5MB. Accepted formats: PNG, JPEG")
            .done()
            .build();

        assert!(form.contains("Maximum size: 5MB"));
        assert!(form.contains("Accepted formats: PNG, JPEG"));
    }
}
