//! Form rendering to HTML
//!
//! Renders form builders to HTML strings with proper escaping
//! and validation error display.

use std::fmt::Write;

use super::builder::FormBuilder;
use super::field::{FieldKind, FormField, InputType};

/// Options for customizing form rendering
#[derive(Debug, Clone)]
pub struct FormRenderOptions {
    /// CSS class for form groups (wrapper around label + input + errors)
    pub group_class: String,
    /// CSS class for labels
    pub label_class: String,
    /// CSS class for input elements
    pub input_class: String,
    /// CSS class for error messages
    pub error_class: String,
    /// CSS class for help text
    pub help_class: String,
    /// CSS class for submit button
    pub submit_class: String,
    /// CSS class applied to inputs with errors
    pub input_error_class: String,
    /// Whether to wrap fields in a div
    pub wrap_fields: bool,
}

impl Default for FormRenderOptions {
    fn default() -> Self {
        Self {
            group_class: "form-group".into(),
            label_class: "form-label".into(),
            input_class: "form-input".into(),
            error_class: "form-error".into(),
            help_class: "form-help".into(),
            submit_class: "form-submit".into(),
            input_error_class: "form-input-error".into(),
            wrap_fields: true,
        }
    }
}

/// Renders forms to HTML
pub struct FormRenderer;

impl FormRenderer {
    /// Render a form to HTML string
    #[must_use]
    pub fn render(form: &FormBuilder<'_>) -> String {
        Self::render_with_options(form, &FormRenderOptions::default())
    }

    /// Render a form with custom options
    #[must_use]
    pub fn render_with_options(form: &FormBuilder<'_>, options: &FormRenderOptions) -> String {
        let mut html = String::with_capacity(1024);

        // Open form tag
        html.push_str("<form");
        Self::write_attr(&mut html, "action", &form.action);
        Self::write_attr(&mut html, "method", &form.method);

        if let Some(ref id) = form.id {
            Self::write_attr(&mut html, "id", id);
        }
        if let Some(ref class) = form.class {
            Self::write_attr(&mut html, "class", class);
        }
        if let Some(ref enctype) = form.enctype {
            Self::write_attr(&mut html, "enctype", enctype);
        }
        if form.novalidate {
            html.push_str(" novalidate");
        }

        // HTMX attributes
        Self::write_htmx_form_attrs(&mut html, form);

        // Custom attributes
        for (name, value) in &form.custom_attrs {
            Self::write_attr(&mut html, name, value);
        }

        html.push_str(">\n");

        // CSRF token
        if let Some(ref token) = form.csrf_token {
            let _ = writeln!(
                html,
                r#"  <input type="hidden" name="_csrf_token" value="{}">"#,
                Self::escape_attr(token)
            );
        }

        // hx-validate attribute if enabled
        if form.htmx_validate {
            html.push_str(r#"  <input type="hidden" name="_hx_validate" value="true">"#);
            html.push('\n');
        }

        // Render fields
        for field in &form.fields {
            html.push_str(&Self::render_field(field, form.errors, options));
        }

        // Submit button
        if let Some(ref text) = form.submit_text {
            let submit_class = form
                .submit_class
                .as_deref()
                .unwrap_or(&options.submit_class);
            let _ = writeln!(
                html,
                r#"  <button type="submit" class="{}">{}</button>"#,
                Self::escape_attr(submit_class),
                Self::escape_html(text)
            );
        }

        html.push_str("</form>");
        html
    }

    fn render_field(
        field: &FormField,
        errors: Option<&super::ValidationErrors>,
        options: &FormRenderOptions,
    ) -> String {
        let mut html = String::with_capacity(256);
        let field_errors = errors.as_ref().map_or_else(<&[_]>::default, |e| e.for_field(&field.name));
        let has_errors = !field_errors.is_empty();

        // Open wrapper if enabled (skip for hidden fields)
        let is_hidden = matches!(field.kind, FieldKind::Input(InputType::Hidden));
        if options.wrap_fields && !is_hidden {
            let _ = writeln!(html, r#"  <div class="{}">"#, options.group_class);
        }

        // Label (skip for hidden and checkbox - checkbox label comes after input)
        let is_checkbox = matches!(field.kind, FieldKind::Checkbox { .. });
        if let Some(ref label) = field.label {
            if !is_hidden && !is_checkbox {
                let _ = writeln!(
                    html,
                    r#"    <label for="{}" class="{}">{}</label>"#,
                    Self::escape_attr(field.effective_id()),
                    options.label_class,
                    Self::escape_html(label)
                );
            }
        }

        // Render the actual input element
        let input_html = match &field.kind {
            FieldKind::Input(input_type) => Self::render_input(field, *input_type, has_errors, options),
            FieldKind::Textarea { rows, cols } => {
                Self::render_textarea(field, *rows, *cols, has_errors, options)
            }
            FieldKind::Select { options: opts, multiple } => {
                Self::render_select(field, opts, *multiple, has_errors, options)
            }
            FieldKind::Checkbox { checked } => {
                Self::render_checkbox(field, *checked, has_errors, options)
            }
            FieldKind::Radio { options: opts } => {
                Self::render_radio(field, opts, has_errors, options)
            }
        };
        html.push_str(&input_html);

        // Checkbox label comes after input
        if is_checkbox {
            if let Some(ref label) = field.label {
                let _ = write!(
                    html,
                    r#" <label for="{}" class="{}">{}</label>"#,
                    Self::escape_attr(field.effective_id()),
                    options.label_class,
                    Self::escape_html(label)
                );
            }
            html.push('\n');
        }

        // Field errors
        for error in field_errors {
            let _ = writeln!(
                html,
                r#"    <span class="{}">{}</span>"#,
                options.error_class,
                Self::escape_html(&error.message)
            );
        }

        // Help text
        if let Some(ref help) = field.help_text {
            let _ = writeln!(
                html,
                r#"    <span class="{}">{}</span>"#,
                options.help_class,
                Self::escape_html(help)
            );
        }

        // Close wrapper
        if options.wrap_fields && !is_hidden {
            html.push_str("  </div>\n");
        }

        html
    }

    fn render_input(
        field: &FormField,
        input_type: InputType,
        has_errors: bool,
        options: &FormRenderOptions,
    ) -> String {
        let mut html = String::with_capacity(128);

        // Hidden fields don't need wrapper indentation
        let indent = if input_type == InputType::Hidden {
            "  "
        } else {
            "    "
        };

        html.push_str(indent);
        html.push_str("<input");
        Self::write_attr(&mut html, "type", input_type.as_str());
        Self::write_attr(&mut html, "name", &field.name);
        Self::write_attr(&mut html, "id", field.effective_id());

        // Class with potential error class
        let class = Self::build_input_class(field, has_errors, options);
        if !class.is_empty() {
            Self::write_attr(&mut html, "class", &class);
        }

        if let Some(ref value) = field.value {
            Self::write_attr(&mut html, "value", value);
        }
        if let Some(ref placeholder) = field.placeholder {
            Self::write_attr(&mut html, "placeholder", placeholder);
        }
        if field.flags.required {
            html.push_str(" required");
        }
        if field.flags.disabled {
            html.push_str(" disabled");
        }
        if field.flags.readonly {
            html.push_str(" readonly");
        }
        if field.flags.autofocus {
            html.push_str(" autofocus");
        }
        if let Some(ref autocomplete) = field.autocomplete {
            Self::write_attr(&mut html, "autocomplete", autocomplete);
        }
        if let Some(len) = field.min_length {
            Self::write_attr(&mut html, "minlength", &len.to_string());
        }
        if let Some(len) = field.max_length {
            Self::write_attr(&mut html, "maxlength", &len.to_string());
        }
        if let Some(ref min) = field.min {
            Self::write_attr(&mut html, "min", min);
        }
        if let Some(ref max) = field.max {
            Self::write_attr(&mut html, "max", max);
        }
        if let Some(ref step) = field.step {
            Self::write_attr(&mut html, "step", step);
        }
        if let Some(ref pattern) = field.pattern {
            Self::write_attr(&mut html, "pattern", pattern);
        }

        // Data attributes
        for (name, value) in &field.data_attrs {
            Self::write_attr(&mut html, &format!("data-{name}"), value);
        }

        // Custom attributes
        for (name, value) in &field.custom_attrs {
            Self::write_attr(&mut html, name, value);
        }

        // HTMX field attributes
        Self::write_htmx_field_attrs(&mut html, field);

        html.push_str(">\n");
        html
    }

    fn render_textarea(
        field: &FormField,
        rows: Option<u32>,
        cols: Option<u32>,
        has_errors: bool,
        options: &FormRenderOptions,
    ) -> String {
        let mut html = String::with_capacity(128);

        html.push_str("    <textarea");
        Self::write_attr(&mut html, "name", &field.name);
        Self::write_attr(&mut html, "id", field.effective_id());

        let class = Self::build_input_class(field, has_errors, options);
        if !class.is_empty() {
            Self::write_attr(&mut html, "class", &class);
        }

        if let Some(ref placeholder) = field.placeholder {
            Self::write_attr(&mut html, "placeholder", placeholder);
        }
        if let Some(r) = rows {
            Self::write_attr(&mut html, "rows", &r.to_string());
        }
        if let Some(c) = cols {
            Self::write_attr(&mut html, "cols", &c.to_string());
        }
        if field.flags.required {
            html.push_str(" required");
        }
        if field.flags.disabled {
            html.push_str(" disabled");
        }
        if field.flags.readonly {
            html.push_str(" readonly");
        }

        Self::write_htmx_field_attrs(&mut html, field);

        html.push('>');
        if let Some(ref value) = field.value {
            html.push_str(&Self::escape_html(value));
        }
        html.push_str("</textarea>\n");
        html
    }

    fn render_select(
        field: &FormField,
        opts: &[super::field::SelectOption],
        multiple: bool,
        has_errors: bool,
        options: &FormRenderOptions,
    ) -> String {
        let mut html = String::with_capacity(256);

        html.push_str("    <select");
        Self::write_attr(&mut html, "name", &field.name);
        Self::write_attr(&mut html, "id", field.effective_id());

        let class = Self::build_input_class(field, has_errors, options);
        if !class.is_empty() {
            Self::write_attr(&mut html, "class", &class);
        }

        if multiple {
            html.push_str(" multiple");
        }
        if field.flags.required {
            html.push_str(" required");
        }
        if field.flags.disabled {
            html.push_str(" disabled");
        }

        Self::write_htmx_field_attrs(&mut html, field);

        html.push_str(">\n");

        for opt in opts {
            html.push_str("      <option");
            Self::write_attr(&mut html, "value", &opt.value);
            if opt.disabled {
                html.push_str(" disabled");
            }
            if field.value.as_ref() == Some(&opt.value) {
                html.push_str(" selected");
            }
            html.push('>');
            html.push_str(&Self::escape_html(&opt.label));
            html.push_str("</option>\n");
        }

        html.push_str("    </select>\n");
        html
    }

    fn render_checkbox(
        field: &FormField,
        checked: bool,
        has_errors: bool,
        options: &FormRenderOptions,
    ) -> String {
        let mut html = String::with_capacity(128);

        html.push_str("    <input");
        Self::write_attr(&mut html, "type", "checkbox");
        Self::write_attr(&mut html, "name", &field.name);
        Self::write_attr(&mut html, "id", field.effective_id());

        let class = Self::build_input_class(field, has_errors, options);
        if !class.is_empty() {
            Self::write_attr(&mut html, "class", &class);
        }

        if let Some(ref value) = field.value {
            Self::write_attr(&mut html, "value", value);
        } else {
            Self::write_attr(&mut html, "value", "true");
        }

        if checked {
            html.push_str(" checked");
        }
        if field.flags.required {
            html.push_str(" required");
        }
        if field.flags.disabled {
            html.push_str(" disabled");
        }

        Self::write_htmx_field_attrs(&mut html, field);

        html.push('>');
        html
    }

    fn render_radio(
        field: &FormField,
        opts: &[super::field::SelectOption],
        has_errors: bool,
        options: &FormRenderOptions,
    ) -> String {
        let mut html = String::with_capacity(256);
        let class = Self::build_input_class(field, has_errors, options);

        for (i, opt) in opts.iter().enumerate() {
            let opt_id = format!("{}_{}", field.effective_id(), i);
            html.push_str("    <div class=\"form-radio\">\n");
            html.push_str("      <input");
            Self::write_attr(&mut html, "type", "radio");
            Self::write_attr(&mut html, "name", &field.name);
            Self::write_attr(&mut html, "id", &opt_id);
            Self::write_attr(&mut html, "value", &opt.value);
            if !class.is_empty() {
                Self::write_attr(&mut html, "class", &class);
            }
            if field.value.as_ref() == Some(&opt.value) {
                html.push_str(" checked");
            }
            if opt.disabled {
                html.push_str(" disabled");
            }
            if field.flags.required && i == 0 {
                html.push_str(" required");
            }
            html.push_str(">\n");
            let _ = writeln!(
                html,
                "      <label for=\"{}\">{}</label>",
                Self::escape_attr(&opt_id),
                Self::escape_html(&opt.label)
            );
            html.push_str("    </div>\n");
        }

        html
    }

    fn build_input_class(field: &FormField, has_errors: bool, options: &FormRenderOptions) -> String {
        let mut classes = Vec::new();
        classes.push(options.input_class.as_str());

        if let Some(ref class) = field.class {
            classes.push(class.as_str());
        }
        if has_errors {
            classes.push(options.input_error_class.as_str());
        }

        classes.join(" ")
    }

    fn write_attr(html: &mut String, name: &str, value: &str) {
        html.push(' ');
        html.push_str(name);
        html.push_str("=\"");
        html.push_str(&Self::escape_attr(value));
        html.push('"');
    }

    fn write_htmx_form_attrs(html: &mut String, form: &FormBuilder<'_>) {
        if let Some(ref url) = form.htmx.get {
            Self::write_attr(html, "hx-get", url);
        }
        if let Some(ref url) = form.htmx.post {
            Self::write_attr(html, "hx-post", url);
        }
        if let Some(ref url) = form.htmx.put {
            Self::write_attr(html, "hx-put", url);
        }
        if let Some(ref url) = form.htmx.delete {
            Self::write_attr(html, "hx-delete", url);
        }
        if let Some(ref url) = form.htmx.patch {
            Self::write_attr(html, "hx-patch", url);
        }
        if let Some(ref selector) = form.htmx.target {
            Self::write_attr(html, "hx-target", selector);
        }
        if let Some(ref strategy) = form.htmx.swap {
            Self::write_attr(html, "hx-swap", strategy);
        }
        if let Some(ref trigger) = form.htmx.trigger {
            Self::write_attr(html, "hx-trigger", trigger);
        }
        if let Some(ref selector) = form.htmx.indicator {
            Self::write_attr(html, "hx-indicator", selector);
        }
        if let Some(ref url) = form.htmx.push_url {
            Self::write_attr(html, "hx-push-url", url);
        }
        if let Some(ref message) = form.htmx.confirm {
            Self::write_attr(html, "hx-confirm", message);
        }
        if let Some(ref selector) = form.htmx.disabled_elt {
            Self::write_attr(html, "hx-disabled-elt", selector);
        }
    }

    fn write_htmx_field_attrs(html: &mut String, field: &FormField) {
        if let Some(ref url) = field.htmx.get {
            Self::write_attr(html, "hx-get", url);
        }
        if let Some(ref url) = field.htmx.post {
            Self::write_attr(html, "hx-post", url);
        }
        if let Some(ref url) = field.htmx.put {
            Self::write_attr(html, "hx-put", url);
        }
        if let Some(ref url) = field.htmx.delete {
            Self::write_attr(html, "hx-delete", url);
        }
        if let Some(ref url) = field.htmx.patch {
            Self::write_attr(html, "hx-patch", url);
        }
        if let Some(ref selector) = field.htmx.target {
            Self::write_attr(html, "hx-target", selector);
        }
        if let Some(ref strategy) = field.htmx.swap {
            Self::write_attr(html, "hx-swap", strategy);
        }
        if let Some(ref trigger) = field.htmx.trigger {
            Self::write_attr(html, "hx-trigger", trigger);
        }
        if let Some(ref selector) = field.htmx.indicator {
            Self::write_attr(html, "hx-indicator", selector);
        }
        if let Some(ref vals) = field.htmx.vals {
            // Use single quotes for hx-vals since it contains JSON
            html.push_str(" hx-vals='");
            html.push_str(vals);
            html.push('\'');
        }
        if field.htmx.validate {
            Self::write_attr(html, "hx-validate", "true");
        }
    }

    /// Escape a string for use in HTML attribute values
    fn escape_attr(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// Escape a string for use in HTML content
    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::ValidationErrors;

    #[test]
    fn test_render_simple_form() {
        let form = FormBuilder::new("/test", "POST").submit("Submit");
        let html = FormRenderer::render(&form);

        assert!(html.contains(r#"action="/test""#));
        assert!(html.contains(r#"method="POST""#));
        assert!(html.contains("<button"));
        assert!(html.contains("Submit"));
    }

    #[test]
    fn test_render_with_csrf() {
        let form = FormBuilder::new("/test", "POST").csrf_token("abc123");
        let html = FormRenderer::render(&form);

        assert!(html.contains(r#"name="_csrf_token""#));
        assert!(html.contains(r#"value="abc123""#));
    }

    #[test]
    fn test_render_input_field() {
        let form = FormBuilder::new("/test", "POST")
            .field("email", InputType::Email)
            .label("Email")
            .placeholder("test@example.com")
            .required()
            .done();
        let html = FormRenderer::render(&form);

        assert!(html.contains(r#"type="email""#));
        assert!(html.contains(r#"name="email""#));
        assert!(html.contains(r#"placeholder="test@example.com""#));
        assert!(html.contains("required"));
        assert!(html.contains(r#"<label for="email""#));
    }

    #[test]
    fn test_render_with_errors() {
        let mut errors = ValidationErrors::new();
        errors.add("email", "is invalid");

        let form = FormBuilder::new("/test", "POST")
            .errors(&errors)
            .field("email", InputType::Email)
            .label("Email")
            .done();
        let html = FormRenderer::render(&form);

        assert!(html.contains("is invalid"));
        assert!(html.contains("form-error"));
        assert!(html.contains("form-input-error"));
    }

    #[test]
    fn test_render_textarea() {
        let form = FormBuilder::new("/test", "POST")
            .textarea("bio")
            .rows(5)
            .cols(40)
            .value("Hello world")
            .done();
        let html = FormRenderer::render(&form);

        assert!(html.contains("<textarea"));
        assert!(html.contains(r#"rows="5""#));
        assert!(html.contains(r#"cols="40""#));
        assert!(html.contains("Hello world"));
        assert!(html.contains("</textarea>"));
    }

    #[test]
    fn test_render_select() {
        let form = FormBuilder::new("/test", "POST")
            .select("country")
            .option("us", "United States")
            .option("ca", "Canada")
            .selected("us")
            .done();
        let html = FormRenderer::render(&form);

        assert!(html.contains("<select"));
        assert!(html.contains("<option"));
        assert!(html.contains(r#"value="us""#));
        assert!(html.contains("selected"));
        assert!(html.contains("United States"));
    }

    #[test]
    fn test_render_checkbox() {
        let form = FormBuilder::new("/test", "POST")
            .checkbox("terms")
            .label("I agree")
            .checked()
            .done();
        let html = FormRenderer::render(&form);

        assert!(html.contains(r#"type="checkbox""#));
        assert!(html.contains("checked"));
        assert!(html.contains("I agree"));
    }

    #[test]
    fn test_render_htmx_attrs() {
        let form = FormBuilder::new("/test", "POST")
            .htmx_post("/api/test")
            .htmx_target("#result")
            .htmx_swap("innerHTML");
        let html = FormRenderer::render(&form);

        assert!(html.contains(r#"hx-post="/api/test""#));
        assert!(html.contains(r##"hx-target="#result""##));
        assert!(html.contains(r#"hx-swap="innerHTML""#));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(FormRenderer::escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(FormRenderer::escape_html("a & b"), "a &amp; b");
    }

    #[test]
    fn test_escape_attr() {
        assert_eq!(FormRenderer::escape_attr("\"test\""), "&quot;test&quot;");
    }
}
