//! Form builder API with fluent interface
//!
//! Provides a builder pattern for constructing HTML forms with
//! HTMX integration and validation support.

use super::error::ValidationErrors;
use super::field::{FieldKind, FormField, InputType, SelectOption};
use super::render::FormRenderer;

/// Builder for constructing HTML forms
///
/// # Examples
///
/// ```rust
/// use acton_htmx::forms::{FormBuilder, InputType};
///
/// let html = FormBuilder::new("/login", "POST")
///     .id("login-form")
///     .csrf_token("abc123")
///     .field("email", InputType::Email)
///         .label("Email Address")
///         .required()
///         .placeholder("you@example.com")
///         .done()
///     .field("password", InputType::Password)
///         .label("Password")
///         .required()
///         .done()
///     .submit("Sign In")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct FormBuilder<'a> {
    /// Form action URL
    pub(crate) action: String,
    /// HTTP method
    pub(crate) method: String,
    /// Form ID
    pub(crate) id: Option<String>,
    /// CSS classes
    pub(crate) class: Option<String>,
    /// CSRF token
    pub(crate) csrf_token: Option<String>,
    /// Enctype for file uploads
    pub(crate) enctype: Option<String>,
    /// Form fields
    pub(crate) fields: Vec<FormField>,
    /// Submit button text
    pub(crate) submit_text: Option<String>,
    /// Submit button class
    pub(crate) submit_class: Option<String>,
    /// Validation errors
    pub(crate) errors: Option<&'a ValidationErrors>,
    /// HTMX attributes
    pub(crate) htmx: HtmxFormAttrs,
    /// Custom attributes
    pub(crate) custom_attrs: Vec<(String, String)>,
    /// Whether to include HTMX validation
    pub(crate) htmx_validate: bool,
    /// Disable browser validation
    pub(crate) novalidate: bool,
}

/// HTMX attributes for the form element
#[derive(Debug, Clone, Default)]
pub struct HtmxFormAttrs {
    /// hx-get URL
    pub get: Option<String>,
    /// hx-post URL
    pub post: Option<String>,
    /// hx-put URL
    pub put: Option<String>,
    /// hx-delete URL
    pub delete: Option<String>,
    /// hx-patch URL
    pub patch: Option<String>,
    /// hx-target selector
    pub target: Option<String>,
    /// hx-swap strategy
    pub swap: Option<String>,
    /// hx-trigger event
    pub trigger: Option<String>,
    /// hx-indicator selector
    pub indicator: Option<String>,
    /// hx-push-url
    pub push_url: Option<String>,
    /// hx-confirm message
    pub confirm: Option<String>,
    /// hx-disabled-elt selector
    pub disabled_elt: Option<String>,
}

impl<'a> FormBuilder<'a> {
    /// Create a new form builder with action and method
    #[must_use]
    pub fn new(action: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            method: method.into(),
            id: None,
            class: None,
            csrf_token: None,
            enctype: None,
            fields: Vec::new(),
            submit_text: None,
            submit_class: None,
            errors: None,
            htmx: HtmxFormAttrs::default(),
            custom_attrs: Vec::new(),
            htmx_validate: false,
            novalidate: false,
        }
    }

    /// Set the form ID
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the form CSS class
    #[must_use]
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.class = Some(class.into());
        self
    }

    /// Set the CSRF token
    #[must_use]
    pub fn csrf_token(mut self, token: impl Into<String>) -> Self {
        self.csrf_token = Some(token.into());
        self
    }

    /// Set the form enctype (for file uploads use "multipart/form-data")
    #[must_use]
    pub fn enctype(mut self, enctype: impl Into<String>) -> Self {
        self.enctype = Some(enctype.into());
        self
    }

    /// Enable multipart form data (for file uploads)
    #[must_use]
    pub fn multipart(mut self) -> Self {
        self.enctype = Some("multipart/form-data".into());
        self
    }

    /// Set validation errors to display
    #[must_use]
    pub fn errors(mut self, errors: &'a ValidationErrors) -> Self {
        self.errors = Some(errors);
        self
    }

    /// Set the submit button text
    #[must_use]
    pub fn submit(mut self, text: impl Into<String>) -> Self {
        self.submit_text = Some(text.into());
        self
    }

    /// Set the submit button CSS class
    #[must_use]
    pub fn submit_class(mut self, class: impl Into<String>) -> Self {
        self.submit_class = Some(class.into());
        self
    }

    /// Disable browser validation (add novalidate attribute)
    #[must_use]
    pub fn novalidate(mut self) -> Self {
        self.novalidate = true;
        self
    }

    /// Add a custom attribute
    #[must_use]
    pub fn attr(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_attrs.push((name.into(), value.into()));
        self
    }

    // =========================================================================
    // HTMX Attributes
    // =========================================================================

    /// Set hx-get attribute
    #[must_use]
    pub fn htmx_get(mut self, url: impl Into<String>) -> Self {
        self.htmx.get = Some(url.into());
        self
    }

    /// Set hx-post attribute
    #[must_use]
    pub fn htmx_post(mut self, url: impl Into<String>) -> Self {
        self.htmx.post = Some(url.into());
        self
    }

    /// Set hx-put attribute
    #[must_use]
    pub fn htmx_put(mut self, url: impl Into<String>) -> Self {
        self.htmx.put = Some(url.into());
        self
    }

    /// Set hx-delete attribute
    #[must_use]
    pub fn htmx_delete(mut self, url: impl Into<String>) -> Self {
        self.htmx.delete = Some(url.into());
        self
    }

    /// Set hx-patch attribute
    #[must_use]
    pub fn htmx_patch(mut self, url: impl Into<String>) -> Self {
        self.htmx.patch = Some(url.into());
        self
    }

    /// Set hx-target attribute
    #[must_use]
    pub fn htmx_target(mut self, selector: impl Into<String>) -> Self {
        self.htmx.target = Some(selector.into());
        self
    }

    /// Set hx-swap attribute
    #[must_use]
    pub fn htmx_swap(mut self, strategy: impl Into<String>) -> Self {
        self.htmx.swap = Some(strategy.into());
        self
    }

    /// Set hx-trigger attribute
    #[must_use]
    pub fn htmx_trigger(mut self, trigger: impl Into<String>) -> Self {
        self.htmx.trigger = Some(trigger.into());
        self
    }

    /// Set hx-indicator attribute
    #[must_use]
    pub fn htmx_indicator(mut self, selector: impl Into<String>) -> Self {
        self.htmx.indicator = Some(selector.into());
        self
    }

    /// Set hx-push-url attribute
    #[must_use]
    pub fn htmx_push_url(mut self, url: impl Into<String>) -> Self {
        self.htmx.push_url = Some(url.into());
        self
    }

    /// Set hx-confirm attribute
    #[must_use]
    pub fn htmx_confirm(mut self, message: impl Into<String>) -> Self {
        self.htmx.confirm = Some(message.into());
        self
    }

    /// Set hx-disabled-elt attribute
    #[must_use]
    pub fn htmx_disabled_elt(mut self, selector: impl Into<String>) -> Self {
        self.htmx.disabled_elt = Some(selector.into());
        self
    }

    /// Enable hx-validate
    #[must_use]
    pub fn htmx_validate(mut self) -> Self {
        self.htmx_validate = true;
        self
    }

    // =========================================================================
    // Field Builders
    // =========================================================================

    /// Add an input field and return a field builder
    #[must_use]
    pub fn field(self, name: impl Into<String>, input_type: InputType) -> FieldBuilder<'a> {
        FieldBuilder::new(self, FormField::input(name, input_type))
    }

    /// Add a textarea field and return a field builder
    #[must_use]
    pub fn textarea(self, name: impl Into<String>) -> TextareaBuilder<'a> {
        TextareaBuilder::new(self, FormField::textarea(name))
    }

    /// Add a select field and return a select builder
    #[must_use]
    pub fn select(self, name: impl Into<String>) -> SelectBuilder<'a> {
        SelectBuilder::new(self, FormField::select(name))
    }

    /// Add a checkbox field and return a checkbox builder
    #[must_use]
    pub fn checkbox(self, name: impl Into<String>) -> CheckboxBuilder<'a> {
        CheckboxBuilder::new(self, FormField::checkbox(name))
    }

    /// Add a hidden field
    #[must_use]
    pub fn hidden(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let mut field = FormField::input(name, InputType::Hidden);
        field.value = Some(value.into());
        self.fields.push(field);
        self
    }

    /// Add a pre-built field
    #[must_use]
    pub fn add_field(mut self, field: FormField) -> Self {
        self.fields.push(field);
        self
    }

    /// Build the form HTML
    #[must_use]
    pub fn build(self) -> String {
        FormRenderer::render(&self)
    }
}

// =============================================================================
// Field Builder
// =============================================================================

/// Builder for input fields
pub struct FieldBuilder<'a> {
    form: FormBuilder<'a>,
    field: FormField,
}

impl<'a> FieldBuilder<'a> {
    fn new(form: FormBuilder<'a>, field: FormField) -> Self {
        Self { form, field }
    }

    /// Set the field label
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.field.label = Some(label.into());
        self
    }

    /// Set placeholder text
    #[must_use]
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.field.placeholder = Some(placeholder.into());
        self
    }

    /// Set the current value
    #[must_use]
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.field.value = Some(value.into());
        self
    }

    /// Mark field as required
    #[must_use]
    pub fn required(mut self) -> Self {
        self.field.required = true;
        self
    }

    /// Mark field as disabled
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.field.disabled = true;
        self
    }

    /// Mark field as readonly
    #[must_use]
    pub fn readonly(mut self) -> Self {
        self.field.readonly = true;
        self
    }

    /// Enable autofocus
    #[must_use]
    pub fn autofocus(mut self) -> Self {
        self.field.autofocus = true;
        self
    }

    /// Set autocomplete attribute
    #[must_use]
    pub fn autocomplete(mut self, value: impl Into<String>) -> Self {
        self.field.autocomplete = Some(value.into());
        self
    }

    /// Set minimum length
    #[must_use]
    pub fn min_length(mut self, len: usize) -> Self {
        self.field.min_length = Some(len);
        self
    }

    /// Set maximum length
    #[must_use]
    pub fn max_length(mut self, len: usize) -> Self {
        self.field.max_length = Some(len);
        self
    }

    /// Set minimum value (for number inputs)
    #[must_use]
    pub fn min(mut self, value: impl Into<String>) -> Self {
        self.field.min = Some(value.into());
        self
    }

    /// Set maximum value (for number inputs)
    #[must_use]
    pub fn max(mut self, value: impl Into<String>) -> Self {
        self.field.max = Some(value.into());
        self
    }

    /// Set step value (for number inputs)
    #[must_use]
    pub fn step(mut self, value: impl Into<String>) -> Self {
        self.field.step = Some(value.into());
        self
    }

    /// Set validation pattern (regex)
    #[must_use]
    pub fn pattern(mut self, pattern: impl Into<String>) -> Self {
        self.field.pattern = Some(pattern.into());
        self
    }

    /// Set CSS class
    #[must_use]
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.field.class = Some(class.into());
        self
    }

    /// Set element ID (overrides default which is the field name)
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.field.id = Some(id.into());
        self
    }

    /// Set help text
    #[must_use]
    pub fn help(mut self, text: impl Into<String>) -> Self {
        self.field.help_text = Some(text.into());
        self
    }

    /// Add a data attribute
    #[must_use]
    pub fn data(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.field.data_attrs.push((name.into(), value.into()));
        self
    }

    /// Add a custom attribute
    #[must_use]
    pub fn attr(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.field.custom_attrs.push((name.into(), value.into()));
        self
    }

    // HTMX attributes for the field
    /// Set hx-get for this field
    #[must_use]
    pub fn htmx_get(mut self, url: impl Into<String>) -> Self {
        self.field.htmx.get = Some(url.into());
        self
    }

    /// Set hx-post for this field
    #[must_use]
    pub fn htmx_post(mut self, url: impl Into<String>) -> Self {
        self.field.htmx.post = Some(url.into());
        self
    }

    /// Set hx-target for this field
    #[must_use]
    pub fn htmx_target(mut self, selector: impl Into<String>) -> Self {
        self.field.htmx.target = Some(selector.into());
        self
    }

    /// Set hx-swap for this field
    #[must_use]
    pub fn htmx_swap(mut self, strategy: impl Into<String>) -> Self {
        self.field.htmx.swap = Some(strategy.into());
        self
    }

    /// Set hx-trigger for this field
    #[must_use]
    pub fn htmx_trigger(mut self, trigger: impl Into<String>) -> Self {
        self.field.htmx.trigger = Some(trigger.into());
        self
    }

    /// Finish building this field and return to form builder
    #[must_use]
    pub fn done(mut self) -> FormBuilder<'a> {
        self.form.fields.push(self.field);
        self.form
    }
}

// =============================================================================
// Textarea Builder
// =============================================================================

/// Builder for textarea fields
pub struct TextareaBuilder<'a> {
    form: FormBuilder<'a>,
    field: FormField,
}

impl<'a> TextareaBuilder<'a> {
    fn new(form: FormBuilder<'a>, field: FormField) -> Self {
        Self { form, field }
    }

    /// Set the field label
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.field.label = Some(label.into());
        self
    }

    /// Set placeholder text
    #[must_use]
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.field.placeholder = Some(placeholder.into());
        self
    }

    /// Set the current value
    #[must_use]
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.field.value = Some(value.into());
        self
    }

    /// Mark field as required
    #[must_use]
    pub fn required(mut self) -> Self {
        self.field.required = true;
        self
    }

    /// Mark field as disabled
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.field.disabled = true;
        self
    }

    /// Set number of rows
    #[must_use]
    pub fn rows(mut self, rows: u32) -> Self {
        if let FieldKind::Textarea {
            rows: ref mut r, ..
        } = self.field.kind
        {
            *r = Some(rows);
        }
        self
    }

    /// Set number of columns
    #[must_use]
    pub fn cols(mut self, cols: u32) -> Self {
        if let FieldKind::Textarea {
            cols: ref mut c, ..
        } = self.field.kind
        {
            *c = Some(cols);
        }
        self
    }

    /// Set CSS class
    #[must_use]
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.field.class = Some(class.into());
        self
    }

    /// Set element ID
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.field.id = Some(id.into());
        self
    }

    /// Set help text
    #[must_use]
    pub fn help(mut self, text: impl Into<String>) -> Self {
        self.field.help_text = Some(text.into());
        self
    }

    /// Finish building this field and return to form builder
    #[must_use]
    pub fn done(mut self) -> FormBuilder<'a> {
        self.form.fields.push(self.field);
        self.form
    }
}

// =============================================================================
// Select Builder
// =============================================================================

/// Builder for select fields
pub struct SelectBuilder<'a> {
    form: FormBuilder<'a>,
    field: FormField,
    selected_value: Option<String>,
}

impl<'a> SelectBuilder<'a> {
    fn new(form: FormBuilder<'a>, field: FormField) -> Self {
        Self {
            form,
            field,
            selected_value: None,
        }
    }

    /// Set the field label
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.field.label = Some(label.into());
        self
    }

    /// Add an option
    #[must_use]
    pub fn option(mut self, value: impl Into<String>, label: impl Into<String>) -> Self {
        if let FieldKind::Select { ref mut options, .. } = self.field.kind {
            options.push(SelectOption::new(value, label));
        }
        self
    }

    /// Add a disabled placeholder option
    #[must_use]
    pub fn placeholder_option(mut self, label: impl Into<String>) -> Self {
        if let FieldKind::Select { ref mut options, .. } = self.field.kind {
            options.insert(0, SelectOption::disabled("", label));
        }
        self
    }

    /// Set the selected value
    #[must_use]
    pub fn selected(mut self, value: impl Into<String>) -> Self {
        self.selected_value = Some(value.into());
        self
    }

    /// Mark field as required
    #[must_use]
    pub fn required(mut self) -> Self {
        self.field.required = true;
        self
    }

    /// Mark field as disabled
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.field.disabled = true;
        self
    }

    /// Allow multiple selections
    #[must_use]
    pub fn multiple(mut self) -> Self {
        if let FieldKind::Select {
            ref mut multiple, ..
        } = self.field.kind
        {
            *multiple = true;
        }
        self
    }

    /// Set CSS class
    #[must_use]
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.field.class = Some(class.into());
        self
    }

    /// Set element ID
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.field.id = Some(id.into());
        self
    }

    /// Finish building this field and return to form builder
    #[must_use]
    pub fn done(mut self) -> FormBuilder<'a> {
        // Store selected value in the field's value
        self.field.value = self.selected_value;
        self.form.fields.push(self.field);
        self.form
    }
}

// =============================================================================
// Checkbox Builder
// =============================================================================

/// Builder for checkbox fields
pub struct CheckboxBuilder<'a> {
    form: FormBuilder<'a>,
    field: FormField,
}

impl<'a> CheckboxBuilder<'a> {
    fn new(form: FormBuilder<'a>, field: FormField) -> Self {
        Self { form, field }
    }

    /// Set the field label
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.field.label = Some(label.into());
        self
    }

    /// Set the checkbox value (sent when checked)
    #[must_use]
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.field.value = Some(value.into());
        self
    }

    /// Set checkbox as checked
    #[must_use]
    pub fn checked(mut self) -> Self {
        if let FieldKind::Checkbox {
            ref mut checked, ..
        } = self.field.kind
        {
            *checked = true;
        }
        self
    }

    /// Mark field as required
    #[must_use]
    pub fn required(mut self) -> Self {
        self.field.required = true;
        self
    }

    /// Mark field as disabled
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.field.disabled = true;
        self
    }

    /// Set CSS class
    #[must_use]
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.field.class = Some(class.into());
        self
    }

    /// Set element ID
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.field.id = Some(id.into());
        self
    }

    /// Finish building this field and return to form builder
    #[must_use]
    pub fn done(mut self) -> FormBuilder<'a> {
        self.form.fields.push(self.field);
        self.form
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_builder_basic() {
        let form = FormBuilder::new("/test", "POST");
        assert_eq!(form.action, "/test");
        assert_eq!(form.method, "POST");
    }

    #[test]
    fn test_form_builder_with_id() {
        let form = FormBuilder::new("/test", "POST").id("my-form");
        assert_eq!(form.id.as_deref(), Some("my-form"));
    }

    #[test]
    fn test_form_builder_csrf() {
        let form = FormBuilder::new("/test", "POST").csrf_token("token123");
        assert_eq!(form.csrf_token.as_deref(), Some("token123"));
    }

    #[test]
    fn test_field_builder() {
        let form = FormBuilder::new("/test", "POST")
            .field("email", InputType::Email)
            .label("Email")
            .required()
            .placeholder("test@example.com")
            .done();

        assert_eq!(form.fields.len(), 1);
        let field = &form.fields[0];
        assert_eq!(field.name, "email");
        assert_eq!(field.label.as_deref(), Some("Email"));
        assert!(field.required);
        assert_eq!(field.placeholder.as_deref(), Some("test@example.com"));
    }

    #[test]
    fn test_textarea_builder() {
        let form = FormBuilder::new("/test", "POST")
            .textarea("content")
            .label("Content")
            .rows(10)
            .cols(50)
            .done();

        assert_eq!(form.fields.len(), 1);
        let field = &form.fields[0];
        assert!(matches!(
            field.kind,
            FieldKind::Textarea {
                rows: Some(10),
                cols: Some(50)
            }
        ));
    }

    #[test]
    fn test_select_builder() {
        let form = FormBuilder::new("/test", "POST")
            .select("country")
            .label("Country")
            .option("us", "United States")
            .option("ca", "Canada")
            .selected("us")
            .done();

        assert_eq!(form.fields.len(), 1);
        let field = &form.fields[0];
        assert!(field.is_select());
        assert_eq!(field.value.as_deref(), Some("us"));
    }

    #[test]
    fn test_checkbox_builder() {
        let form = FormBuilder::new("/test", "POST")
            .checkbox("terms")
            .label("I agree")
            .checked()
            .done();

        assert_eq!(form.fields.len(), 1);
        let field = &form.fields[0];
        assert!(matches!(field.kind, FieldKind::Checkbox { checked: true }));
    }

    #[test]
    fn test_hidden_field() {
        let form = FormBuilder::new("/test", "POST").hidden("user_id", "123");

        assert_eq!(form.fields.len(), 1);
        let field = &form.fields[0];
        assert!(matches!(field.kind, FieldKind::Input(InputType::Hidden)));
        assert_eq!(field.value.as_deref(), Some("123"));
    }

    #[test]
    fn test_htmx_form_attrs() {
        let form = FormBuilder::new("/test", "POST")
            .htmx_post("/api/test")
            .htmx_target("#result")
            .htmx_swap("innerHTML")
            .htmx_indicator("#spinner");

        assert_eq!(form.htmx.post.as_deref(), Some("/api/test"));
        assert_eq!(form.htmx.target.as_deref(), Some("#result"));
        assert_eq!(form.htmx.swap.as_deref(), Some("innerHTML"));
        assert_eq!(form.htmx.indicator.as_deref(), Some("#spinner"));
    }
}
