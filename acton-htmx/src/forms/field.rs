//! Form field types and input configuration
//!
//! Defines the various input types and field configurations
//! supported by the form builder.

/// HTML input types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputType {
    /// Text input (default)
    #[default]
    Text,
    /// Email input with validation
    Email,
    /// Password input (masked)
    Password,
    /// Number input
    Number,
    /// Telephone input
    Tel,
    /// URL input
    Url,
    /// Search input
    Search,
    /// Date input
    Date,
    /// Time input
    Time,
    /// Date and time input
    DateTimeLocal,
    /// Month input
    Month,
    /// Week input
    Week,
    /// Color picker
    Color,
    /// Range slider
    Range,
    /// Hidden input
    Hidden,
    /// File upload
    File,
}

impl InputType {
    /// Get the HTML type attribute value
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Email => "email",
            Self::Password => "password",
            Self::Number => "number",
            Self::Tel => "tel",
            Self::Url => "url",
            Self::Search => "search",
            Self::Date => "date",
            Self::Time => "time",
            Self::DateTimeLocal => "datetime-local",
            Self::Month => "month",
            Self::Week => "week",
            Self::Color => "color",
            Self::Range => "range",
            Self::Hidden => "hidden",
            Self::File => "file",
        }
    }
}

impl std::fmt::Display for InputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Option for select dropdowns
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectOption {
    /// Value attribute
    pub value: String,
    /// Display text
    pub label: String,
    /// Whether this option is disabled
    pub disabled: bool,
}

impl SelectOption {
    /// Create a new select option
    #[must_use]
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            disabled: false,
        }
    }

    /// Create a disabled option (useful for placeholder)
    #[must_use]
    pub fn disabled(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            disabled: true,
        }
    }
}

/// Kind of form field
#[derive(Debug, Clone)]
pub enum FieldKind {
    /// Standard input field
    Input(InputType),
    /// Textarea for multi-line text
    Textarea {
        /// Number of visible text lines
        rows: Option<u32>,
        /// Visible width in average character widths
        cols: Option<u32>,
    },
    /// Select dropdown
    Select {
        /// Available options
        options: Vec<SelectOption>,
        /// Allow multiple selections
        multiple: bool,
    },
    /// Checkbox
    Checkbox {
        /// Whether checkbox is checked
        checked: bool,
    },
    /// Radio button group
    Radio {
        /// Available options
        options: Vec<SelectOption>,
    },
}

impl Default for FieldKind {
    fn default() -> Self {
        Self::Input(InputType::default())
    }
}

/// A form field with all its attributes
#[derive(Debug, Clone)]
pub struct FormField {
    /// Field name (used for form submission)
    pub name: String,
    /// Field kind (input, textarea, select, etc.)
    pub kind: FieldKind,
    /// Label text
    pub label: Option<String>,
    /// Placeholder text
    pub placeholder: Option<String>,
    /// Current value
    pub value: Option<String>,
    /// Whether field is required
    pub required: bool,
    /// Whether field is disabled
    pub disabled: bool,
    /// Whether field is read-only
    pub readonly: bool,
    /// Autofocus this field
    pub autofocus: bool,
    /// Autocomplete attribute
    pub autocomplete: Option<String>,
    /// Minimum length for text inputs
    pub min_length: Option<usize>,
    /// Maximum length for text inputs
    pub max_length: Option<usize>,
    /// Minimum value for number inputs
    pub min: Option<String>,
    /// Maximum value for number inputs
    pub max: Option<String>,
    /// Step value for number inputs
    pub step: Option<String>,
    /// Pattern for validation (regex)
    pub pattern: Option<String>,
    /// CSS class(es)
    pub class: Option<String>,
    /// Element ID (defaults to name if not set)
    pub id: Option<String>,
    /// Help text shown below the field
    pub help_text: Option<String>,
    /// HTMX attributes
    pub htmx: HtmxFieldAttrs,
    /// Custom data attributes
    pub data_attrs: Vec<(String, String)>,
    /// Custom attributes
    pub custom_attrs: Vec<(String, String)>,
}

impl FormField {
    /// Create a new input field
    #[must_use]
    pub fn input(name: impl Into<String>, input_type: InputType) -> Self {
        Self::new(name, FieldKind::Input(input_type))
    }

    /// Create a new textarea field
    #[must_use]
    pub fn textarea(name: impl Into<String>) -> Self {
        Self::new(
            name,
            FieldKind::Textarea {
                rows: None,
                cols: None,
            },
        )
    }

    /// Create a new select field
    #[must_use]
    pub fn select(name: impl Into<String>) -> Self {
        Self::new(
            name,
            FieldKind::Select {
                options: Vec::new(),
                multiple: false,
            },
        )
    }

    /// Create a new checkbox field
    #[must_use]
    pub fn checkbox(name: impl Into<String>) -> Self {
        Self::new(name, FieldKind::Checkbox { checked: false })
    }

    /// Create a new radio button group
    #[must_use]
    pub fn radio(name: impl Into<String>) -> Self {
        Self::new(name, FieldKind::Radio { options: Vec::new() })
    }

    fn new(name: impl Into<String>, kind: FieldKind) -> Self {
        Self {
            name: name.into(),
            kind,
            label: None,
            placeholder: None,
            value: None,
            required: false,
            disabled: false,
            readonly: false,
            autofocus: false,
            autocomplete: None,
            min_length: None,
            max_length: None,
            min: None,
            max: None,
            step: None,
            pattern: None,
            class: None,
            id: None,
            help_text: None,
            htmx: HtmxFieldAttrs::default(),
            data_attrs: Vec::new(),
            custom_attrs: Vec::new(),
        }
    }

    /// Get the effective ID (custom ID or field name)
    #[must_use]
    pub fn effective_id(&self) -> &str {
        self.id.as_deref().unwrap_or(&self.name)
    }

    /// Check if this field is an input type
    #[must_use]
    pub fn is_input(&self) -> bool {
        matches!(self.kind, FieldKind::Input(_))
    }

    /// Check if this field is a textarea
    #[must_use]
    pub fn is_textarea(&self) -> bool {
        matches!(self.kind, FieldKind::Textarea { .. })
    }

    /// Check if this field is a select
    #[must_use]
    pub fn is_select(&self) -> bool {
        matches!(self.kind, FieldKind::Select { .. })
    }

    /// Check if this field is a checkbox
    #[must_use]
    pub fn is_checkbox(&self) -> bool {
        matches!(self.kind, FieldKind::Checkbox { .. })
    }

    /// Check if this field is a radio group
    #[must_use]
    pub fn is_radio(&self) -> bool {
        matches!(self.kind, FieldKind::Radio { .. })
    }
}

/// HTMX-specific attributes for form fields
#[derive(Debug, Clone, Default)]
pub struct HtmxFieldAttrs {
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
    /// hx-vals JSON
    pub vals: Option<String>,
    /// hx-validate
    pub validate: bool,
}

impl HtmxFieldAttrs {
    /// Check if any HTMX attributes are set
    #[must_use]
    pub fn has_any(&self) -> bool {
        self.get.is_some()
            || self.post.is_some()
            || self.put.is_some()
            || self.delete.is_some()
            || self.patch.is_some()
            || self.target.is_some()
            || self.swap.is_some()
            || self.trigger.is_some()
            || self.indicator.is_some()
            || self.vals.is_some()
            || self.validate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_type_as_str() {
        assert_eq!(InputType::Email.as_str(), "email");
        assert_eq!(InputType::Password.as_str(), "password");
        assert_eq!(InputType::DateTimeLocal.as_str(), "datetime-local");
    }

    #[test]
    fn test_select_option() {
        let opt = SelectOption::new("us", "United States");
        assert_eq!(opt.value, "us");
        assert_eq!(opt.label, "United States");
        assert!(!opt.disabled);
    }

    #[test]
    fn test_select_option_disabled() {
        let opt = SelectOption::disabled("", "Select a country...");
        assert!(opt.disabled);
    }

    #[test]
    fn test_form_field_input() {
        let field = FormField::input("email", InputType::Email);
        assert_eq!(field.name, "email");
        assert!(field.is_input());
        assert!(!field.is_textarea());
    }

    #[test]
    fn test_form_field_effective_id() {
        let mut field = FormField::input("email", InputType::Email);
        assert_eq!(field.effective_id(), "email");

        field.id = Some("custom-email-id".into());
        assert_eq!(field.effective_id(), "custom-email-id");
    }

    #[test]
    fn test_htmx_field_attrs() {
        let attrs = HtmxFieldAttrs::default();
        assert!(!attrs.has_any());

        let attrs_with_get = HtmxFieldAttrs {
            get: Some("/search".into()),
            ..Default::default()
        };
        assert!(attrs_with_get.has_any());
    }
}
