//! Form validation error types
//!
//! Provides error types for form validation that integrate with
//! the `validator` crate and support HTMX partial updates.

use std::collections::HashMap;

/// A single validation error for a field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// The error message
    pub message: String,
    /// Optional error code for programmatic handling
    pub code: Option<String>,
}

impl FieldError {
    /// Create a new field error with just a message
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: None,
        }
    }

    /// Create a field error with a message and code
    #[must_use]
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: Some(code.into()),
        }
    }
}

impl std::fmt::Display for FieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Collection of validation errors keyed by field name
///
/// # Examples
///
/// ```rust
/// use acton_htmx::forms::ValidationErrors;
///
/// let mut errors = ValidationErrors::new();
/// errors.add("email", "is required");
/// errors.add("email", "must be a valid email address");
/// errors.add("password", "must be at least 8 characters");
///
/// assert!(errors.has_errors());
/// assert_eq!(errors.for_field("email").len(), 2);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ValidationErrors {
    errors: HashMap<String, Vec<FieldError>>,
}

impl ValidationErrors {
    /// Create a new empty error collection
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an error for a field
    pub fn add(&mut self, field: impl Into<String>, message: impl Into<String>) {
        let field = field.into();
        self.errors
            .entry(field)
            .or_default()
            .push(FieldError::new(message));
    }

    /// Add an error with a code for a field
    pub fn add_with_code(
        &mut self,
        field: impl Into<String>,
        message: impl Into<String>,
        code: impl Into<String>,
    ) {
        let field = field.into();
        self.errors
            .entry(field)
            .or_default()
            .push(FieldError::with_code(message, code));
    }

    /// Check if there are any errors
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Check if a specific field has errors
    #[must_use]
    pub fn has_field_error(&self, field: &str) -> bool {
        self.errors.contains_key(field)
    }

    /// Get all errors for a specific field
    #[must_use]
    pub fn for_field(&self, field: &str) -> &[FieldError] {
        self.errors.get(field).map_or(&[], Vec::as_slice)
    }

    /// Get all field names that have errors
    #[must_use]
    pub fn fields_with_errors(&self) -> Vec<&str> {
        self.errors.keys().map(String::as_str).collect()
    }

    /// Get the total number of errors
    #[must_use]
    pub fn count(&self) -> usize {
        self.errors.values().map(Vec::len).sum()
    }

    /// Clear all errors
    pub fn clear(&mut self) {
        self.errors.clear();
    }

    /// Merge errors from another collection
    pub fn merge(&mut self, other: &Self) {
        for (field, errors) in &other.errors {
            self.errors
                .entry(field.clone())
                .or_default()
                .extend(errors.iter().cloned());
        }
    }

    /// Iterate over all errors
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[FieldError])> {
        self.errors
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
    }
}

/// Convert from validator crate's `ValidationErrors`
///
/// The validator crate is always available as a workspace dependency.
impl From<validator::ValidationErrors> for ValidationErrors {
    fn from(errors: validator::ValidationErrors) -> Self {
        let mut result = Self::new();
        for (field, field_errors) in errors.field_errors() {
            for error in field_errors {
                let message = error
                    .message
                    .as_ref()
                    .map_or_else(|| error.code.to_string(), ToString::to_string);
                result.add_with_code(field.to_string(), message, error.code.to_string());
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_error() {
        let error = FieldError::new("is required");
        assert_eq!(error.message, "is required");
        assert!(error.code.is_none());
    }

    #[test]
    fn test_field_error_with_code() {
        let error = FieldError::with_code("is required", "required");
        assert_eq!(error.message, "is required");
        assert_eq!(error.code.as_deref(), Some("required"));
    }

    #[test]
    fn test_validation_errors_new() {
        let errors = ValidationErrors::new();
        assert!(!errors.has_errors());
        assert_eq!(errors.count(), 0);
    }

    #[test]
    fn test_validation_errors_add() {
        let mut errors = ValidationErrors::new();
        errors.add("email", "is required");
        errors.add("email", "is invalid");

        assert!(errors.has_errors());
        assert!(errors.has_field_error("email"));
        assert!(!errors.has_field_error("password"));
        assert_eq!(errors.for_field("email").len(), 2);
        assert_eq!(errors.count(), 2);
    }

    #[test]
    fn test_validation_errors_merge() {
        let mut errors1 = ValidationErrors::new();
        errors1.add("email", "is required");

        let mut errors2 = ValidationErrors::new();
        errors2.add("password", "too short");
        errors2.add("email", "is invalid");

        errors1.merge(&errors2);

        assert_eq!(errors1.for_field("email").len(), 2);
        assert_eq!(errors1.for_field("password").len(), 1);
        assert_eq!(errors1.count(), 3);
    }

    #[test]
    fn test_validation_errors_clear() {
        let mut errors = ValidationErrors::new();
        errors.add("email", "is required");
        assert!(errors.has_errors());

        errors.clear();
        assert!(!errors.has_errors());
    }

    #[test]
    fn test_fields_with_errors() {
        let mut errors = ValidationErrors::new();
        errors.add("email", "is required");
        errors.add("password", "too short");

        let fields = errors.fields_with_errors();
        assert_eq!(fields.len(), 2);
        assert!(fields.contains(&"email"));
        assert!(fields.contains(&"password"));
    }
}
