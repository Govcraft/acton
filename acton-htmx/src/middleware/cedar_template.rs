//! Template helpers for Cedar authorization
//!
//! This module provides template-friendly authorization helpers for Askama templates.
//! Since Askama doesn't support async function calls in templates, this module provides
//! a synchronous context struct that can be pre-populated in handlers.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use acton_htmx::middleware::cedar_template::AuthzContext;
//!
//! // In handler
//! async fn show_post(
//!     State(cedar): State<CedarAuthz>,
//!     Authenticated(user): Authenticated<User>,
//!     Path(id): Path<i64>,
//! ) -> Result<Response> {
//!     let post = Post::find_by_id(&state.db, id).await?;
//!
//!     // Build authorization context for template
//!     let authz = AuthzContext::builder(&cedar, &user)
//!         .can_update(&format!("/posts/{id}"))
//!         .can_delete(&format!("/posts/{id}"))
//!         .build()
//!         .await;
//!
//!     let template = PostShowTemplate { post, authz };
//!     Ok(template.into_response())
//! }
//! ```
//!
//! ```jinja2
//! <!-- In template: templates/posts/show.html -->
//! <h1>{{ post.title }}</h1>
//! <p>{{ post.content }}</p>
//!
//! {% if authz.can_update %}
//!   <a href="/posts/{{ post.id }}/edit" hx-get="/posts/{{ post.id }}/edit">
//!     Edit
//!   </a>
//! {% endif %}
//!
//! {% if authz.can_delete %}
//!   <button hx-delete="/posts/{{ post.id }}" hx-confirm="Delete this post?">
//!     Delete
//!   </button>
//! {% endif %}
//! ```

#[cfg(feature = "cedar")]
use std::collections::HashMap;

#[cfg(feature = "cedar")]
use super::cedar::CedarAuthz;

#[cfg(feature = "cedar")]
use crate::auth::user::User;

/// Authorization context for templates
///
/// This struct holds pre-computed authorization results that can be used in Askama templates.
/// Build this in your handler using the builder pattern, then pass it to your template.
///
/// # Example
///
/// ```rust,ignore
/// let authz = AuthzContext::builder(&cedar, &user)
///     .can_update("/posts/{id}")
///     .can_delete("/posts/{id}")
///     .can_create("/posts")
///     .build()
///     .await;
/// ```
#[cfg(feature = "cedar")]
#[allow(clippy::struct_excessive_bools)] // Template context, bools are appropriate
#[derive(Debug, Clone, Default)]
pub struct AuthzContext {
    /// Can the user update the resource?
    pub can_update: bool,

    /// Can the user delete the resource?
    pub can_delete: bool,

    /// Can the user create resources of this type?
    pub can_create: bool,

    /// Can the user read the resource?
    pub can_read: bool,

    /// Custom permission checks (key: permission name, value: allowed)
    pub permissions: HashMap<String, bool>,
}

/// Builder for AuthzContext
///
/// Use this to construct an `AuthzContext` with pre-computed authorization checks.
#[cfg(feature = "cedar")]
pub struct AuthzContextBuilder<'a> {
    cedar: &'a CedarAuthz,
    user: &'a User,
    update_path: Option<String>,
    delete_path: Option<String>,
    create_path: Option<String>,
    read_path: Option<String>,
    custom_checks: Vec<(String, String)>, // (name, action)
}

#[cfg(feature = "cedar")]
impl<'a> AuthzContextBuilder<'a> {
    /// Create a new builder
    const fn new(cedar: &'a CedarAuthz, user: &'a User) -> Self {
        Self {
            cedar,
            user,
            update_path: None,
            delete_path: None,
            create_path: None,
            read_path: None,
            custom_checks: Vec::new(),
        }
    }

    /// Check if user can update the resource at the given path
    #[must_use]
    pub fn can_update(mut self, path: impl Into<String>) -> Self {
        self.update_path = Some(path.into());
        self
    }

    /// Check if user can delete the resource at the given path
    #[must_use]
    pub fn can_delete(mut self, path: impl Into<String>) -> Self {
        self.delete_path = Some(path.into());
        self
    }

    /// Check if user can create resources at the given path
    #[must_use]
    pub fn can_create(mut self, path: impl Into<String>) -> Self {
        self.create_path = Some(path.into());
        self
    }

    /// Check if user can read the resource at the given path
    #[must_use]
    pub fn can_read(mut self, path: impl Into<String>) -> Self {
        self.read_path = Some(path.into());
        self
    }

    /// Add a custom permission check
    ///
    /// The result will be available in `context.permissions.get("name")`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let authz = AuthzContext::builder(&cedar, &user)
    ///     .check("publish", "POST /posts/{id}/publish")
    ///     .build()
    ///     .await;
    ///
    /// // In template:
    /// // {% if authz.permissions.publish %}
    /// //   <button>Publish</button>
    /// // {% endif %}
    /// ```
    #[must_use]
    pub fn check(mut self, name: impl Into<String>, action: impl Into<String>) -> Self {
        self.custom_checks.push((name.into(), action.into()));
        self
    }

    /// Build the AuthzContext by evaluating all authorization checks
    pub async fn build(self) -> AuthzContext {
        let mut context = AuthzContext::default();

        // Check update permission
        if let Some(path) = self.update_path {
            context.can_update = self.cedar.can_update(self.user, &path).await;
        }

        // Check delete permission
        if let Some(path) = self.delete_path {
            context.can_delete = self.cedar.can_delete(self.user, &path).await;
        }

        // Check create permission
        if let Some(path) = self.create_path {
            context.can_create = self.cedar.can_create(self.user, &path).await;
        }

        // Check read permission
        if let Some(path) = self.read_path {
            context.can_read = self.cedar.can_read(self.user, &path).await;
        }

        // Evaluate custom checks
        for (name, action) in self.custom_checks {
            let allowed = self.cedar.can_perform(self.user, &action, None).await;
            context.permissions.insert(name, allowed);
        }

        context
    }
}

#[cfg(feature = "cedar")]
impl AuthzContext {
    /// Create a builder for AuthzContext
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let authz = AuthzContext::builder(&cedar, &user)
    ///     .can_update("/posts/{id}")
    ///     .can_delete("/posts/{id}")
    ///     .build()
    ///     .await;
    /// ```
    #[must_use]
    pub const fn builder<'a>(cedar: &'a CedarAuthz, user: &'a User) -> AuthzContextBuilder<'a> {
        AuthzContextBuilder::new(cedar, user)
    }

    /// Create an empty context (all permissions denied)
    ///
    /// Useful for unauthenticated users or when Cedar is disabled.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            can_update: false,
            can_delete: false,
            can_create: false,
            can_read: false,
            permissions: HashMap::new(),
        }
    }

    /// Create a context with all permissions allowed
    ///
    /// Useful for testing or when bypassing authorization.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            can_update: true,
            can_delete: true,
            can_create: true,
            can_read: true,
            permissions: HashMap::new(),
        }
    }

    /// Check if user has a custom permission
    ///
    /// Returns `None` if the permission was not checked, `Some(bool)` otherwise.
    #[must_use]
    pub fn has_permission(&self, name: &str) -> Option<bool> {
        self.permissions.get(name).copied()
    }
}

#[cfg(test)]
#[cfg(feature = "cedar")]
mod tests {
    use super::*;

    #[test]
    fn test_empty_context() {
        let ctx = AuthzContext::empty();
        assert!(!ctx.can_update);
        assert!(!ctx.can_delete);
        assert!(!ctx.can_create);
        assert!(!ctx.can_read);
        assert!(ctx.permissions.is_empty());
    }

    #[test]
    fn test_allow_all_context() {
        let ctx = AuthzContext::allow_all();
        assert!(ctx.can_update);
        assert!(ctx.can_delete);
        assert!(ctx.can_create);
        assert!(ctx.can_read);
    }

    #[test]
    fn test_has_permission() {
        let mut ctx = AuthzContext::empty();
        assert!(ctx.has_permission("publish").is_none());

        ctx.permissions.insert("publish".to_string(), true);
        assert_eq!(ctx.has_permission("publish"), Some(true));

        ctx.permissions.insert("archive".to_string(), false);
        assert_eq!(ctx.has_permission("archive"), Some(false));
    }
}
