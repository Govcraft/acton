//! Authentication handlers (login, register, logout)
//!
//! This module provides basic handler scaffolds for authentication.
//! Full database integration and template rendering will be added in later phases.
//!
//! # Example
//!
//! ```rust,ignore
//! use acton_htmx::auth::handlers::{login_form, login_post, logout_post};
//! use axum::{Router, routing::{get, post}};
//!
//! # async fn example() {
//! let app = Router::new()
//!     .route("/login", get(login_form))
//!     .route("/login", post(login_post))
//!     .route("/logout", post(logout_post));
//! # }
//! ```

use crate::auth::{EmailAddress, FlashMessage, Session, UserError};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_htmx::HxRequest;
use serde::Deserialize;
use validator::Validate;

/// Login form data
#[derive(Debug, Deserialize, Validate)]
pub struct LoginForm {
    /// User's email address
    #[validate(email)]
    pub email: String,

    /// User's password (min 8 characters)
    #[validate(length(min = 8))]
    pub password: String,
}

/// Registration form data
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterForm {
    /// User's email address
    #[validate(email)]
    pub email: String,

    /// User's password (min 8 characters)
    #[validate(length(min = 8))]
    pub password: String,

    /// Password confirmation (must match password)
    #[validate(length(min = 8))]
    pub password_confirm: String,
}

/// GET /login - Display login form
///
/// # Example
///
/// ```rust,ignore
/// use acton_htmx::auth::handlers::login_form;
/// use axum::{Router, routing::get};
///
/// let app = Router::new().route("/login", get(login_form));
/// ```
pub async fn login_form(
    HxRequest(is_htmx): HxRequest,
) -> Response {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body>
    <h1>Login</h1>
    <form hx-post="/login" hx-target="body">
        <div>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required />
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required />
        </div>
        <button type="submit">Login</button>
    </form>
    <p><a href="/register">Don't have an account? Register</a></p>
</body>
</html>
    "#;

    if is_htmx {
        // For HTMX requests, return just the form
        Html(html).into_response()
    } else {
        Html(html).into_response()
    }
}

/// POST /login - Process login
///
/// # Example
///
/// ```rust,ignore
/// use acton_htmx::auth::handlers::login_post;
/// use axum::{Router, routing::post};
///
/// let app = Router::new().route("/login", post(login_post));
/// ```
pub async fn login_post(
    mut session: Session,
    Form(form): Form<LoginForm>,
) -> Result<Response, AuthHandlerError> {
    // Validate form
    form.validate()
        .map_err(|e| AuthHandlerError::ValidationFailed(e.to_string()))?;

    // Parse email
    let _email = EmailAddress::parse(&form.email)
        .map_err(|_| AuthHandlerError::InvalidCredentials)?;

    // TODO: Authenticate with database
    // For now, this is a placeholder that will be completed when database is integrated
    // let user = User::authenticate(&email, &form.password, &pool).await?;

    // For demonstration, simulate successful login for any valid email
    let user_id = 1; // Placeholder user ID

    // Set user ID in session
    session.set_user_id(Some(user_id));

    // Add success flash message
    session.add_flash(FlashMessage::success("Successfully logged in!"));

    // Redirect to dashboard/home
    Ok(Redirect::to("/").into_response())
}

/// GET /register - Display registration form
///
/// # Example
///
/// ```rust,ignore
/// use acton_htmx::auth::handlers::register_form;
/// use axum::{Router, routing::get};
///
/// let app = Router::new().route("/register", get(register_form));
/// ```
pub async fn register_form(
    HxRequest(is_htmx): HxRequest,
) -> Response {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body>
    <h1>Register</h1>
    <form hx-post="/register" hx-target="body">
        <div>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required />
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required minlength="8" />
        </div>
        <div>
            <label for="password_confirm">Confirm Password:</label>
            <input type="password" id="password_confirm" name="password_confirm" required minlength="8" />
        </div>
        <button type="submit">Register</button>
    </form>
    <p><a href="/login">Already have an account? Login</a></p>
</body>
</html>
    "#;

    if is_htmx {
        Html(html).into_response()
    } else {
        Html(html).into_response()
    }
}

/// POST /register - Process registration
///
/// # Example
///
/// ```rust,ignore
/// use acton_htmx::auth::handlers::register_post;
/// use axum::{Router, routing::post};
///
/// let app = Router::new().route("/register", post(register_post));
/// ```
pub async fn register_post(
    mut session: Session,
    Form(form): Form<RegisterForm>,
) -> Result<Response, AuthHandlerError> {
    // Validate form
    form.validate()
        .map_err(|e| AuthHandlerError::ValidationFailed(e.to_string()))?;

    // Parse email
    let _email = EmailAddress::parse(&form.email)
        .map_err(|_| AuthHandlerError::InvalidEmail)?;

    // Check password confirmation
    if form.password != form.password_confirm {
        return Err(AuthHandlerError::PasswordMismatch);
    }

    // TODO: Create user in database
    // For now, this is a placeholder
    // let create_user = CreateUser {
    //     email,
    //     password: form.password,
    // };
    // let user = User::create(create_user, &pool).await?;

    // For demonstration, simulate successful registration
    let user_id = 1; // Placeholder user ID

    // Set user ID in session (auto-login after registration)
    session.set_user_id(Some(user_id));

    // Add success flash message
    session.add_flash(FlashMessage::success("Account created successfully! Welcome!"));

    // Redirect to dashboard/home
    Ok(Redirect::to("/").into_response())
}

/// POST /logout - Clear session and logout
///
/// # Example
///
/// ```rust,ignore
/// use acton_htmx::auth::handlers::logout_post;
/// use axum::{Router, routing::post};
///
/// let app = Router::new().route("/logout", post(logout_post));
/// ```
pub async fn logout_post(
    mut session: Session,
) -> Response {
    // Clear user ID from session
    session.set_user_id(None);

    // Add info flash message
    session.add_flash(FlashMessage::info("You have been logged out."));

    // Redirect to home or login
    Redirect::to("/login").into_response()
}

/// Authentication handler errors
#[derive(Debug)]
pub enum AuthHandlerError {
    /// Form validation failed
    ValidationFailed(String),

    /// Invalid email format
    InvalidEmail,

    /// Password confirmation doesn't match
    PasswordMismatch,

    /// Invalid credentials
    InvalidCredentials,

    /// User error
    UserError(UserError),

    /// Database not configured
    DatabaseNotConfigured,
}

impl From<UserError> for AuthHandlerError {
    fn from(err: UserError) -> Self {
        Self::UserError(err)
    }
}

impl IntoResponse for AuthHandlerError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::ValidationFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::InvalidEmail => (StatusCode::BAD_REQUEST, "Invalid email format".to_string()),
            Self::PasswordMismatch => (
                StatusCode::BAD_REQUEST,
                "Passwords do not match".to_string(),
            ),
            Self::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password".to_string(),
            ),
            Self::UserError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::DatabaseNotConfigured => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database not configured".to_string(),
            ),
        };

        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_form_struct() {
        let form = LoginForm {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };
        assert!(form.validate().is_ok());
    }

    #[test]
    fn test_register_form_struct() {
        let form = RegisterForm {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            password_confirm: "password123".to_string(),
        };
        assert!(form.validate().is_ok());
    }

    #[test]
    fn test_invalid_email() {
        let form = LoginForm {
            email: "not-an-email".to_string(),
            password: "password123".to_string(),
        };
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_short_password() {
        let form = LoginForm {
            email: "test@example.com".to_string(),
            password: "short".to_string(),
        };
        assert!(form.validate().is_err());
    }
}
