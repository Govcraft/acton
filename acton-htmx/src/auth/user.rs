//! User model and authentication types
//!
//! Provides the core user model with email validation, password hashing,
//! and database integration via SQLx.
//!
//! # Example
//!
//! ```rust,no_run
//! use acton_htmx::auth::user::{User, CreateUser, EmailAddress};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create a new user
//! let email = EmailAddress::parse("user@example.com")?;
//! let create_user = CreateUser {
//!     email,
//!     password: "secure-password".to_string(),
//! };
//!
//! // Hash password and save to database
//! // let user = User::create(create_user, &pool).await?;
//! # Ok(())
//! # }
//! ```

use crate::auth::password::{hash_password, verify_password, PasswordError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use thiserror::Error;
use validator::Validate;

/// User authentication errors
#[derive(Debug, Error)]
pub enum UserError {
    /// Invalid email address format
    #[error("Invalid email address: {0}")]
    InvalidEmail(String),

    /// Password too weak
    #[error("Password does not meet requirements: {0}")]
    WeakPassword(String),

    /// Validation failed
    #[error("Validation error: {0}")]
    ValidationFailed(String),

    /// Password hashing failed
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(#[from] PasswordError),

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// User not found
    #[error("User not found")]
    NotFound,

    /// Invalid credentials
    #[error("Invalid email or password")]
    InvalidCredentials,
}

/// Email address newtype for validation
///
/// Ensures all email addresses in the system are valid.
///
/// # Example
///
/// ```rust
/// use acton_htmx::auth::user::EmailAddress;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let email = EmailAddress::parse("user@example.com")?;
/// assert_eq!(email.as_str(), "user@example.com");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Parse and validate an email address
    ///
    /// # Errors
    ///
    /// Returns error if email format is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::auth::user::EmailAddress;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let email = EmailAddress::parse("user@example.com")?;
    /// assert_eq!(email.as_str(), "user@example.com");
    ///
    /// let invalid = EmailAddress::parse("not-an-email");
    /// assert!(invalid.is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(email: impl Into<String>) -> Result<Self, UserError> {
        // Validate with validator crate
        #[derive(Validate)]
        struct EmailValidator {
            #[validate(email)]
            email: String,
        }

        let email = email.into();

        // Basic email validation
        if !email.contains('@') || !email.contains('.') {
            return Err(UserError::InvalidEmail(
                "Email must contain @ and domain".to_string(),
            ));
        }

        let validator = EmailValidator {
            email: email.clone(),
        };

        validator.validate().map_err(|e| {
            UserError::ValidationFailed(format!("Invalid email format: {e}"))
        })?;

        Ok(Self(email.to_lowercase()))
    }

    /// Get the email as a string slice
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the inner string
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for EmailAddress {
    type Err = UserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// User model representing an authenticated user
///
/// This model is designed to be stored in a database and includes
/// all necessary fields for authentication, authorization, and session management.
///
/// # Security Considerations
///
/// - Password hash is stored, never the plaintext password
/// - Email addresses are normalized to lowercase
/// - Created/updated timestamps for audit trail
/// - Roles and permissions for authorization (Cedar policy integration)
///
/// # Database Schema
///
/// ```sql
/// CREATE TABLE users (
///     id BIGSERIAL PRIMARY KEY,
///     email TEXT NOT NULL UNIQUE,
///     password_hash TEXT NOT NULL,
///     roles TEXT[] NOT NULL DEFAULT '{"user"}',
///     permissions TEXT[] NOT NULL DEFAULT '{}',
///     email_verified BOOLEAN NOT NULL DEFAULT FALSE,
///     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
///     updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
/// );
///
/// CREATE INDEX idx_users_email ON users(email);
/// CREATE INDEX idx_users_roles ON users USING GIN(roles);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    /// User ID (primary key)
    pub id: i64,

    /// Email address (unique, normalized to lowercase)
    #[serde(serialize_with = "serialize_email")]
    #[serde(deserialize_with = "deserialize_email")]
    pub email: EmailAddress,

    /// Argon2id password hash (never exposed in responses)
    #[serde(skip_serializing)]
    pub password_hash: String,

    /// User roles for authorization
    /// Common roles: "user", "admin", "moderator"
    /// Used by Cedar policy engine for role-based access control (RBAC)
    pub roles: Vec<String>,

    /// User permissions for fine-grained authorization
    /// Format: "resource:action" (e.g., "posts:create", "posts:delete")
    /// Used by Cedar policy engine for attribute-based access control (ABAC)
    pub permissions: Vec<String>,

    /// Email verification status
    /// Required for certain actions (e.g., posting content)
    pub email_verified: bool,

    /// Timestamp when user was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when user was last updated
    pub updated_at: DateTime<Utc>,
}

// Custom serialization for EmailAddress in User struct
fn serialize_email<S>(email: &EmailAddress, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(email.as_str())
}

fn deserialize_email<'de, D>(deserializer: D) -> Result<EmailAddress, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    EmailAddress::parse(s).map_err(serde::de::Error::custom)
}

impl User {
    /// Verify a password against this user's hash
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// # Errors
    ///
    /// Returns error if verification fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use acton_htmx::auth::user::User;
    /// # async fn example(user: User) -> anyhow::Result<()> {
    /// if user.verify_password("user-password")? {
    ///     println!("Password correct!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_password(&self, password: &str) -> Result<bool, PasswordError> {
        verify_password(password, &self.password_hash)
    }

    /// Create a new user with hashed password
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Password hashing fails
    /// - Database operation fails
    /// - Email already exists (unique constraint)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use acton_htmx::auth::user::{User, CreateUser, EmailAddress};
    /// use sqlx::PgPool;
    ///
    /// # async fn example(pool: &PgPool) -> anyhow::Result<()> {
    /// let email = EmailAddress::parse("new@example.com")?;
    /// let create = CreateUser {
    ///     email,
    ///     password: "secure-password".to_string(),
    /// };
    ///
    /// let user = User::create(create, pool).await?;
    /// println!("Created user with ID: {}", user.id);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "postgres")]
    pub async fn create(
        data: CreateUser,
        pool: &sqlx::PgPool,
    ) -> Result<Self, UserError> {
        // Validate password strength
        validate_password_strength(&data.password)?;

        // Hash password
        let password_hash = hash_password(&data.password)?;

        // Insert into database with default role "user"
        let user = sqlx::query_as::<_, Self>(
            r"
            INSERT INTO users (email, password_hash, roles, permissions, email_verified)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, email, password_hash, roles, permissions, email_verified, created_at, updated_at
            ",
        )
        .bind(data.email.as_str())
        .bind(&password_hash)
        .bind(vec!["user".to_string()]) // Default role
        .bind(Vec::<String>::new()) // Empty permissions
        .bind(false) // Email not verified
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    /// Find a user by email
    ///
    /// # Errors
    ///
    /// Returns error if database operation fails or user not found
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use acton_htmx::auth::user::{User, EmailAddress};
    /// use sqlx::PgPool;
    ///
    /// # async fn example(pool: &PgPool) -> anyhow::Result<()> {
    /// let email = EmailAddress::parse("user@example.com")?;
    /// let user = User::find_by_email(&email, pool).await?;
    /// println!("Found user: {}", user.email);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "postgres")]
    pub async fn find_by_email(
        email: &EmailAddress,
        pool: &sqlx::PgPool,
    ) -> Result<Self, UserError> {
        let user = sqlx::query_as::<_, Self>(
            r"
            SELECT id, email, password_hash, roles, permissions, email_verified, created_at, updated_at
            FROM users
            WHERE email = $1
            ",
        )
        .bind(email.as_str())
        .fetch_optional(pool)
        .await?
        .ok_or(UserError::NotFound)?;

        Ok(user)
    }

    /// Find a user by ID
    ///
    /// # Errors
    ///
    /// Returns error if database operation fails or user not found
    #[cfg(feature = "postgres")]
    pub async fn find_by_id(id: i64, pool: &sqlx::PgPool) -> Result<Self, UserError> {
        let user = sqlx::query_as::<_, Self>(
            r"
            SELECT id, email, password_hash, roles, permissions, email_verified, created_at, updated_at
            FROM users
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(UserError::NotFound)?;

        Ok(user)
    }

    /// Authenticate a user with email and password
    ///
    /// # Errors
    ///
    /// Returns `UserError::InvalidCredentials` if:
    /// - Email not found
    /// - Password incorrect
    ///
    /// Returns other errors for database or verification failures
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use acton_htmx::auth::user::{User, EmailAddress};
    /// use sqlx::PgPool;
    ///
    /// # async fn example(pool: &PgPool) -> anyhow::Result<()> {
    /// let email = EmailAddress::parse("user@example.com")?;
    /// match User::authenticate(&email, "password", pool).await {
    ///     Ok(user) => println!("Authenticated: {}", user.email),
    ///     Err(_) => println!("Invalid credentials"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "postgres")]
    pub async fn authenticate(
        email: &EmailAddress,
        password: &str,
        pool: &sqlx::PgPool,
    ) -> Result<Self, UserError> {
        // Find user by email
        let user = Self::find_by_email(email, pool)
            .await
            .map_err(|_| UserError::InvalidCredentials)?;

        // Verify password
        let valid = user
            .verify_password(password)
            .map_err(|_| UserError::InvalidCredentials)?;

        if !valid {
            return Err(UserError::InvalidCredentials);
        }

        Ok(user)
    }
}

/// Data for creating a new user
///
/// # Example
///
/// ```rust
/// use acton_htmx::auth::user::{CreateUser, EmailAddress};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let create = CreateUser {
///     email: EmailAddress::parse("new@example.com")?,
///     password: "secure-password".to_string(),
/// };
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Validate)]
pub struct CreateUser {
    /// User's email address
    pub email: EmailAddress,

    /// Plaintext password (will be hashed before storage)
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

/// Validate password strength
///
/// # Requirements
///
/// - At least 8 characters
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one digit
///
/// # Errors
///
/// Returns error if password does not meet requirements
fn validate_password_strength(password: &str) -> Result<(), UserError> {
    if password.len() < 8 {
        return Err(UserError::WeakPassword(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let has_uppercase = password.chars().any(char::is_uppercase);
    let has_lowercase = password.chars().any(char::is_lowercase);
    let has_digit = password.chars().any(|c| c.is_ascii_digit());

    if !has_uppercase {
        return Err(UserError::WeakPassword(
            "Password must contain at least one uppercase letter".to_string(),
        ));
    }

    if !has_lowercase {
        return Err(UserError::WeakPassword(
            "Password must contain at least one lowercase letter".to_string(),
        ));
    }

    if !has_digit {
        return Err(UserError::WeakPassword(
            "Password must contain at least one digit".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_address_parsing() {
        // Valid emails
        assert!(EmailAddress::parse("user@example.com").is_ok());
        assert!(EmailAddress::parse("user.name@example.co.uk").is_ok());
        assert!(EmailAddress::parse("user+tag@example.com").is_ok());

        // Invalid emails
        assert!(EmailAddress::parse("not-an-email").is_err());
        assert!(EmailAddress::parse("@example.com").is_err());
        assert!(EmailAddress::parse("user@").is_err());
        assert!(EmailAddress::parse("user").is_err());
    }

    #[test]
    fn test_email_normalization() {
        let email1 = EmailAddress::parse("User@Example.COM").unwrap();
        let email2 = EmailAddress::parse("user@example.com").unwrap();

        assert_eq!(email1, email2);
        assert_eq!(email1.as_str(), "user@example.com");
    }

    #[test]
    fn test_password_strength_validation() {
        // Valid passwords
        assert!(validate_password_strength("SecurePass123").is_ok());
        assert!(validate_password_strength("MyP@ssw0rd").is_ok());

        // Too short
        assert!(validate_password_strength("Pass1").is_err());

        // Missing uppercase
        assert!(matches!(
            validate_password_strength("password123"),
            Err(UserError::WeakPassword(_))
        ));

        // Missing lowercase
        assert!(matches!(
            validate_password_strength("PASSWORD123"),
            Err(UserError::WeakPassword(_))
        ));

        // Missing digit
        assert!(matches!(
            validate_password_strength("PasswordOnly"),
            Err(UserError::WeakPassword(_))
        ));
    }

    #[test]
    fn test_user_password_verification() {
        let password = "TestPassword123";
        let hash = hash_password(password).expect("Failed to hash password");

        let user = User {
            id: 1,
            email: EmailAddress::parse("test@example.com").unwrap(),
            password_hash: hash,
            roles: vec!["user".to_string()],
            permissions: vec![],
            email_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(user.verify_password(password).expect("Verification failed"));
        assert!(!user
            .verify_password("wrong-password")
            .expect("Verification failed"));
    }

    #[test]
    fn test_email_serialization() {
        let email = EmailAddress::parse("test@example.com").unwrap();
        let json = serde_json::to_string(&email).expect("Failed to serialize");
        assert_eq!(json, r#""test@example.com""#);

        let deserialized: EmailAddress =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized, email);
    }

    #[test]
    fn test_user_serialization_skips_password() {
        let user = User {
            id: 1,
            email: EmailAddress::parse("test@example.com").unwrap(),
            password_hash: "hash".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec![],
            email_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&user).expect("Failed to serialize");
        assert!(!json.contains("password_hash"));
        assert!(json.contains("test@example.com"));
    }
}
