//! Password hashing and verification using Argon2id
//!
//! This module provides secure password hashing using the Argon2id algorithm,
//! which is resistant to both side-channel and GPU-based attacks.
//!
//! # Security Considerations
//!
//! - Uses Argon2id (hybrid mode) for balanced security
//! - Configurable memory cost, iterations, and parallelism
//! - Cryptographically secure random salt generation
//! - Constant-time password verification
//! - Follows OWASP recommendations for password storage
//!
//! # Example
//!
//! ```rust
//! use acton_htmx::auth::password::{PasswordHasher, hash_password, verify_password};
//!
//! # fn example() -> anyhow::Result<()> {
//! // Hash a password with default parameters
//! let password = "correct-horse-battery-staple";
//! let hash = hash_password(password)?;
//!
//! // Verify password
//! assert!(verify_password(password, &hash)?);
//! assert!(!verify_password("wrong-password", &hash)?);
//!
//! // Use custom parameters
//! let hasher = PasswordHasher::builder()
//!     .memory_cost(32 * 1024) // 32 MB
//!     .iterations(3)
//!     .parallelism(2)
//!     .build()?;
//!
//! let hash = hasher.hash(password)?;
//! assert!(hasher.verify(password, &hash)?);
//! # Ok(())
//! # }
//! ```

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Password hashing errors
#[derive(Debug, Error)]
pub enum PasswordError {
    /// Failed to hash password
    #[error("Failed to hash password: {0}")]
    HashingFailed(String),

    /// Failed to verify password
    #[error("Failed to verify password: {0}")]
    VerificationFailed(String),

    /// Invalid password hash format
    #[error("Invalid password hash format: {0}")]
    InvalidHash(String),

    /// Invalid parameters for Argon2
    #[error("Invalid Argon2 parameters: {0}")]
    InvalidParams(String),
}

/// Configuration for Argon2id password hashing
///
/// These parameters control the computational cost of hashing and verification.
/// Higher values provide better security but require more resources.
///
/// # Defaults
///
/// The defaults follow OWASP recommendations for server-side password hashing:
/// - Memory cost: 19456 KiB (~19 MB)
/// - Iterations: 2
/// - Parallelism: 1
/// - Output length: 32 bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordHashConfig {
    /// Memory cost in KiB (default: 19456 = ~19 MB)
    ///
    /// Higher values make attacks more expensive. OWASP recommends at least 12 MiB.
    pub memory_cost: u32,

    /// Number of iterations (default: 2)
    ///
    /// Higher values increase computation time. OWASP recommends at least 2.
    pub iterations: u32,

    /// Degree of parallelism (default: 1)
    ///
    /// Number of parallel threads to use. Typically set to available CPU cores.
    pub parallelism: u32,

    /// Output hash length in bytes (default: 32)
    pub output_length: usize,
}

impl Default for PasswordHashConfig {
    fn default() -> Self {
        Self {
            memory_cost: 19456, // 19 MB (OWASP recommended minimum)
            iterations: 2,      // OWASP recommended minimum
            parallelism: 1,     // Single-threaded by default
            output_length: 32,  // 256 bits
        }
    }
}

/// Password hasher using Argon2id
///
/// Provides secure password hashing with configurable parameters.
/// All methods are constant-time to prevent timing attacks.
#[derive(Clone, Default)]
pub struct PasswordHasher {
    config: PasswordHashConfig,
}

impl PasswordHasher {
    /// Create a new password hasher with default parameters
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::auth::password::PasswordHasher;
    ///
    /// let hasher = PasswordHasher::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a password hasher with custom configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::auth::password::{PasswordHasher, PasswordHashConfig};
    ///
    /// let config = PasswordHashConfig {
    ///     memory_cost: 32 * 1024, // 32 MB
    ///     iterations: 3,
    ///     parallelism: 2,
    ///     output_length: 32,
    /// };
    ///
    /// let hasher = PasswordHasher::with_config(config);
    /// ```
    #[must_use]
    pub const fn with_config(config: PasswordHashConfig) -> Self {
        Self { config }
    }

    /// Create a builder for configuring password hasher parameters
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::auth::password::PasswordHasher;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let hasher = PasswordHasher::builder()
    ///     .memory_cost(32 * 1024)
    ///     .iterations(3)
    ///     .parallelism(2)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn builder() -> PasswordHasherBuilder {
        PasswordHasherBuilder::new()
    }

    /// Hash a password using Argon2id
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Random number generation fails
    /// - Parameters are invalid
    /// - Hashing operation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::auth::password::PasswordHasher;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let hasher = PasswordHasher::new();
    /// let hash = hasher.hash("my-secret-password")?;
    /// println!("Password hash: {}", hash);
    /// # Ok(())
    /// # }
    /// ```
    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        // Generate cryptographically secure random salt
        let salt = SaltString::generate(&mut OsRng);

        // Configure Argon2 parameters
        let params = Params::new(
            self.config.memory_cost,
            self.config.iterations,
            self.config.parallelism,
            Some(self.config.output_length),
        )
        .map_err(|e| PasswordError::InvalidParams(e.to_string()))?;

        // Create Argon2 instance with parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id, // Hybrid mode: resistant to both side-channel and GPU attacks
            Version::V0x13,              // Latest version
            params,
        );

        // Hash the password
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| PasswordError::HashingFailed(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    /// Verify a password against a hash
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Hash format is invalid
    /// - Verification operation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::auth::password::PasswordHasher;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let hasher = PasswordHasher::new();
    /// let hash = hasher.hash("correct-password")?;
    ///
    /// assert!(hasher.verify("correct-password", &hash)?);
    /// assert!(!hasher.verify("wrong-password", &hash)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, PasswordError> {
        // Parse the PHC string (Password Hashing Competition format)
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| PasswordError::InvalidHash(e.to_string()))?;

        // Create Argon2 instance (parameters are read from the hash string)
        let argon2 = Argon2::default();

        // Verify password (constant-time comparison)
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false), // Wrong password
            Err(e) => Err(PasswordError::VerificationFailed(e.to_string())),
        }
    }

    /// Get the current configuration
    #[must_use]
    pub const fn config(&self) -> &PasswordHashConfig {
        &self.config
    }
}

/// Builder for `PasswordHasher`
///
/// Provides a fluent interface for configuring password hashing parameters.
#[derive(Default)]
pub struct PasswordHasherBuilder {
    config: PasswordHashConfig,
}

impl PasswordHasherBuilder {
    /// Create a new builder with default parameters
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set memory cost in KiB
    ///
    /// OWASP recommends at least 12 MiB (12288 KiB).
    #[must_use]
    pub const fn memory_cost(mut self, cost: u32) -> Self {
        self.config.memory_cost = cost;
        self
    }

    /// Set number of iterations
    ///
    /// OWASP recommends at least 2.
    #[must_use]
    pub const fn iterations(mut self, iterations: u32) -> Self {
        self.config.iterations = iterations;
        self
    }

    /// Set degree of parallelism
    ///
    /// Typically set to the number of available CPU cores.
    #[must_use]
    pub const fn parallelism(mut self, parallelism: u32) -> Self {
        self.config.parallelism = parallelism;
        self
    }

    /// Set output hash length in bytes
    #[must_use]
    pub const fn output_length(mut self, length: usize) -> Self {
        self.config.output_length = length;
        self
    }

    /// Build the password hasher
    ///
    /// # Errors
    ///
    /// Returns error if parameters are invalid
    pub fn build(self) -> Result<PasswordHasher, PasswordError> {
        // Validate parameters by attempting to create Params
        Params::new(
            self.config.memory_cost,
            self.config.iterations,
            self.config.parallelism,
            Some(self.config.output_length),
        )
        .map_err(|e| PasswordError::InvalidParams(e.to_string()))?;

        Ok(PasswordHasher {
            config: self.config,
        })
    }
}

/// Hash a password using default Argon2id parameters
///
/// This is a convenience function that uses `PasswordHasher::default()`.
///
/// # Errors
///
/// Returns error if hashing fails
///
/// # Example
///
/// ```rust
/// use acton_htmx::auth::password::hash_password;
///
/// # fn example() -> anyhow::Result<()> {
/// let hash = hash_password("my-secret-password")?;
/// println!("Password hash: {}", hash);
/// # Ok(())
/// # }
/// ```
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    PasswordHasher::default().hash(password)
}

/// Verify a password against a hash using default parameters
///
/// This is a convenience function that uses `PasswordHasher::default()`.
///
/// # Errors
///
/// Returns error if verification fails
///
/// # Example
///
/// ```rust
/// use acton_htmx::auth::password::{hash_password, verify_password};
///
/// # fn example() -> anyhow::Result<()> {
/// let hash = hash_password("correct-password")?;
///
/// assert!(verify_password("correct-password", &hash)?);
/// assert!(!verify_password("wrong-password", &hash)?);
/// # Ok(())
/// # }
/// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    PasswordHasher::default().verify(password, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let hasher = PasswordHasher::new();
        let password = "test-password-123";

        let hash = hasher.hash(password).expect("Failed to hash password");

        // Hash should be in PHC string format
        assert!(hash.starts_with("$argon2id$"));

        // Should verify correctly
        assert!(hasher
            .verify(password, &hash)
            .expect("Failed to verify password"));

        // Wrong password should fail
        assert!(!hasher
            .verify("wrong-password", &hash)
            .expect("Failed to verify wrong password"));
    }

    #[test]
    fn test_convenience_functions() {
        let password = "test-password-456";
        let hash = hash_password(password).expect("Failed to hash");

        assert!(verify_password(password, &hash).expect("Failed to verify"));
        assert!(!verify_password("wrong", &hash).expect("Failed to verify wrong"));
    }

    #[test]
    fn test_custom_parameters() {
        let hasher = PasswordHasher::builder()
            .memory_cost(16 * 1024) // 16 MB
            .iterations(3)
            .parallelism(2)
            .build()
            .expect("Failed to build hasher");

        let password = "custom-params-test";
        let hash = hasher.hash(password).expect("Failed to hash");

        assert!(hasher.verify(password, &hash).expect("Failed to verify"));
    }

    #[test]
    fn test_invalid_hash_format() {
        let hasher = PasswordHasher::new();
        let result = hasher.verify("password", "invalid-hash");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasswordError::InvalidHash(_)));
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let hasher = PasswordHasher::new();
        let password = "same-password";

        let hash1 = hasher.hash(password).expect("Failed to hash 1");
        let hash2 = hasher.hash(password).expect("Failed to hash 2");

        // Different salts = different hashes
        assert_ne!(hash1, hash2);

        // Both should verify
        assert!(hasher.verify(password, &hash1).expect("Failed to verify 1"));
        assert!(hasher.verify(password, &hash2).expect("Failed to verify 2"));
    }

    #[test]
    fn test_default_config() {
        let config = PasswordHashConfig::default();
        assert_eq!(config.memory_cost, 19456); // ~19 MB
        assert_eq!(config.iterations, 2);
        assert_eq!(config.parallelism, 1);
        assert_eq!(config.output_length, 32);
    }

    #[test]
    fn test_builder_pattern() {
        let hasher = PasswordHasher::builder()
            .memory_cost(20000)
            .iterations(4)
            .parallelism(4)
            .output_length(64)
            .build()
            .expect("Failed to build");

        assert_eq!(hasher.config().memory_cost, 20000);
        assert_eq!(hasher.config().iterations, 4);
        assert_eq!(hasher.config().parallelism, 4);
        assert_eq!(hasher.config().output_length, 64);
    }

    #[test]
    fn test_invalid_parameters() {
        // Memory cost too low
        let result = PasswordHasher::builder().memory_cost(1).build();
        assert!(result.is_err());

        // Iterations too low
        let result = PasswordHasher::builder().iterations(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_verification() {
        // This test ensures the API supports constant-time verification,
        // though the actual constant-time behavior is provided by the argon2 crate
        let hasher = PasswordHasher::new();
        let hash = hasher.hash("test").expect("Failed to hash");

        // Both operations should complete without revealing timing info
        let _ = hasher.verify("test", &hash);
        let _ = hasher.verify("wrong", &hash);
    }
}
