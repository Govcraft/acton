//! Core OAuth2 types and configuration
//!
//! This module defines the foundational types for OAuth2 authentication,
//! including provider configurations, tokens, and user information.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// OAuth2 provider identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    /// Google OAuth2
    Google,
    /// GitHub OAuth2
    GitHub,
    /// Generic OpenID Connect provider
    Oidc,
}

impl OAuthProvider {
    /// Get the provider as a string (lowercase)
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
            Self::Oidc => "oidc",
        }
    }

    /// Parse provider from string
    ///
    /// # Errors
    ///
    /// Returns error if the provider name is not recognized
    pub fn from_str(s: &str) -> Result<Self, OAuthError> {
        match s.to_lowercase().as_str() {
            "google" => Ok(Self::Google),
            "github" => Ok(Self::GitHub),
            "oidc" => Ok(Self::Oidc),
            _ => Err(OAuthError::UnknownProvider(s.to_string())),
        }
    }
}

/// Configuration for an OAuth2 provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// OAuth2 client ID
    pub client_id: String,
    /// OAuth2 client secret
    pub client_secret: String,
    /// Redirect URI (callback URL)
    pub redirect_uri: String,
    /// OAuth2 scopes to request
    pub scopes: Vec<String>,
    /// Authorization endpoint (for generic OIDC)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// Token endpoint (for generic OIDC)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// UserInfo endpoint (for generic OIDC)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_url: Option<String>,
}

/// Complete OAuth2 configuration for all providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// Google OAuth2 configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google: Option<ProviderConfig>,
    /// GitHub OAuth2 configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github: Option<ProviderConfig>,
    /// Generic OIDC configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc: Option<ProviderConfig>,
}

impl OAuthConfig {
    /// Create a new empty OAuth2 configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            google: None,
            github: None,
            oidc: None,
        }
    }

    /// Get configuration for a specific provider
    ///
    /// # Errors
    ///
    /// Returns error if the provider is not configured
    pub fn get_provider(&self, provider: OAuthProvider) -> Result<&ProviderConfig, OAuthError> {
        match provider {
            OAuthProvider::Google => self
                .google
                .as_ref()
                .ok_or(OAuthError::ProviderNotConfigured(provider)),
            OAuthProvider::GitHub => self
                .github
                .as_ref()
                .ok_or(OAuthError::ProviderNotConfigured(provider)),
            OAuthProvider::Oidc => self
                .oidc
                .as_ref()
                .ok_or(OAuthError::ProviderNotConfigured(provider)),
        }
    }

    /// Check if a provider is configured
    #[must_use]
    pub fn is_provider_configured(&self, provider: OAuthProvider) -> bool {
        match provider {
            OAuthProvider::Google => self.google.is_some(),
            OAuthProvider::GitHub => self.github.is_some(),
            OAuthProvider::Oidc => self.oidc.is_some(),
        }
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// OAuth2 CSRF state token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// The state token
    pub token: String,
    /// Provider for this state
    pub provider: OAuthProvider,
    /// When the state expires
    pub expires_at: SystemTime,
}

impl OAuthState {
    /// Generate a new state token
    #[must_use]
    pub fn generate(provider: OAuthProvider) -> Self {
        use rand::Rng;

        // Generate 32 bytes of random data and encode as hex
        let random_bytes: [u8; 32] = rand::rng().random();
        let token = hex::encode(random_bytes);

        Self {
            token,
            provider,
            expires_at: SystemTime::now() + Duration::from_secs(600), // 10 minutes
        }
    }

    /// Check if the state token has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

/// OAuth2 access token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// Access token
    pub access_token: String,
    /// Refresh token (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// When the token expires
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<SystemTime>,
    /// OAuth2 scopes granted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

impl OAuthToken {
    /// Check if the access token has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map_or(false, |expires| SystemTime::now() > expires)
    }
}

/// User information from OAuth2 provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    /// Provider-specific user ID
    pub provider_user_id: String,
    /// Email address
    pub email: String,
    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Avatar/profile picture URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Whether email is verified
    pub email_verified: bool,
}

/// OAuth2 errors
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Unknown provider
    #[error("Unknown OAuth2 provider: {0}")]
    UnknownProvider(String),

    /// Provider not configured
    #[error("OAuth2 provider not configured: {0:?}")]
    ProviderNotConfigured(OAuthProvider),

    /// Invalid state token
    #[error("Invalid or expired OAuth2 state token")]
    InvalidState,

    /// State token mismatch (potential CSRF attack)
    #[error("OAuth2 state token mismatch (potential CSRF attack)")]
    StateMismatch,

    /// Authorization code exchange failed
    #[error("Failed to exchange authorization code for token: {0}")]
    TokenExchangeFailed(String),

    /// Failed to fetch user info
    #[error("Failed to fetch user information: {0}")]
    UserInfoFailed(String),

    /// Token expired
    #[error("OAuth2 token has expired")]
    TokenExpired,

    /// Generic OAuth2 error
    #[error("OAuth2 error: {0}")]
    Generic(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_as_str() {
        assert_eq!(OAuthProvider::Google.as_str(), "google");
        assert_eq!(OAuthProvider::GitHub.as_str(), "github");
        assert_eq!(OAuthProvider::Oidc.as_str(), "oidc");
    }

    #[test]
    fn test_provider_from_str() {
        assert_eq!(
            OAuthProvider::from_str("google").unwrap(),
            OAuthProvider::Google
        );
        assert_eq!(
            OAuthProvider::from_str("GOOGLE").unwrap(),
            OAuthProvider::Google
        );
        assert_eq!(
            OAuthProvider::from_str("github").unwrap(),
            OAuthProvider::GitHub
        );
        assert_eq!(
            OAuthProvider::from_str("oidc").unwrap(),
            OAuthProvider::Oidc
        );
        assert!(OAuthProvider::from_str("invalid").is_err());
    }

    #[test]
    fn test_oauth_config_default() {
        let config = OAuthConfig::default();
        assert!(config.google.is_none());
        assert!(config.github.is_none());
        assert!(config.oidc.is_none());
    }

    #[test]
    fn test_oauth_config_is_provider_configured() {
        let mut config = OAuthConfig::default();
        assert!(!config.is_provider_configured(OAuthProvider::Google));

        config.google = Some(ProviderConfig {
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            scopes: vec!["email".to_string()],
            auth_url: None,
            token_url: None,
            userinfo_url: None,
        });

        assert!(config.is_provider_configured(OAuthProvider::Google));
        assert!(!config.is_provider_configured(OAuthProvider::GitHub));
    }

    #[test]
    fn test_oauth_state_generation() {
        let state = OAuthState::generate(OAuthProvider::Google);
        assert_eq!(state.provider, OAuthProvider::Google);
        assert!(!state.is_expired());
        assert_eq!(state.token.len(), 64); // 32 bytes encoded as hex
    }

    #[test]
    fn test_oauth_token_is_expired() {
        let token = OAuthToken {
            access_token: "test".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: None,
            scopes: None,
        };
        assert!(!token.is_expired());

        let expired_token = OAuthToken {
            access_token: "test".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: Some(SystemTime::now() - Duration::from_secs(3600)),
            scopes: None,
        };
        assert!(expired_token.is_expired());
    }
}
