//! GitHub OAuth2 provider implementation
//!
//! This module implements OAuth2 authentication with GitHub using their OAuth2 API.

use serde::{Deserialize, Serialize};

use super::base::BaseOAuthProvider;
use crate::htmx::oauth2::types::{OAuthError, OAuthToken, OAuthUserInfo, ProviderConfig};

/// GitHub OAuth2 provider
pub struct GitHubProvider {
    base: BaseOAuthProvider,
}

impl GitHubProvider {
    /// Create a new GitHub OAuth2 provider
    ///
    /// # Errors
    ///
    /// Returns error if the configuration is invalid
    pub fn new(config: &ProviderConfig) -> Result<Self, OAuthError> {
        Ok(Self {
            base: BaseOAuthProvider::new(
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                config,
                "https://api.github.com/user".to_string(),
            )?,
        })
    }

    /// Generate authorization URL and CSRF state
    ///
    /// Returns tuple of (authorization_url, csrf_state, pkce_verifier)
    #[must_use]
    pub fn authorization_url(&self) -> (String, String, String) {
        self.base.authorization_url(&["read:user", "user:email"])
    }

    /// Exchange authorization code for access token
    ///
    /// # Errors
    ///
    /// Returns error if the token exchange fails
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<OAuthToken, OAuthError> {
        self.base.exchange_code(code, pkce_verifier).await
    }

    /// Fetch user information using access token
    ///
    /// # Errors
    ///
    /// Returns error if the user info request fails
    pub async fn fetch_user_info(&self, access_token: &str) -> Result<OAuthUserInfo, OAuthError> {
        // Fetch user profile
        let user_json = self.base
            .fetch_json_with_headers(
                "https://api.github.com/user",
                access_token,
                Some(&[("User-Agent", "acton-dx")]),
            )
            .await?;

        let github_user: GitHubUser = serde_json::from_value(user_json)
            .map_err(|e| OAuthError::UserInfoFailed(format!("Failed to parse GitHub user: {e}")))?;

        // Fetch user emails (to get primary verified email)
        let emails_json = self.base
            .fetch_json_with_headers(
                "https://api.github.com/user/emails",
                access_token,
                Some(&[("User-Agent", "acton-dx")]),
            )
            .await;

        let emails: Vec<GitHubEmail> = emails_json.map_or_else(
            |_| vec![],
            |json| serde_json::from_value(json).unwrap_or_default(),
        );

        // Find primary verified email
        let primary_email = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified))
            .or_else(|| emails.first());

        let email = primary_email.map_or_else(
            || format!("{}@users.noreply.github.com", github_user.id),
            |e| e.email.clone(),
        );

        let email_verified = primary_email.is_some_and(|e| e.verified);

        Ok(OAuthUserInfo {
            provider_user_id: github_user.id.to_string(),
            email,
            name: github_user.name.or(Some(github_user.login)),
            avatar_url: Some(github_user.avatar_url),
            email_verified,
        })
    }
}

/// GitHub user response
#[derive(Debug, Deserialize, Serialize)]
struct GitHubUser {
    id: i64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: String,
}

/// GitHub email response
#[derive(Debug, Deserialize, Serialize)]
struct GitHubEmail {
    email: String,
    verified: bool,
    primary: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_provider_creation() {
        let config = ProviderConfig {
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            redirect_uri: "http://localhost:3000/auth/github/callback".to_string(),
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
            auth_url: None,
            token_url: None,
            userinfo_url: None,
        };

        let provider = GitHubProvider::new(&config).unwrap();
        let (auth_url, csrf_state, pkce_verifier) = provider.authorization_url();

        assert!(auth_url.starts_with("https://github.com/login/oauth/authorize"));
        assert!(auth_url.contains("client_id=test-client-id"));
        assert!(auth_url.contains("redirect_uri"));
        assert!(auth_url.contains("scope=read%3Auser"));
        assert!(!csrf_state.is_empty());
        assert!(!pkce_verifier.is_empty());
    }
}
