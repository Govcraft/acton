# Example: Social Login with OAuth2

This example demonstrates a complete OAuth2 implementation with Google and GitHub authentication, including account linking and profile management.

## Features

- Social login with Google and GitHub
- Account linking (multiple providers per user)
- Profile management with linked accounts
- Secure CSRF protection with state tokens
- PKCE for enhanced security

## Setup

### 1. Initialize Project

```bash
# Create new project
acton-htmx new social-login-app
cd social-login-app

# Set up OAuth2 providers
acton-htmx scaffold oauth2 google
acton-htmx scaffold oauth2 github
```

### 2. Configure Providers

Update `config/development.toml`:

```toml
[oauth2.google]
client_id = "your-google-client-id.apps.googleusercontent.com"
client_secret = "your-google-client-secret"
redirect_uri = "http://localhost:3000/auth/google/callback"
scopes = ["openid", "email", "profile"]

[oauth2.github]
client_id = "your-github-client-id"
client_secret = "your-github-client-secret"
redirect_uri = "http://localhost:3000/auth/github/callback"
scopes = ["read:user", "user:email"]
```

### 3. Run Migrations

```bash
acton-htmx db migrate
```

## Implementation

### Database Models

#### User Model

```rust
// src/models/user.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub password_hash: Option<String>, // Optional for OAuth-only users
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Find user by ID
    pub async fn find_by_id(db: &PgPool, id: i64) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"SELECT * FROM users WHERE id = $1"#,
            id
        )
        .fetch_optional(db)
        .await
    }

    /// Find user by email
    pub async fn find_by_email(db: &PgPool, email: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"SELECT * FROM users WHERE email = $1"#,
            email
        )
        .fetch_optional(db)
        .await
    }

    /// Create user from OAuth info
    pub async fn create_from_oauth(
        db: &PgPool,
        email: &str,
        name: Option<&str>,
        avatar_url: Option<&str>,
        email_verified: bool,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO users (email, name, avatar_url, email_verified, password_hash)
            VALUES ($1, $2, $3, $4, NULL)
            RETURNING *
            "#,
            email,
            name,
            avatar_url,
            email_verified
        )
        .fetch_one(db)
        .await
    }

    /// Check if user has a password set
    pub fn has_password(&self) -> bool {
        self.password_hash.is_some()
    }
}
```

#### OAuthAccount Model

```rust
// src/models/oauth_account.rs
use acton_htmx::oauth2::types::{OAuthProvider, OAuthUserInfo};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccount {
    pub id: i64,
    pub user_id: i64,
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OAuthAccount {
    /// Find OAuth account by provider and provider user ID
    pub async fn find_by_provider(
        db: &PgPool,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT * FROM oauth_accounts
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider.as_str(),
            provider_user_id
        )
        .fetch_optional(db)
        .await
    }

    /// Create new OAuth account
    pub async fn create(
        db: &PgPool,
        user_id: i64,
        provider: OAuthProvider,
        user_info: &OAuthUserInfo,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO oauth_accounts
                (user_id, provider, provider_user_id, email, name, avatar_url)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
            user_id,
            provider.as_str(),
            user_info.provider_user_id,
            user_info.email,
            user_info.name,
            user_info.avatar_url
        )
        .fetch_one(db)
        .await
    }

    /// Find all OAuth accounts for a user
    pub async fn find_by_user_id(
        db: &PgPool,
        user_id: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"SELECT * FROM oauth_accounts WHERE user_id = $1 ORDER BY created_at DESC"#,
            user_id
        )
        .fetch_all(db)
        .await
    }

    /// Delete OAuth account
    pub async fn delete(
        db: &PgPool,
        user_id: i64,
        provider: OAuthProvider,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_accounts
            WHERE user_id = $1 AND provider = $2
            "#,
            user_id,
            provider.as_str()
        )
        .execute(db)
        .await?;
        Ok(())
    }
}
```

### Handlers

#### OAuth Handlers

```rust
// src/handlers/oauth.rs
use acton_htmx::{
    auth::Session,
    error::ActonHtmxError,
    htmx::{HxRedirect, HxResponseTrigger},
    oauth2::{
        agent::{GenerateState, ValidateState},
        providers::{GitHubProvider, GoogleProvider},
        types::{OAuthProvider, OAuthUserInfo},
    },
    state::ActonHtmxState,
};
use acton_reactive::prelude::AgentHandleInterface;
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
};
use crate::models::{User, OAuthAccount};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    pub code: String,
    pub state: String,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthInitiate {
    pub link: Option<bool>,
}

/// Initiate OAuth flow (login or link)
pub async fn initiate_oauth(
    State(state): State<ActonHtmxState>,
    Path(provider_name): Path<String>,
    Query(params): Query<OAuthInitiate>,
    mut session: Session,
) -> Result<impl IntoResponse, ActonHtmxError> {
    let provider = provider_name.parse::<OAuthProvider>()
        .map_err(|_| ActonHtmxError::BadRequest(format!("Unknown provider: {provider_name}")))?;

    let oauth_config = &state.config().oauth2;
    let provider_config = oauth_config.get_provider(provider)
        .map_err(|e| ActonHtmxError::ServerError(format!("Provider not configured: {e}")))?;

    // Generate CSRF state token
    let (generate_msg, rx) = GenerateState::new(provider);
    state.oauth2_agent().send(generate_msg).await;
    let oauth_state = rx.await
        .map_err(|e| ActonHtmxError::ServerError(format!("Failed to generate state: {e}")))?;

    // Generate authorization URL with PKCE
    let (auth_url, _csrf_state, pkce_verifier) = match provider {
        OAuthProvider::Google => {
            let google = GoogleProvider::new(provider_config)
                .map_err(|e| ActonHtmxError::ServerError(format!("Google OAuth error: {e}")))?;
            google.authorization_url()
        }
        OAuthProvider::GitHub => {
            let github = GitHubProvider::new(provider_config)
                .map_err(|e| ActonHtmxError::ServerError(format!("GitHub OAuth error: {e}")))?;
            github.authorization_url()
        }
        _ => return Err(ActonHtmxError::BadRequest("Provider not supported".to_string())),
    };

    // Store state and PKCE verifier in session
    session.set("oauth2_state".to_string(), &oauth_state.token)?;
    session.set("oauth2_pkce_verifier".to_string(), &pkce_verifier)?;
    session.set("oauth2_provider".to_string(), &provider_name)?;

    // Store link mode if linking account
    if params.link.unwrap_or(false) {
        // User must be logged in to link account
        let user_id: i64 = session.get("user_id")?;
        session.set("oauth2_link_mode".to_string(), &true)?;
        session.set("oauth2_link_user_id".to_string(), &user_id)?;
    }

    Ok(axum::response::Redirect::to(&auth_url))
}

/// Handle OAuth callback
pub async fn handle_oauth_callback(
    State(state): State<ActonHtmxState>,
    Path(provider_name): Path<String>,
    Query(params): Query<OAuthCallback>,
    mut session: Session,
) -> Result<impl IntoResponse, ActonHtmxError> {
    // Check for provider errors
    if let Some(error) = params.error {
        return Err(ActonHtmxError::BadRequest(format!("OAuth error: {error}")));
    }

    let provider = provider_name.parse::<OAuthProvider>()
        .map_err(|_| ActonHtmxError::BadRequest(format!("Unknown provider: {provider_name}")))?;

    // Validate CSRF state token
    let stored_state: String = session.get("oauth2_state")
        .map_err(|_| ActonHtmxError::BadRequest("Missing OAuth state".to_string()))?;

    let (validate_msg, rx) = ValidateState::new(&params.state);
    state.oauth2_agent().send(validate_msg).await;
    let is_valid = rx.await
        .map_err(|e| ActonHtmxError::ServerError(format!("State validation error: {e}")))?;

    if !is_valid {
        return Err(ActonHtmxError::BadRequest("Invalid OAuth state".to_string()));
    }

    // Get OAuth config
    let oauth_config = &state.config().oauth2;
    let provider_config = oauth_config.get_provider(provider)
        .map_err(|e| ActonHtmxError::ServerError(format!("Provider not configured: {e}")))?;

    // Get PKCE verifier
    let pkce_verifier: String = session.get("oauth2_pkce_verifier")
        .map_err(|_| ActonHtmxError::BadRequest("Missing PKCE verifier".to_string()))?;

    // Exchange code for token and get user info
    let user_info = match provider {
        OAuthProvider::Google => {
            let google = GoogleProvider::new(provider_config)
                .map_err(|e| ActonHtmxError::ServerError(format!("Google OAuth error: {e}")))?;
            let token = google.exchange_code(&params.code, &pkce_verifier).await
                .map_err(|e| ActonHtmxError::ServerError(format!("Token exchange failed: {e}")))?;
            google.user_info(&token).await
                .map_err(|e| ActonHtmxError::ServerError(format!("User info failed: {e}")))?
        }
        OAuthProvider::GitHub => {
            let github = GitHubProvider::new(provider_config)
                .map_err(|e| ActonHtmxError::ServerError(format!("GitHub OAuth error: {e}")))?;
            let token = github.exchange_code(&params.code, &pkce_verifier).await
                .map_err(|e| ActonHtmxError::ServerError(format!("Token exchange failed: {e}")))?;
            github.user_info(&token).await
                .map_err(|e| ActonHtmxError::ServerError(format!("User info failed: {e}")))?
        }
        _ => return Err(ActonHtmxError::BadRequest("Provider not supported".to_string())),
    };

    // Check if in link mode
    let link_mode: Option<bool> = session.get("oauth2_link_mode").ok();
    let link_user_id: Option<i64> = session.get("oauth2_link_user_id").ok();

    let user = if link_mode.unwrap_or(false) && link_user_id.is_some() {
        // Link OAuth account to existing user
        let user_id = link_user_id.unwrap();
        let user = User::find_by_id(state.db_pool(), user_id).await?
            .ok_or_else(|| ActonHtmxError::BadRequest("User not found".to_string()))?;

        // Check if this OAuth account is already linked
        if OAuthAccount::find_by_provider(state.db_pool(), provider, &user_info.provider_user_id)
            .await?
            .is_some()
        {
            return Err(ActonHtmxError::BadRequest(
                format!("{} account already linked to another user", provider.as_str())
            ));
        }

        // Link account
        OAuthAccount::create(state.db_pool(), user_id, provider, &user_info).await?;

        // Clean up link mode session data
        let _ = session.remove("oauth2_link_mode".to_string());
        let _ = session.remove("oauth2_link_user_id".to_string());

        user
    } else {
        // Login or register with OAuth
        find_or_create_oauth_user(state.db_pool(), provider, &user_info).await?
    };

    // Clean up OAuth session data
    let _ = session.remove("oauth2_state".to_string());
    let _ = session.remove("oauth2_pkce_verifier".to_string());
    let _ = session.remove("oauth2_provider".to_string());

    // Authenticate session
    session.set("user_id".to_string(), &user.id)?;

    if link_mode.unwrap_or(false) {
        Ok(HxRedirect::to("/settings/account").into_response())
    } else {
        Ok(HxRedirect::to("/dashboard").into_response())
    }
}

/// Unlink OAuth account
pub async fn unlink_oauth_account(
    State(state): State<ActonHtmxState>,
    Path(provider_name): Path<String>,
    session: Session,
) -> Result<impl IntoResponse, ActonHtmxError> {
    let user_id: i64 = session.get("user_id")?;
    let user = User::find_by_id(state.db_pool(), user_id).await?
        .ok_or_else(|| ActonHtmxError::BadRequest("User not found".to_string()))?;

    let provider = provider_name.parse::<OAuthProvider>()
        .map_err(|_| ActonHtmxError::BadRequest(format!("Unknown provider: {provider_name}")))?;

    // Check user has password or another OAuth account
    if !user.has_password() {
        let other_accounts = OAuthAccount::find_by_user_id(state.db_pool(), user_id)
            .await?
            .into_iter()
            .filter(|a| a.provider != provider.as_str())
            .count();

        if other_accounts == 0 {
            return Err(ActonHtmxError::BadRequest(
                "Cannot unlink last authentication method".to_string()
            ));
        }
    }

    // Delete OAuth account
    OAuthAccount::delete(state.db_pool(), user_id, provider).await?;

    Ok(HxResponseTrigger::new("accountUnlinked")
        .with_detail("provider", provider.as_str())
        .into_response())
}

/// Find or create user from OAuth info
async fn find_or_create_oauth_user(
    db: &sqlx::PgPool,
    provider: OAuthProvider,
    user_info: &OAuthUserInfo,
) -> Result<User, ActonHtmxError> {
    // Check if OAuth account exists
    if let Some(oauth_account) = OAuthAccount::find_by_provider(
        db,
        provider,
        &user_info.provider_user_id
    ).await? {
        // Account exists, load user
        return User::find_by_id(db, oauth_account.user_id).await?
            .ok_or_else(|| ActonHtmxError::ServerError("User not found".to_string()));
    }

    // Check if user exists by email
    if let Some(user) = User::find_by_email(db, &user_info.email).await? {
        // Link OAuth account to existing user
        OAuthAccount::create(db, user.id, provider, user_info).await?;
        return Ok(user);
    }

    // Create new user from OAuth info
    let user = User::create_from_oauth(
        db,
        &user_info.email,
        user_info.name.as_deref(),
        user_info.avatar_url.as_deref(),
        user_info.email_verified,
    ).await?;

    OAuthAccount::create(db, user.id, provider, user_info).await?;

    Ok(user)
}
```

### Templates

#### Login Page with OAuth

```html
<!-- templates/auth/login.html -->
{% extends "base.html" %}

{% block content %}
<div class="login-container">
    <h1>Sign In</h1>

    <!-- OAuth Login Buttons -->
    <div class="oauth-login">
        {% include "auth/google_button.html" %}
        {% include "auth/github_button.html" %}
    </div>

    <div class="divider">
        <span>or</span>
    </div>

    <!-- Email/Password Login -->
    <form hx-post="/auth/login" hx-swap="outerHTML" hx-target="closest .login-container">
        {{ csrf_token_with() | safe }}

        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
        </div>

        <button type="submit" class="btn btn-primary btn-block">Sign In</button>
    </form>

    <p class="text-center">
        Don't have an account? <a href="/auth/register">Sign up</a>
    </p>
</div>

<style>
.login-container {
    max-width: 400px;
    margin: 2rem auto;
    padding: 2rem;
    border: 1px solid #ddd;
    border-radius: 0.5rem;
}

.oauth-login {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.divider {
    display: flex;
    align-items: center;
    text-align: center;
    margin: 1.5rem 0;
}

.divider::before,
.divider::after {
    content: '';
    flex: 1;
    border-bottom: 1px solid #ddd;
}

.divider span {
    padding: 0 1rem;
    color: #666;
}
</style>
{% endblock %}
```

#### Account Settings with Linked Accounts

The template is generated by `acton-htmx scaffold oauth2` command at:
- `templates/auth/linked_accounts.html`

### Routes

```rust
// src/main.rs
use axum::{
    routing::{get, post},
    Router,
};
use acton_htmx::{
    oauth2::handlers as oauth_handlers,
    state::ActonHtmxState,
};
use crate::handlers::oauth;

fn oauth_routes() -> Router<ActonHtmxState> {
    Router::new()
        .route("/auth/:provider", get(oauth::initiate_oauth))
        .route("/auth/:provider/callback", get(oauth::handle_oauth_callback))
        .route("/auth/:provider/unlink", post(oauth::unlink_oauth_account))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ... initialize state ...

    let app = Router::new()
        .merge(oauth_routes())
        .route("/", get(home))
        .route("/dashboard", get(dashboard))
        .route("/settings/account", get(account_settings))
        // ... other routes ...
        .with_state(state);

    // ... start server ...
    Ok(())
}
```

## Running the Application

### 1. Set Up OAuth Credentials

Follow provider-specific instructions in [docs/guides/07-oauth2.md](../guides/07-oauth2.md):

- [Google OAuth2 Setup](../guides/07-oauth2.md#google-oauth2)
- [GitHub OAuth2 Setup](../guides/07-oauth2.md#github-oauth2)

### 2. Start Development Server

```bash
acton-htmx dev
```

### 3. Test OAuth Flow

1. Navigate to `http://localhost:3000/auth/login`
2. Click "Sign in with Google" or "Sign in with GitHub"
3. Authorize the application
4. Redirected to dashboard with authenticated session

### 4. Test Account Linking

1. Log in with password or OAuth
2. Navigate to `http://localhost:3000/settings/account`
3. Click "Link Account" for another provider
4. Authorize the second provider
5. Both accounts now linked to same user

## Security Considerations

### ✅ Implemented

- CSRF protection with state tokens
- PKCE for authorization code flow
- State token expiration (10 minutes)
- One-time use state tokens
- HTTP-only, Secure, SameSite cookies
- Email verification checks
- Account hijacking prevention

### 🔒 Recommended for Production

- Rate limiting on OAuth endpoints
- Audit logging for OAuth events
- Email notifications for new linked accounts
- Two-factor authentication
- Account recovery flows
- Session timeout and renewal

## Next Steps

- Add email/password registration and login
- Implement password reset flow
- Add profile editing
- Implement email verification
- Add account deletion
- Deploy to production with HTTPS

## Full Example

For a complete working example, see the [acton-htmx-examples repository](https://github.com/GovCraft/acton-htmx-examples/tree/main/oauth2-social-login).
