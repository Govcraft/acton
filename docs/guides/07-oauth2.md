# Guide 07: OAuth2 Social Authentication

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Provider Setup](#provider-setup)
  - [Google OAuth2](#google-oauth2)
  - [GitHub OAuth2](#github-oauth2)
  - [Generic OIDC](#generic-oidc)
- [Configuration](#configuration)
- [Integration](#integration)
- [Account Linking](#account-linking)
- [Security](#security)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

acton-htmx provides built-in OAuth2 authentication support for social login providers. The OAuth2 module includes:

- **Google OAuth2** (with OpenID Connect)
- **GitHub OAuth2**
- **Generic OpenID Connect** provider support
- **Account Linking** - Link multiple providers to one user account
- **CSRF Protection** - State tokens prevent cross-site request forgery
- **PKCE Support** - Proof Key for Code Exchange for enhanced security
- **Type Safety** - Strongly typed providers and configurations

### Architecture

The OAuth2 system uses:

1. **OAuth2Agent** - Manages CSRF state tokens via acton-reactive agents
2. **Provider Implementations** - Type-safe Google, GitHub, and OIDC providers
3. **Database Integration** - `oauth_accounts` table for account linking
4. **Security-First Design** - PKCE, state validation, token expiration

## Quick Start

### 1. Add Database Migration

The OAuth2 module requires the `oauth_accounts` table. Migration `002_create_oauth_accounts` is included:

```sql
CREATE TABLE oauth_accounts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('google', 'github', 'oidc')),
    provider_user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_oauth_accounts_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT unique_oauth_account UNIQUE (provider, provider_user_id)
);
```

Run the migration:

```bash
acton-htmx db migrate
```

### 2. Configure Providers

Add OAuth2 configuration to your `config/development.toml`:

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

**Production**: Use environment variables:

```bash
export GOOGLE_CLIENT_ID="..."
export GOOGLE_CLIENT_SECRET="..."
export GITHUB_CLIENT_ID="..."
export GITHUB_CLIENT_SECRET="..."
```

### 3. Add Routes

Add OAuth2 routes to your `main.rs`:

```rust
use acton_htmx::oauth2::handlers::{
    initiate_oauth,
    handle_oauth_callback,
    unlink_oauth_account
};

let app = Router::new()
    // OAuth2 routes
    .route("/auth/:provider", get(initiate_oauth))
    .route("/auth/:provider/callback", get(handle_oauth_callback))
    .route("/auth/:provider/unlink", post(unlink_oauth_account))
    // ... other routes
    .with_state(state);
```

### 4. Add Login Buttons

In your login template (`templates/auth/login.html`):

```html
<div class="oauth-login">
    <a href="/auth/google" class="btn btn-google">
        Sign in with Google
    </a>
    <a href="/auth/github" class="btn btn-github">
        Sign in with GitHub
    </a>
</div>
```

## Provider Setup

### Google OAuth2

#### 1. Create Google OAuth2 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Navigate to "APIs & Services" → "Credentials"
4. Click "Create Credentials" → "OAuth 2.0 Client ID"
5. Configure consent screen:
   - Application name: Your app name
   - Authorized domains: `yourdomain.com`
   - Scopes: `email`, `profile`, `openid`
6. Create OAuth2 client:
   - Application type: "Web application"
   - Authorized redirect URIs:
     - Development: `http://localhost:3000/auth/google/callback`
     - Production: `https://yourdomain.com/auth/google/callback`
7. Copy Client ID and Client Secret

#### 2. Configuration

```toml
[oauth2.google]
client_id = "123456789-abcdefg.apps.googleusercontent.com"
client_secret = "GOCSPX-your-secret-here"
redirect_uri = "http://localhost:3000/auth/google/callback"
scopes = ["openid", "email", "profile"]
```

**Scopes**:
- `openid` - Required for OpenID Connect
- `email` - Access user's email address
- `profile` - Access user's name and avatar
- `https://www.googleapis.com/auth/userinfo.email` - Alternative email scope

#### 3. User Info

Google returns:
```json
{
    "sub": "1234567890",
    "email": "user@gmail.com",
    "email_verified": true,
    "name": "John Doe",
    "picture": "https://lh3.googleusercontent.com/..."
}
```

### GitHub OAuth2

#### 1. Create GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in details:
   - Application name: Your app name
   - Homepage URL: `https://yourdomain.com`
   - Authorization callback URL:
     - Development: `http://localhost:3000/auth/github/callback`
     - Production: `https://yourdomain.com/auth/github/callback`
4. Click "Register application"
5. Copy Client ID
6. Generate a new Client Secret

#### 2. Configuration

```toml
[oauth2.github]
client_id = "Iv1.abc123def456"
client_secret = "your-github-client-secret"
redirect_uri = "http://localhost:3000/auth/github/callback"
scopes = ["read:user", "user:email"]
```

**Scopes**:
- `read:user` - Read user profile information
- `user:email` - Access user's email addresses

#### 3. User Info

GitHub returns:
```json
{
    "id": 12345678,
    "login": "username",
    "email": "user@example.com",
    "name": "John Doe",
    "avatar_url": "https://avatars.githubusercontent.com/u/12345678"
}
```

### Generic OIDC

For other OpenID Connect providers (Auth0, Okta, Keycloak, etc.):

#### Configuration

```toml
[oauth2.oidc]
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_uri = "http://localhost:3000/auth/oidc/callback"
scopes = ["openid", "email", "profile"]
# OIDC-specific endpoints
auth_url = "https://your-provider.com/oauth2/authorize"
token_url = "https://your-provider.com/oauth2/token"
userinfo_url = "https://your-provider.com/oauth2/userinfo"
```

**Discovery**: Most OIDC providers support automatic discovery via `/.well-known/openid-configuration`

## Configuration

### Environment Variables

For production, use environment variables instead of config files:

```bash
# Google
export OAUTH2_GOOGLE_CLIENT_ID="..."
export OAUTH2_GOOGLE_CLIENT_SECRET="..."
export OAUTH2_GOOGLE_REDIRECT_URI="https://yourdomain.com/auth/google/callback"

# GitHub
export OAUTH2_GITHUB_CLIENT_ID="..."
export OAUTH2_GITHUB_CLIENT_SECRET="..."
export OAUTH2_GITHUB_REDIRECT_URI="https://yourdomain.com/auth/github/callback"
```

### Multiple Environments

Use separate config files:

```bash
config/
├── development.toml    # Local OAuth apps
├── staging.toml        # Staging OAuth apps
└── production.toml     # Production OAuth apps
```

### Redirect URI Patterns

**Development**:
```
http://localhost:3000/auth/{provider}/callback
```

**Production**:
```
https://yourdomain.com/auth/{provider}/callback
```

**Note**: Provider must be one of: `google`, `github`, `oidc`

## Integration

### Complete OAuth2 Flow

#### 1. Initiate OAuth

User clicks "Sign in with Google":

```rust
// Handler: GET /auth/google
pub async fn initiate_oauth(
    State(state): State<ActonHtmxState>,
    Path(provider_name): Path<String>,
    mut session: Session,
) -> Result<impl IntoResponse, ActonHtmxError> {
    let provider = provider_name.parse::<OAuthProvider>()?;

    // Generate CSRF state token
    let oauth_state = state.oauth2_agent()
        .generate_state(provider).await?;

    // Generate authorization URL with PKCE
    let (auth_url, pkce_verifier) = GoogleProvider::new(provider_config)?
        .authorization_url();

    // Store state and PKCE verifier in session
    session.set("oauth2_state", &oauth_state.token)?;
    session.set("oauth2_pkce_verifier", &pkce_verifier)?;

    // Redirect to Google
    Ok(Redirect::to(&auth_url))
}
```

#### 2. Handle Callback

Provider redirects back with authorization code:

```rust
// Handler: GET /auth/google/callback?code=...&state=...
pub async fn handle_oauth_callback(
    State(state): State<ActonHtmxState>,
    Path(provider_name): Path<String>,
    Query(params): Query<OAuthCallback>,
    mut session: Session,
) -> Result<impl IntoResponse, ActonHtmxError> {
    // Validate CSRF state token
    let stored_state: String = session.get("oauth2_state")?;
    state.oauth2_agent().validate_state(&params.state).await?;

    // Exchange authorization code for access token
    let pkce_verifier: String = session.get("oauth2_pkce_verifier")?;
    let token = GoogleProvider::new(provider_config)?
        .exchange_code(&params.code, &pkce_verifier).await?;

    // Fetch user info from provider
    let user_info = GoogleProvider::user_info(&token).await?;

    // Find or create user
    let user = find_or_create_oauth_user(
        &state.db_pool(),
        provider,
        &user_info,
    ).await?;

    // Authenticate session
    session.set("user_id", user.id)?;
    session.add_flash(FlashMessage::success("Signed in successfully!"));

    Ok(HxRedirect::to("/dashboard"))
}
```

#### 3. Find or Create User

```rust
async fn find_or_create_oauth_user(
    db: &PgPool,
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
        return User::find_by_id(db, oauth_account.user_id).await;
    }

    // Check if user exists by email
    if let Some(user) = User::find_by_email(db, &user_info.email).await? {
        // Link OAuth account to existing user
        OAuthAccount::create(db, user.id, provider, user_info).await?;
        return Ok(user);
    }

    // Create new user from OAuth info
    let user = User::create_from_oauth(db, user_info).await?;
    OAuthAccount::create(db, user.id, provider, user_info).await?;

    Ok(user)
}
```

### Database Models

#### OAuthAccount Model

```rust
use sqlx::PgPool;
use chrono::{DateTime, Utc};

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
            r#"SELECT * FROM oauth_accounts WHERE user_id = $1"#,
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

## Account Linking

Allow users to link multiple OAuth providers to their account:

### UI Example

```html
<!-- templates/settings/account.html -->
<h2>Linked Accounts</h2>

<div class="linked-accounts">
    {% if google_linked %}
    <div class="account-item">
        <img src="/icons/google.svg" alt="Google">
        <span>Google ({{ user.email }})</span>
        <form hx-post="/auth/google/unlink" hx-swap="outerHTML">
            <button type="submit" class="btn btn-danger">Unlink</button>
        </form>
    </div>
    {% else %}
    <div class="account-item">
        <img src="/icons/google.svg" alt="Google">
        <span>Google</span>
        <a href="/auth/google?link=true" class="btn btn-primary">Link Account</a>
    </div>
    {% endif %}

    {% if github_linked %}
    <div class="account-item">
        <img src="/icons/github.svg" alt="GitHub">
        <span>GitHub ({{ github_username }})</span>
        <form hx-post="/auth/github/unlink" hx-swap="outerHTML">
            <button type="submit" class="btn btn-danger">Unlink</button>
        </form>
    </div>
    {% else %}
    <div class="account-item">
        <img src="/icons/github.svg" alt="GitHub">
        <span>GitHub</span>
        <a href="/auth/github?link=true" class="btn btn-primary">Link Account</a>
    </div>
    {% endif %}
</div>
```

### Handler: Link Account

```rust
pub async fn initiate_oauth_link(
    State(state): State<ActonHtmxState>,
    Path(provider_name): Path<String>,
    mut session: Session,
    Authenticated(user): Authenticated<User>,
) -> Result<impl IntoResponse, ActonHtmxError> {
    // Store link intent in session
    session.set("oauth2_link_mode", true)?;
    session.set("oauth2_link_user_id", user.id)?;

    // Same flow as regular OAuth, but callback handler checks link_mode
    initiate_oauth(State(state), Path(provider_name), session).await
}
```

### Handler: Unlink Account

```rust
pub async fn unlink_oauth_account(
    State(state): State<ActonHtmxState>,
    Path(provider_name): Path<String>,
    Authenticated(user): Authenticated<User>,
) -> Result<impl IntoResponse, ActonHtmxError> {
    let provider = provider_name.parse::<OAuthProvider>()?;

    // Check user has password or another OAuth account
    if !user.has_password() {
        let other_accounts = OAuthAccount::find_by_user_id(&state.db_pool(), user.id)
            .await?
            .into_iter()
            .filter(|a| a.provider != provider.as_str())
            .count();

        if other_accounts == 0 {
            return Err(ActonHtmxError::BadRequest(
                "Cannot unlink last authentication method. Set a password first.".to_string()
            ));
        }
    }

    // Delete OAuth account
    OAuthAccount::delete(&state.db_pool(), user.id, provider).await?;

    Ok(HxTrigger::new("accountUnlinked")
        .with_detail("provider", provider.as_str())
        .into_response())
}
```

## Security

### CSRF Protection

acton-htmx automatically protects against CSRF attacks using state tokens:

1. **State Generation**: Cryptographically secure 256-bit tokens
2. **State Validation**: Server-side validation via `OAuth2Agent`
3. **One-Time Use**: State tokens deleted after validation
4. **Expiration**: Tokens expire after 10 minutes

### PKCE (Proof Key for Code Exchange)

All providers use PKCE to prevent authorization code interception:

1. **Code Verifier**: Random 128-character string
2. **Code Challenge**: SHA256 hash of verifier
3. **Secure Storage**: Verifier stored in HTTP-only session cookie
4. **Validation**: Provider validates challenge during token exchange

### Security Checklist

- [ ] Use HTTPS in production (enforce with `HSTS` header)
- [ ] Store secrets in environment variables (never in code)
- [ ] Use HTTP-only, Secure, SameSite cookies
- [ ] Validate email before auto-linking accounts
- [ ] Implement rate limiting on OAuth endpoints
- [ ] Log OAuth events for audit trail
- [ ] Require email verification for OAuth-created accounts
- [ ] Don't allow account unlinking if no password set

### Common Vulnerabilities

#### ❌ State Token Reuse

```rust
// BAD: Reusing state token
if params.state == stored_state {
    // Vulnerable to replay attacks
}
```

✅ **Solution**: One-time token validation via agent

```rust
// GOOD: One-time validation
state.oauth2_agent().validate_state(&params.state).await?;
// Token is automatically removed after validation
```

#### ❌ Missing PKCE

```rust
// BAD: No PKCE
let auth_url = client.authorize_url().url();
```

✅ **Solution**: Always use PKCE

```rust
// GOOD: PKCE enabled
let (auth_url, _state, pkce_verifier) = provider.authorization_url();
session.set("pkce_verifier", &pkce_verifier)?;
```

#### ❌ Account Hijacking

```rust
// BAD: Auto-link by email without verification
if let Some(user) = User::find_by_email(db, &oauth_email).await? {
    link_account(user.id, oauth_info).await?; // Dangerous!
}
```

✅ **Solution**: Require authentication or email verification

```rust
// GOOD: Require user to be logged in to link
if session.get::<i64>("user_id").is_ok() {
    link_account(user.id, oauth_info).await?;
} else {
    // Create new user, send email verification
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_provider_parsing() {
        assert_eq!(
            "google".parse::<OAuthProvider>().unwrap(),
            OAuthProvider::Google
        );
        assert!("invalid".parse::<OAuthProvider>().is_err());
    }

    #[test]
    fn test_state_token_expiration() {
        let state = OAuthState::generate(OAuthProvider::Google);
        assert!(!state.is_expired());
        assert_eq!(state.token.len(), 64); // 32 bytes hex-encoded
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_oauth_flow() {
    let app = test_app().await;

    // 1. Initiate OAuth
    let response = app.get("/auth/google").await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let redirect_url = response.headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(redirect_url.contains("accounts.google.com"));

    // 2. Simulate callback (use mock provider in tests)
    let callback = app.get("/auth/google/callback?code=test&state=valid").await;
    assert_eq!(callback.status(), StatusCode::FOUND);
}
```

### Mock Provider

For testing without real OAuth providers:

```rust
pub struct MockOAuthProvider {
    pub user_info: OAuthUserInfo,
}

impl MockOAuthProvider {
    pub async fn exchange_code(&self, _code: &str) -> Result<OAuthToken> {
        Ok(OAuthToken {
            access_token: "mock_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_at: None,
            refresh_token: None,
            scopes: None,
        })
    }

    pub async fn user_info(&self, _token: &OAuthToken) -> Result<OAuthUserInfo> {
        Ok(self.user_info.clone())
    }
}
```

## Troubleshooting

### Error: "redirect_uri_mismatch"

**Cause**: Redirect URI doesn't match configured value in provider

**Solution**:
1. Check provider settings (Google Console, GitHub OAuth Apps)
2. Ensure exact match including protocol (`http` vs `https`)
3. Trailing slashes matter: `/callback` ≠ `/callback/`

### Error: "invalid_client"

**Cause**: Client ID or secret incorrect

**Solution**:
1. Verify `client_id` and `client_secret` in config
2. Check environment variables are loaded
3. Regenerate client secret if needed

### Error: "State token mismatch"

**Cause**: CSRF state validation failed

**Possible Causes**:
1. Session cookies not working (check `SameSite` attribute)
2. State token expired (> 10 minutes)
3. User opened multiple OAuth windows

**Solution**:
1. Enable session middleware
2. Check cookie configuration
3. Implement "retry" flow

### Error: "Email already exists"

**Cause**: Email from OAuth provider already registered

**Solution**:
1. Check if user is logged in → Link account
2. If not logged in → Prompt to sign in and link
3. Implement email verification before auto-linking

### Provider-Specific Issues

#### Google: "Access blocked"

Check:
- [ ] OAuth consent screen configured
- [ ] Authorized domains added
- [ ] Scopes not too permissive
- [ ] App verification completed (for production)

#### GitHub: "Not found"

Check:
- [ ] OAuth App created (not GitHub App)
- [ ] Callback URL matches exactly
- [ ] User granted email scope

## Next Steps

- [Guide 08: Background Jobs](./08-background-jobs.md) - Use OAuth2 with background job notifications
- [Guide 03: Authentication](./03-authentication.md) - Combine OAuth2 with password authentication
- [API Reference](https://docs.rs/acton-htmx) - Full OAuth2 API documentation

## Additional Resources

- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC](https://datatracker.ietf.org/doc/html/rfc7636)
- [Google OAuth2 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [GitHub OAuth Apps Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
