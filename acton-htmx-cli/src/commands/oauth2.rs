//! `OAuth2` provider scaffold command
//!
//! Generates `OAuth2` authentication setup for supported providers (Google, GitHub, OIDC).

use anyhow::{anyhow, Context, Result};
use console::style;
use std::fs;
use std::path::Path;

pub struct OAuth2Command {
    provider: String,
}

impl OAuth2Command {
    pub const fn new(provider: String) -> Self {
        Self { provider }
    }

    pub fn execute(&self) -> Result<()> {
        // Validate provider
        let provider = self.provider.to_lowercase();
        if !["google", "github", "oidc"].contains(&provider.as_str()) {
            return Err(anyhow!(
                "Unknown provider '{}'. Supported providers: google, github, oidc",
                self.provider
            ));
        }

        println!(
            "\n{} {} {}",
            style("Setting up OAuth2 for").cyan().bold(),
            style(&provider).green().bold(),
            style("...").cyan().bold()
        );

        // Get project root
        let project_root = std::env::current_dir()
            .context("Failed to get current directory")?;

        // Generate configuration snippet
        Self::generate_config_snippet(&project_root, &provider)?;

        // Generate route example
        Self::generate_route_example(&project_root, &provider)?;

        // Generate templates
        Self::generate_templates(&project_root, &provider)?;

        // Print next steps
        Self::print_next_steps(&provider);

        println!(
            "\n{} OAuth2 setup for {} complete!",
            style("✓").green().bold(),
            style(&provider).green().bold()
        );

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn generate_config_snippet(project_root: &Path, provider: &str) -> Result<()> {
        let config_dir = project_root.join("config");
        let config_file = config_dir.join("development.toml");

        // Create config directory if it doesn't exist
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)
                .context("Failed to create config directory")?;
        }

        // Generate provider-specific config
        let config_content = match provider {
            "google" => r#"
# Google OAuth2 Configuration
[oauth2.google]
client_id = "your-google-client-id.apps.googleusercontent.com"
client_secret = "your-google-client-secret"
redirect_uri = "http://localhost:3000/auth/google/callback"
scopes = ["openid", "email", "profile"]
"#,
            "github" => r#"
# GitHub OAuth2 Configuration
[oauth2.github]
client_id = "your-github-client-id"
client_secret = "your-github-client-secret"
redirect_uri = "http://localhost:3000/auth/github/callback"
scopes = ["read:user", "user:email"]
"#,
            "oidc" => r#"
# Generic OIDC Configuration
[oauth2.oidc]
client_id = "your-oidc-client-id"
client_secret = "your-oidc-client-secret"
redirect_uri = "http://localhost:3000/auth/oidc/callback"
scopes = ["openid", "email", "profile"]
# Provider-specific endpoints (auto-discovered if supported)
auth_url = "https://your-provider.com/oauth2/authorize"
token_url = "https://your-provider.com/oauth2/token"
userinfo_url = "https://your-provider.com/oauth2/userinfo"
"#,
            _ => unreachable!(),
        };

        // Append to existing config or create new file
        if config_file.exists() {
            let existing_content = fs::read_to_string(&config_file)?;
            if existing_content.contains(&format!("[oauth2.{provider}]")) {
                println!(
                    "  {} config/development.toml ({} config already exists)",
                    style("Skipped").yellow().bold(),
                    provider
                );
            } else {
                fs::write(&config_file, format!("{existing_content}\n{config_content}"))?;
                println!(
                    "  {} config/development.toml (appended {} config)",
                    style("Updated").yellow().bold(),
                    provider
                );
            }
        } else {
            fs::write(&config_file, config_content)?;
            println!(
                "  {} config/development.toml",
                style("Created").green().bold()
            );
        }

        // Generate .env.example
        let env_example = project_root.join(".env.example");
        let env_content = match provider {
            "google" => r#"
# Google OAuth2 (production)
OAUTH2_GOOGLE_CLIENT_ID="your-google-client-id.apps.googleusercontent.com"
OAUTH2_GOOGLE_CLIENT_SECRET="your-google-client-secret"
OAUTH2_GOOGLE_REDIRECT_URI="https://yourdomain.com/auth/google/callback"
"#,
            "github" => r#"
# GitHub OAuth2 (production)
OAUTH2_GITHUB_CLIENT_ID="your-github-client-id"
OAUTH2_GITHUB_CLIENT_SECRET="your-github-client-secret"
OAUTH2_GITHUB_REDIRECT_URI="https://yourdomain.com/auth/github/callback"
"#,
            "oidc" => r#"
# Generic OIDC (production)
OAUTH2_OIDC_CLIENT_ID="your-oidc-client-id"
OAUTH2_OIDC_CLIENT_SECRET="your-oidc-client-secret"
OAUTH2_OIDC_REDIRECT_URI="https://yourdomain.com/auth/oidc/callback"
OAUTH2_OIDC_AUTH_URL="https://your-provider.com/oauth2/authorize"
OAUTH2_OIDC_TOKEN_URL="https://your-provider.com/oauth2/token"
OAUTH2_OIDC_USERINFO_URL="https://your-provider.com/oauth2/userinfo"
"#,
            _ => unreachable!(),
        };

        if env_example.exists() {
            let existing_env = fs::read_to_string(&env_example)?;
            if existing_env.contains(&format!("OAUTH2_{}", provider.to_uppercase())) {
                println!(
                    "  {} .env.example ({} variables already exist)",
                    style("Skipped").yellow().bold(),
                    provider
                );
            } else {
                fs::write(&env_example, format!("{existing_env}\n{env_content}"))?;
                println!(
                    "  {} .env.example (appended {} variables)",
                    style("Updated").yellow().bold(),
                    provider
                );
            }
        } else {
            fs::write(&env_example, env_content)?;
            println!(
                "  {} .env.example",
                style("Created").green().bold()
            );
        }

        Ok(())
    }

    fn generate_route_example(project_root: &Path, provider: &str) -> Result<()> {
        let docs_dir = project_root.join("docs");
        let examples_dir = docs_dir.join("examples");

        // Create directories if they don't exist
        fs::create_dir_all(&examples_dir)
            .context("Failed to create docs/examples directory")?;

        let route_file = examples_dir.join(format!("{provider}_oauth_routes.rs"));

        let route_content = format!(r#"//! Example OAuth2 routes for {}
//!
//! Add these routes to your main.rs router

use axum::{{routing::{{get, post}}, Router}};
use acton_htmx::oauth2::handlers::{{
    initiate_oauth,
    handle_oauth_callback,
    unlink_oauth_account,
}};
use acton_htmx::state::ActonHtmxState;

pub fn {}_oauth_routes() -> Router<ActonHtmxState> {{
    Router::new()
        .route("/auth/{}", get(initiate_oauth))
        .route("/auth/{}/callback", get(handle_oauth_callback))
        .route("/auth/{}/unlink", post(unlink_oauth_account))
}}

// In your main.rs:
//
// use crate::routes::{}_oauth_routes;
//
// let app = Router::new()
//     .merge({}_oauth_routes())
//     // ... other routes
//     .with_state(state);
"#,
            provider.to_uppercase(),
            provider,
            provider,
            provider,
            provider,
            provider,
            provider
        );

        fs::write(&route_file, route_content)?;
        println!(
            "  {} docs/examples/{}_oauth_routes.rs",
            style("Created").green().bold(),
            provider
        );

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn generate_templates(project_root: &Path, provider: &str) -> Result<()> {
        let templates_dir = project_root.join("templates");
        let auth_dir = templates_dir.join("auth");

        // Create directories if they don't exist
        fs::create_dir_all(&auth_dir)
            .context("Failed to create templates/auth directory")?;

        // Generate login button partial
        let button_file = auth_dir.join(format!("{provider}_button.html"));
        let button_content = match provider {
            "google" => r##"<!-- Google OAuth2 Login Button -->
<a href="/auth/google"
   class="oauth-button oauth-button-google"
   aria-label="Sign in with Google">
    <svg class="oauth-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
    </svg>
    <span>Sign in with Google</span>
</a>
"##,
            "github" => r#"<!-- GitHub OAuth2 Login Button -->
<a href="/auth/github"
   class="oauth-button oauth-button-github"
   aria-label="Sign in with GitHub">
    <svg class="oauth-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" fill="currentColor"/>
    </svg>
    <span>Sign in with GitHub</span>
</a>
"#,
            "oidc" => r#"<!-- Generic OIDC Login Button -->
<a href="/auth/oidc"
   class="oauth-button oauth-button-oidc"
   aria-label="Sign in with SSO">
    <svg class="oauth-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z" fill="currentColor"/>
    </svg>
    <span>Sign in with SSO</span>
</a>
"#,
            _ => unreachable!(),
        };

        fs::write(&button_file, button_content)?;
        println!(
            "  {} templates/auth/{}_button.html",
            style("Created").green().bold(),
            provider
        );

        // Generate account linking template
        let linking_file = auth_dir.join("linked_accounts.html");
        if !linking_file.exists() {
            let linking_content = r#"<!-- OAuth2 Account Linking UI -->
{% extends "base.html" %}

{% block content %}
<div class="account-settings">
    <h2>Linked Accounts</h2>
    <p>Connect your account with social login providers for easier sign-in.</p>

    <div class="linked-accounts-list">
        <!-- Google Account -->
        <div class="account-item">
            <div class="account-provider">
                {% include "auth/google_button.html" %}
            </div>
            {% if google_linked %}
                <div class="account-status">
                    <span class="status-badge status-linked">Linked</span>
                    <span class="account-email">{{ google_email }}</span>
                </div>
                <form hx-post="/auth/google/unlink"
                      hx-confirm="Are you sure you want to unlink your Google account?"
                      hx-swap="outerHTML"
                      hx-target="closest .account-item">
                    {{ csrf_token_with() | safe }}
                    <button type="submit" class="btn btn-sm btn-danger">Unlink</button>
                </form>
            {% else %}
                <div class="account-status">
                    <span class="status-badge status-unlinked">Not linked</span>
                </div>
                <a href="/auth/google?link=true" class="btn btn-sm btn-primary">Link Account</a>
            {% endif %}
        </div>

        <!-- GitHub Account -->
        <div class="account-item">
            <div class="account-provider">
                {% include "auth/github_button.html" %}
            </div>
            {% if github_linked %}
                <div class="account-status">
                    <span class="status-badge status-linked">Linked</span>
                    <span class="account-email">{{ github_username }}</span>
                </div>
                <form hx-post="/auth/github/unlink"
                      hx-confirm="Are you sure you want to unlink your GitHub account?"
                      hx-swap="outerHTML"
                      hx-target="closest .account-item">
                    {{ csrf_token_with() | safe }}
                    <button type="submit" class="btn btn-sm btn-danger">Unlink</button>
                </form>
            {% else %}
                <div class="account-status">
                    <span class="status-badge status-unlinked">Not linked</span>
                </div>
                <a href="/auth/github?link=true" class="btn btn-sm btn-primary">Link Account</a>
            {% endif %}
        </div>
    </div>

    <div class="account-warning">
        <svg class="warning-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z" fill="currentColor"/>
        </svg>
        <p><strong>Note:</strong> You must have at least one authentication method (password or linked account)
           to access your account.</p>
    </div>
</div>
{% endblock %}
"#;
            fs::write(&linking_file, linking_content)?;
            println!(
                "  {} templates/auth/linked_accounts.html",
                style("Created").green().bold()
            );
        }

        // Generate CSS for OAuth buttons
        let static_dir = project_root.join("static");
        let css_dir = static_dir.join("css");
        fs::create_dir_all(&css_dir)
            .context("Failed to create static/css directory")?;

        let oauth_css_file = css_dir.join("oauth.css");
        if !oauth_css_file.exists() {
            let oauth_css = r"/* OAuth2 Button Styles */
.oauth-button {
    display: inline-flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1.5rem;
    border: 1px solid #ddd;
    border-radius: 0.375rem;
    background: white;
    color: #333;
    text-decoration: none;
    font-weight: 500;
    transition: all 0.2s ease;
}

.oauth-button:hover {
    background: #f9f9f9;
    border-color: #999;
    transform: translateY(-1px);
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.oauth-icon {
    width: 20px;
    height: 20px;
}

.oauth-button-google {
    border-color: #4285F4;
}

.oauth-button-google:hover {
    background: #4285F4;
    color: white;
}

.oauth-button-github {
    border-color: #333;
}

.oauth-button-github:hover {
    background: #333;
    color: white;
}

.oauth-button-oidc {
    border-color: #666;
}

.oauth-button-oidc:hover {
    background: #666;
    color: white;
}

/* Account Linking Styles */
.account-settings {
    max-width: 800px;
    margin: 2rem auto;
    padding: 2rem;
}

.linked-accounts-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin: 2rem 0;
}

.account-item {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem;
    border: 1px solid #ddd;
    border-radius: 0.5rem;
}

.account-provider {
    flex: 0 0 200px;
}

.account-status {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.status-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 999px;
    font-size: 0.875rem;
    font-weight: 500;
}

.status-linked {
    background: #d4edda;
    color: #155724;
}

.status-unlinked {
    background: #f8d7da;
    color: #721c24;
}

.account-email {
    color: #666;
    font-size: 0.875rem;
}

.account-warning {
    display: flex;
    gap: 1rem;
    padding: 1rem;
    margin-top: 2rem;
    background: #fff3cd;
    border: 1px solid #ffc107;
    border-radius: 0.375rem;
}

.warning-icon {
    width: 24px;
    height: 24px;
    flex-shrink: 0;
    color: #856404;
}

.account-warning p {
    margin: 0;
    color: #856404;
}
";
            fs::write(&oauth_css_file, oauth_css)?;
            println!(
                "  {} static/css/oauth.css",
                style("Created").green().bold()
            );
        }

        Ok(())
    }

    fn print_next_steps(provider: &str) {
        println!("\n{}", style("Next Steps:").cyan().bold());

        match provider {
            "google" => {
                println!("\n  1. Create Google OAuth2 credentials:");
                println!("     → Visit: https://console.cloud.google.com/");
                println!("     → Navigate to 'APIs & Services' → 'Credentials'");
                println!("     → Create OAuth 2.0 Client ID (Web application)");
                println!("     → Add redirect URI: http://localhost:3000/auth/google/callback");
                println!("\n  2. Update config/development.toml with your credentials");
                println!("     → Replace 'your-google-client-id' with your Client ID");
                println!("     → Replace 'your-google-client-secret' with your Client Secret");
            }
            "github" => {
                println!("\n  1. Create GitHub OAuth App:");
                println!("     → Visit: https://github.com/settings/developers");
                println!("     → Click 'New OAuth App'");
                println!("     → Authorization callback URL: http://localhost:3000/auth/github/callback");
                println!("\n  2. Update config/development.toml with your credentials");
                println!("     → Replace 'your-github-client-id' with your Client ID");
                println!("     → Replace 'your-github-client-secret' with your Client Secret");
            }
            "oidc" => {
                println!("\n  1. Get OIDC provider credentials from your provider");
                println!("     → Check provider documentation for OAuth2/OIDC setup");
                println!("     → Configure redirect URI: http://localhost:3000/auth/oidc/callback");
                println!("\n  2. Update config/development.toml with your credentials");
                println!("     → Replace placeholder values with actual provider details");
                println!("     → Update auth_url, token_url, and userinfo_url if not auto-discovered");
            }
            _ => unreachable!(),
        }

        println!("\n  3. Run database migration:");
        println!("     $ acton-htmx db migrate");

        println!("\n  4. Add OAuth2 routes to your main.rs:");
        println!("     → See example in docs/examples/{provider}_oauth_routes.rs");

        println!("\n  5. Include OAuth button in your login template:");
        println!("     → {{{{ include \"auth/{provider}_button.html\" }}}}");

        println!("\n  6. Link CSS in your base template:");
        println!("     → <link rel=\"stylesheet\" href=\"/static/css/oauth.css\">");

        println!("\n  📚 For detailed setup instructions, see:");
        println!("     docs/guides/07-oauth2.md");
    }
}
