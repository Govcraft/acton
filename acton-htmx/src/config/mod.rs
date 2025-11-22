//! Configuration management for acton-htmx
//!
//! Extends acton-service's XDG-compliant configuration system with HTMX-specific
//! settings. Configuration is loaded from multiple sources with clear precedence:
//!
//! 1. Environment variables (highest priority, `ACTON_` prefix)
//! 2. `./config.toml` (development)
//! 3. `~/.config/acton-htmx/config.toml` (user config, XDG)
//! 4. `/etc/acton-htmx/config.toml` (system config)
//! 5. Hardcoded defaults (fallback)
//!
//! # Example Configuration
//!
//! ```toml
//! # config.toml
//! [service]
//! name = "my-htmx-app"
//! port = 3000
//!
//! [database]
//! url = "sqlite://./dev.db"
//! optional = true
//! lazy_init = true
//!
//! [htmx]
//! request_timeout_ms = 5000
//! history_enabled = true
//! auto_vary = true
//!
//! [templates]
//! template_dir = "./templates"
//! cache_enabled = true
//! hot_reload = true
//!
//! [security]
//! csrf_enabled = true
//! session_max_age_secs = 86400
//! ```
//!
//! # Usage
//!
//! ```rust
//! use acton_htmx::config::ActonHtmxConfig;
//!
//! // Load default configuration
//! let config = ActonHtmxConfig::default();
//!
//! // Access HTMX-specific config
//! let timeout = config.htmx.request_timeout_ms;
//! let csrf_enabled = config.security.csrf_enabled;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::oauth2::types::OAuthConfig;

/// HTMX-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HtmxSettings {
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,

    /// Enable HTMX history support
    pub history_enabled: bool,

    /// Enable auto-vary middleware for caching
    pub auto_vary: bool,

    /// Enable request guards for HTMX-only routes
    pub guards_enabled: bool,
}

impl Default for HtmxSettings {
    fn default() -> Self {
        Self {
            request_timeout_ms: 5000,
            history_enabled: true,
            auto_vary: true,
            guards_enabled: false,
        }
    }
}

/// Template engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TemplateSettings {
    /// Directory containing Askama templates
    pub template_dir: PathBuf,

    /// Enable template caching
    pub cache_enabled: bool,

    /// Enable hot reload in development
    pub hot_reload: bool,

    /// Template file extensions to watch
    pub watch_extensions: Vec<String>,
}

impl Default for TemplateSettings {
    fn default() -> Self {
        Self {
            template_dir: PathBuf::from("./templates"),
            cache_enabled: true,
            hot_reload: cfg!(debug_assertions),
            watch_extensions: vec!["html".to_string(), "jinja".to_string()],
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecuritySettings {
    /// Enable CSRF protection
    pub csrf_enabled: bool,

    /// Session maximum age in seconds
    pub session_max_age_secs: u64,

    /// Enable secure cookies (HTTPS only)
    pub secure_cookies: bool,

    /// Cookie `SameSite` policy
    pub same_site: SameSitePolicy,

    /// Enable security headers middleware
    pub security_headers_enabled: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            csrf_enabled: true,
            session_max_age_secs: 86400, // 24 hours
            secure_cookies: !cfg!(debug_assertions),
            same_site: SameSitePolicy::Lax,
            security_headers_enabled: true,
        }
    }
}

/// Cookie `SameSite` policy
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSitePolicy {
    /// Strict `SameSite` policy
    Strict,
    /// Lax `SameSite` policy (recommended)
    Lax,
    /// None `SameSite` policy (requires secure cookies)
    None,
}

/// Complete acton-htmx configuration
///
/// Combines framework configuration with HTMX-specific settings.
/// Uses `#[serde(flatten)]` to merge all fields into a single `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActonHtmxConfig {
    /// HTMX-specific settings
    #[serde(default)]
    pub htmx: HtmxSettings,

    /// Template engine settings
    #[serde(default)]
    pub templates: TemplateSettings,

    /// Security settings
    #[serde(default)]
    pub security: SecuritySettings,

    /// OAuth2 configuration
    #[serde(default)]
    pub oauth2: OAuthConfig,

    /// Feature flags
    #[serde(default)]
    pub features: HashMap<String, bool>,
}

impl ActonHtmxConfig {
    /// Load configuration for a specific service
    ///
    /// Searches for configuration in XDG-compliant locations with precedence:
    /// 1. Environment variables (`ACTON_*`)
    /// 2. `./config.toml`
    /// 3. `~/.config/acton-htmx/{service_name}/config.toml`
    /// 4. `/etc/acton-htmx/{service_name}/config.toml`
    /// 5. Defaults
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use acton_htmx::config::ActonHtmxConfig;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let config = ActonHtmxConfig::load_for_service("my-app")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_for_service(_service_name: &str) -> anyhow::Result<Self> {
        // TODO: Implement using figment
        // For now, return default config
        Ok(Self::default())
    }

    /// Load configuration from a specific file
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use acton_htmx::config::ActonHtmxConfig;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let config = ActonHtmxConfig::load_from("./config/production.toml")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_from(_path: &str) -> anyhow::Result<Self> {
        // TODO: Implement using figment
        Ok(Self::default())
    }

    /// Get the recommended XDG config path for a service
    ///
    /// # Example
    ///
    /// ```rust
    /// use acton_htmx::config::ActonHtmxConfig;
    ///
    /// let path = ActonHtmxConfig::recommended_path("my-app");
    /// // Returns: ~/.config/acton-htmx/my-app/config.toml
    /// ```
    #[must_use]
    pub fn recommended_path(_service_name: &str) -> PathBuf {
        // TODO: Implement XDG path resolution
        PathBuf::from("./config.toml")
    }

    /// Create config directory for a service
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use acton_htmx::config::ActonHtmxConfig;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// ActonHtmxConfig::create_config_dir("my-app")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_config_dir(_service_name: &str) -> anyhow::Result<PathBuf> {
        // TODO: Implement directory creation
        Ok(PathBuf::from("./config"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ActonHtmxConfig::default();
        assert_eq!(config.htmx.request_timeout_ms, 5000);
        assert!(config.htmx.history_enabled);
        assert!(config.htmx.auto_vary);
        assert!(config.security.csrf_enabled);
        assert_eq!(config.security.session_max_age_secs, 86400);
    }

    #[test]
    fn test_template_defaults() {
        let templates = TemplateSettings::default();
        assert_eq!(templates.template_dir, PathBuf::from("./templates"));
        assert!(templates.cache_enabled);
        assert_eq!(templates.watch_extensions, vec!["html", "jinja"]);
    }

    #[test]
    fn test_security_defaults() {
        let security = SecuritySettings::default();
        assert!(security.csrf_enabled);
        assert!(security.security_headers_enabled);

        // secure_cookies should be true in release, false in debug
        #[cfg(debug_assertions)]
        assert!(!security.secure_cookies);

        #[cfg(not(debug_assertions))]
        assert!(security.secure_cookies);
    }
}
