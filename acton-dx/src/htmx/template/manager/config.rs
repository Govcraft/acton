//! Template configuration
//!
//! Provides configurable settings for template management, including
//! customizable GitHub repository URLs for template downloads.

use serde::{Deserialize, Serialize};

/// Configuration for template management
///
/// This allows framework users to customize where templates are downloaded from,
/// enabling them to fork the default templates and point to their own repository.
///
/// # Examples
///
/// ```rust
/// use acton_dx::template::manager::TemplateConfig;
///
/// // Use default configuration (official acton-dx templates)
/// let config = TemplateConfig::default();
///
/// // Or point to a custom fork
/// let custom_config = TemplateConfig::new()
///     .with_github_repo("https://raw.githubusercontent.com/myorg/my-templates")
///     .with_github_branch("main");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Base URL for raw GitHub content
    ///
    /// Default: `https://raw.githubusercontent.com/Govcraft/acton-dx`
    pub github_repo: String,

    /// Branch to download templates from
    ///
    /// Default: `main`
    pub github_branch: String,

    /// Whether to use the cache directory
    ///
    /// When disabled, templates are downloaded fresh each time.
    /// Default: `true`
    pub cache_enabled: bool,

    /// Whether to automatically download missing templates
    ///
    /// When enabled, missing templates are downloaded automatically.
    /// When disabled, missing templates result in an error.
    /// Default: `true`
    pub auto_download: bool,
}

impl TemplateConfig {
    /// Create a new template configuration with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom GitHub repository URL
    ///
    /// # Arguments
    ///
    /// * `repo` - The base URL for raw GitHub content (without trailing slash)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use acton_dx::template::manager::TemplateConfig;
    ///
    /// let config = TemplateConfig::new()
    ///     .with_github_repo("https://raw.githubusercontent.com/myorg/my-templates");
    /// ```
    #[must_use]
    pub fn with_github_repo(mut self, repo: impl Into<String>) -> Self {
        self.github_repo = repo.into();
        self
    }

    /// Set a custom branch name
    ///
    /// # Arguments
    ///
    /// * `branch` - The branch name to download templates from
    ///
    /// # Examples
    ///
    /// ```rust
    /// use acton_dx::template::manager::TemplateConfig;
    ///
    /// let config = TemplateConfig::new()
    ///     .with_github_branch("develop");
    /// ```
    #[must_use]
    pub fn with_github_branch(mut self, branch: impl Into<String>) -> Self {
        self.github_branch = branch.into();
        self
    }

    /// Enable or disable caching
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to cache downloaded templates
    #[must_use]
    pub const fn with_cache(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Enable or disable automatic downloads
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to automatically download missing templates
    #[must_use]
    pub const fn with_auto_download(mut self, enabled: bool) -> Self {
        self.auto_download = enabled;
        self
    }

    /// Build the full URL for downloading a template
    ///
    /// # Arguments
    ///
    /// * `category` - The template category (e.g., "project", "scaffold", "framework")
    /// * `template_name` - The template file name
    ///
    /// # Examples
    ///
    /// ```rust
    /// use acton_dx::template::manager::TemplateConfig;
    ///
    /// let config = TemplateConfig::default();
    /// let url = config.template_url("project", "common/Cargo.toml.jinja");
    /// assert!(url.contains("templates/project/common/Cargo.toml.jinja"));
    /// ```
    #[must_use]
    pub fn template_url(&self, category: &str, template_name: &str) -> String {
        format!(
            "{}/{}/templates/{}/{}",
            self.github_repo, self.github_branch, category, template_name
        )
    }
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            github_repo: "https://raw.githubusercontent.com/Govcraft/acton-dx".to_string(),
            github_branch: "main".to_string(),
            cache_enabled: true,
            auto_download: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TemplateConfig::default();
        assert!(config.github_repo.contains("Govcraft/acton-dx"));
        assert_eq!(config.github_branch, "main");
        assert!(config.cache_enabled);
        assert!(config.auto_download);
    }

    #[test]
    fn test_custom_repo() {
        let config =
            TemplateConfig::new().with_github_repo("https://raw.githubusercontent.com/myorg/repo");
        assert!(config.github_repo.contains("myorg/repo"));
    }

    #[test]
    fn test_custom_branch() {
        let config = TemplateConfig::new().with_github_branch("develop");
        assert_eq!(config.github_branch, "develop");
    }

    #[test]
    fn test_template_url() {
        let config = TemplateConfig::default();
        let url = config.template_url("project", "common/main.rs.jinja");
        assert_eq!(
            url,
            "https://raw.githubusercontent.com/Govcraft/acton-dx/main/templates/project/common/main.rs.jinja"
        );
    }

    #[test]
    fn test_custom_template_url() {
        let config = TemplateConfig::new()
            .with_github_repo("https://raw.githubusercontent.com/myorg/templates")
            .with_github_branch("v2");

        let url = config.template_url("scaffold", "model.rs.jinja");
        assert_eq!(
            url,
            "https://raw.githubusercontent.com/myorg/templates/v2/templates/scaffold/model.rs.jinja"
        );
    }

    #[test]
    fn test_disable_cache() {
        let config = TemplateConfig::new().with_cache(false);
        assert!(!config.cache_enabled);
    }

    #[test]
    fn test_disable_auto_download() {
        let config = TemplateConfig::new().with_auto_download(false);
        assert!(!config.auto_download);
    }

    #[test]
    fn test_builder_chain() {
        let config = TemplateConfig::new()
            .with_github_repo("https://example.com")
            .with_github_branch("feature")
            .with_cache(false)
            .with_auto_download(false);

        assert_eq!(config.github_repo, "https://example.com");
        assert_eq!(config.github_branch, "feature");
        assert!(!config.cache_enabled);
        assert!(!config.auto_download);
    }
}
