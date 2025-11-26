//! XDG Base Directory Specification support
//!
//! Provides paths for template storage following the XDG specification:
//! - Config: `$XDG_CONFIG_HOME/acton-dx/templates/{category}/` (user customizations)
//! - Cache: `$XDG_CACHE_HOME/acton-dx/templates/{category}/` (downloaded defaults)

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur when resolving XDG directories
#[derive(Debug, Error)]
pub enum XdgError {
    /// Home directory could not be determined
    #[error("could not determine home directory")]
    NoHomeDirectory,

    /// Failed to create directory
    #[error("failed to create directory '{path}': {source}")]
    CreateDirectoryFailed {
        /// The path that could not be created
        path: PathBuf,
        /// The underlying IO error
        source: std::io::Error,
    },
}

/// XDG-compliant paths for a template category
///
/// Manages paths for both configuration (user customizations) and cache
/// (downloaded defaults) directories.
#[derive(Debug, Clone)]
pub struct XdgPaths {
    /// Config directory for user customizations
    config_dir: PathBuf,
    /// Cache directory for downloaded defaults
    cache_dir: PathBuf,
}

impl XdgPaths {
    /// Create XDG paths for a template category
    ///
    /// # Arguments
    ///
    /// * `category` - The template category name (e.g., "project", "scaffold", "framework")
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use acton_dx::template::manager::XdgPaths;
    ///
    /// let paths = XdgPaths::new("project").unwrap();
    /// println!("Config: {:?}", paths.config_dir());
    /// println!("Cache: {:?}", paths.cache_dir());
    /// ```
    pub fn new(category: &str) -> Result<Self, XdgError> {
        let config_dir = Self::resolve_config_dir(category)?;
        let cache_dir = Self::resolve_cache_dir(category)?;

        Ok(Self {
            config_dir,
            cache_dir,
        })
    }

    /// Ensure both directories exist
    ///
    /// Creates the config and cache directories if they don't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if directories cannot be created.
    pub fn ensure_directories(&self) -> Result<(), XdgError> {
        std::fs::create_dir_all(&self.config_dir).map_err(|e| XdgError::CreateDirectoryFailed {
            path: self.config_dir.clone(),
            source: e,
        })?;

        std::fs::create_dir_all(&self.cache_dir).map_err(|e| XdgError::CreateDirectoryFailed {
            path: self.cache_dir.clone(),
            source: e,
        })?;

        Ok(())
    }

    /// Get the config directory path (user customizations)
    #[must_use]
    pub fn config_dir(&self) -> &PathBuf {
        &self.config_dir
    }

    /// Get the cache directory path (downloaded defaults)
    #[must_use]
    pub fn cache_dir(&self) -> &PathBuf {
        &self.cache_dir
    }

    /// Resolve the full path for a template in config directory
    #[must_use]
    pub fn config_path(&self, template_name: &str) -> PathBuf {
        self.config_dir.join(template_name)
    }

    /// Resolve the full path for a template in cache directory
    #[must_use]
    pub fn cache_path(&self, template_name: &str) -> PathBuf {
        self.cache_dir.join(template_name)
    }

    /// Check if a template exists in config (user customization)
    #[must_use]
    pub fn has_config_template(&self, template_name: &str) -> bool {
        self.config_path(template_name).exists()
    }

    /// Check if a template exists in cache (downloaded default)
    #[must_use]
    pub fn has_cache_template(&self, template_name: &str) -> bool {
        self.cache_path(template_name).exists()
    }

    /// Check if a template exists in either location
    #[must_use]
    pub fn has_template(&self, template_name: &str) -> bool {
        self.has_config_template(template_name) || self.has_cache_template(template_name)
    }

    /// Resolve template path with priority: config > cache
    ///
    /// Returns the path where the template exists, preferring config over cache.
    #[must_use]
    pub fn resolve_template(&self, template_name: &str) -> Option<PathBuf> {
        let config_path = self.config_path(template_name);
        if config_path.exists() {
            return Some(config_path);
        }

        let cache_path = self.cache_path(template_name);
        if cache_path.exists() {
            return Some(cache_path);
        }

        None
    }

    /// Resolve XDG config base directory
    fn resolve_config_dir(category: &str) -> Result<PathBuf, XdgError> {
        let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg)
        } else {
            dirs::home_dir()
                .ok_or(XdgError::NoHomeDirectory)?
                .join(".config")
        };

        Ok(base.join("acton-dx").join("templates").join(category))
    }

    /// Resolve XDG cache base directory
    fn resolve_cache_dir(category: &str) -> Result<PathBuf, XdgError> {
        let base = if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            PathBuf::from(xdg)
        } else {
            dirs::home_dir()
                .ok_or(XdgError::NoHomeDirectory)?
                .join(".cache")
        };

        Ok(base.join("acton-dx").join("templates").join(category))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_xdg_config_home_override() {
        env::set_var("XDG_CONFIG_HOME", "/tmp/test-xdg-config");
        let paths = XdgPaths::new("project").unwrap();
        assert_eq!(
            paths.config_dir(),
            &PathBuf::from("/tmp/test-xdg-config/acton-dx/templates/project")
        );
        env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn test_xdg_cache_home_override() {
        env::set_var("XDG_CACHE_HOME", "/tmp/test-xdg-cache");
        let paths = XdgPaths::new("scaffold").unwrap();
        assert_eq!(
            paths.cache_dir(),
            &PathBuf::from("/tmp/test-xdg-cache/acton-dx/templates/scaffold")
        );
        env::remove_var("XDG_CACHE_HOME");
    }

    #[test]
    fn test_config_path() {
        env::set_var("XDG_CONFIG_HOME", "/tmp/test-config");
        let paths = XdgPaths::new("framework").unwrap();
        let template_path = paths.config_path("forms/input.html");
        assert_eq!(
            template_path,
            PathBuf::from("/tmp/test-config/acton-dx/templates/framework/forms/input.html")
        );
        env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn test_cache_path() {
        env::set_var("XDG_CACHE_HOME", "/tmp/test-cache");
        let paths = XdgPaths::new("project").unwrap();
        let template_path = paths.cache_path("common/Cargo.toml.jinja");
        assert_eq!(
            template_path,
            PathBuf::from("/tmp/test-cache/acton-dx/templates/project/common/Cargo.toml.jinja")
        );
        env::remove_var("XDG_CACHE_HOME");
    }

    #[test]
    fn test_has_template_returns_false_for_missing() {
        env::set_var("XDG_CONFIG_HOME", "/tmp/nonexistent-config");
        env::set_var("XDG_CACHE_HOME", "/tmp/nonexistent-cache");
        let paths = XdgPaths::new("test").unwrap();
        assert!(!paths.has_template("nonexistent.jinja"));
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("XDG_CACHE_HOME");
    }

    #[test]
    fn test_resolve_template_returns_none_for_missing() {
        env::set_var("XDG_CONFIG_HOME", "/tmp/nonexistent-config2");
        env::set_var("XDG_CACHE_HOME", "/tmp/nonexistent-cache2");
        let paths = XdgPaths::new("test").unwrap();
        assert!(paths.resolve_template("missing.jinja").is_none());
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("XDG_CACHE_HOME");
    }
}
