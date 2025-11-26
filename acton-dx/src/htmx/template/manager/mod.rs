//! Template management system with XDG-compliant storage
//!
//! This module provides a unified template management system for:
//! - **Project templates**: Used by `acton-dx new` for scaffolding new projects
//! - **Scaffold templates**: Used by `acton-dx scaffold` for CRUD generation
//! - **Framework templates**: Runtime templates for forms, flash messages, error pages
//!
//! # XDG Directory Structure
//!
//! Templates follow the XDG Base Directory Specification:
//! - **Config** (`$XDG_CONFIG_HOME/acton-dx/templates/{category}/`): User customizations
//! - **Cache** (`$XDG_CACHE_HOME/acton-dx/templates/{category}/`): Downloaded defaults
//!
//! Resolution order: config (customizations) > cache (downloaded defaults)
//!
//! # Architecture
//!
//! The template system consists of:
//! - [`XdgPaths`]: Handles XDG Base Directory resolution for any template category
//! - [`TemplateConfig`]: Configurable settings including custom GitHub repository URLs
//! - [`TemplateCategory`]: Trait for defining template categories (project, scaffold, framework)
//! - [`TemplateManager`]: Generic template manager that combines the above
//!
//! # Example
//!
//! ```rust,no_run
//! use acton_htmx::template::manager::{TemplateConfig, XdgPaths};
//!
//! // Create XDG paths for a category
//! let paths = XdgPaths::new("project").unwrap();
//! println!("Config: {:?}", paths.config_dir());
//! println!("Cache: {:?}", paths.cache_dir());
//!
//! // Use custom GitHub repository for templates
//! let config = TemplateConfig::new()
//!     .with_github_repo("https://raw.githubusercontent.com/myorg/my-templates")
//!     .with_github_branch("main");
//! ```

mod category;
mod config;
mod core;
mod xdg;

pub use category::{
    FrameworkCategory, ProjectCategory, ScaffoldCategory, TemplateCategory, TemplateMetadata,
};
pub use config::TemplateConfig;
pub use core::{TemplateManager, TemplateManagerError, TemplateSource};
pub use xdg::{XdgError, XdgPaths};
