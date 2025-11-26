//! Framework template management commands
//!
//! Commands for managing XDG-compliant framework templates:
//! - `init` - Download default templates
//! - `list` - Show installed templates
//! - `diff` - Show changes from default
//! - `reset` - Reset template to default
//! - `edit` - Open template in editor

use anyhow::{Context, Result};
use clap::Subcommand;
use console::{style, Emoji};
use similar::{ChangeTag, TextDiff};
use std::path::PathBuf;

static CHECK: Emoji<'_, '_> = Emoji("✓ ", "");
static CROSS: Emoji<'_, '_> = Emoji("✗ ", "");
static FOLDER: Emoji<'_, '_> = Emoji("📁 ", "");
static FILE: Emoji<'_, '_> = Emoji("📄 ", "");
static DOWNLOAD: Emoji<'_, '_> = Emoji("⬇️  ", "");
static CUSTOM: Emoji<'_, '_> = Emoji("✨ ", "");
static DEFAULT: Emoji<'_, '_> = Emoji("  ", "");

/// Framework template names
const TEMPLATE_NAMES: &[&str] = &[
    "forms/form.html",
    "forms/field-wrapper.html",
    "forms/input.html",
    "forms/textarea.html",
    "forms/select.html",
    "forms/checkbox.html",
    "forms/radio-group.html",
    "forms/submit-button.html",
    "forms/help-text.html",
    "forms/label.html",
    "forms/csrf-input.html",
    "validation/field-errors.html",
    "validation/validation-summary.html",
    "flash/container.html",
    "flash/message.html",
    "htmx/oob-wrapper.html",
    "errors/400.html",
    "errors/401.html",
    "errors/403.html",
    "errors/404.html",
    "errors/422.html",
    "errors/500.html",
];

/// GitHub base URL for framework templates
const GITHUB_RAW_BASE: &str =
    "https://raw.githubusercontent.com/Govcraft/acton-dx/main/acton-dx/src/htmx/template/framework/defaults";

/// Template management subcommands
#[derive(Subcommand)]
pub enum TemplatesCommand {
    /// Initialize framework templates (download defaults)
    Init,
    /// List all templates and their status
    List {
        /// Filter by category (forms, validation, flash, htmx, errors)
        #[arg(long)]
        category: Option<String>,
        /// Show only customized templates
        #[arg(long)]
        customized: bool,
    },
    /// Show diff between customized and default template
    Diff {
        /// Template name (e.g., forms/input.html)
        template: Option<String>,
        /// Show diff for all customized templates
        #[arg(long)]
        all: bool,
    },
    /// Reset template to default
    Reset {
        /// Template name to reset (e.g., forms/input.html)
        template: Option<String>,
        /// Reset all templates
        #[arg(long)]
        all: bool,
    },
    /// Open template in editor for customization
    Edit {
        /// Template name (e.g., forms/input.html)
        template: String,
    },
}

impl TemplatesCommand {
    /// Execute the templates command
    ///
    /// # Errors
    ///
    /// Returns error if template operation fails.
    pub fn execute(self) -> Result<()> {
        match self {
            Self::Init => init_templates(),
            Self::List { category, customized } => list_templates(category.as_deref(), customized),
            Self::Diff { template, all } => diff_templates(template.as_deref(), all),
            Self::Reset { template, all } => reset_templates(template.as_deref(), all),
            Self::Edit { template } => edit_template(&template),
        }
    }
}

/// Get the XDG config directory for framework templates
fn get_config_dir() -> Result<PathBuf> {
    let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        PathBuf::from(home).join(".config")
    };
    Ok(base.join("acton-dx").join("templates").join("framework"))
}

/// Get the XDG cache directory for framework templates
fn get_cache_dir() -> Result<PathBuf> {
    let base = if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        PathBuf::from(home).join(".cache")
    };
    Ok(base.join("acton-dx").join("templates").join("framework"))
}

/// Initialize framework templates by downloading defaults
fn init_templates() -> Result<()> {
    println!("{DOWNLOAD}Initializing framework templates...");
    println!();

    let cache_dir = get_cache_dir()?;
    std::fs::create_dir_all(&cache_dir)?;

    let mut downloaded = 0;
    let mut errors = 0;

    for name in TEMPLATE_NAMES {
        let url = format!("{GITHUB_RAW_BASE}/{name}");
        let path = cache_dir.join(name);

        // Create parent directories
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        match download_template(&url) {
            Ok(content) => {
                std::fs::write(&path, content)?;
                println!("  {CHECK}{}", style(name).green());
                downloaded += 1;
            }
            Err(e) => {
                println!("  {CROSS}{} - {}", style(name).red(), e);
                errors += 1;
            }
        }
    }

    println!();
    println!(
        "{CHECK}Downloaded {} templates to {}",
        downloaded,
        style(cache_dir.display()).cyan()
    );

    if errors > 0 {
        println!("{CROSS}{errors} templates failed to download");
    }

    println!();
    println!("To customize a template:");
    println!("  {} {}", style("acton htmx templates edit").cyan(), style("<template-name>").yellow());
    println!();
    println!("Example:");
    println!("  {} {}", style("acton htmx templates edit").cyan(), style("errors/403.html").yellow());

    Ok(())
}

/// Download a template from GitHub
fn download_template(url: &str) -> Result<String> {
    let response = ureq::get(url)
        .call()
        .with_context(|| format!("Failed to fetch {url}"))?;

    if response.status() != 200 {
        anyhow::bail!("HTTP {}", response.status());
    }

    response
        .into_body()
        .read_to_string()
        .context("Failed to read response body")
}

/// List templates and their customization status
fn list_templates(category: Option<&str>, customized_only: bool) -> Result<()> {
    let config_dir = get_config_dir()?;
    let cache_dir = get_cache_dir()?;

    println!("{FOLDER}Framework Templates");
    println!();
    println!(
        "  Config: {}",
        style(config_dir.display()).cyan()
    );
    println!(
        "  Cache:  {}",
        style(cache_dir.display()).dim()
    );
    println!();

    let mut by_category: std::collections::BTreeMap<&str, Vec<(&str, bool)>> =
        std::collections::BTreeMap::new();

    for name in TEMPLATE_NAMES {
        // Filter by category if specified
        if let Some(cat) = category {
            if !name.starts_with(cat) {
                continue;
            }
        }

        let is_customized = config_dir.join(name).exists();

        // Filter customized if specified
        if customized_only && !is_customized {
            continue;
        }

        let cat = name.split('/').next().unwrap_or("other");
        by_category.entry(cat).or_default().push((name, is_customized));
    }

    let mut total_customized = 0;
    let mut total_default = 0;

    for (cat, templates) in &by_category {
        println!("  {}", style(cat).bold());
        for (name, is_customized) in templates {
            if *is_customized {
                println!("    {CUSTOM}{}", style(name).yellow());
                total_customized += 1;
            } else {
                println!("    {DEFAULT}{}", style(name).dim());
                total_default += 1;
            }
        }
        println!();
    }

    println!(
        "  {} customized, {} default",
        style(total_customized).yellow(),
        style(total_default).dim()
    );

    Ok(())
}

/// Show diff between customized and default template
fn diff_templates(template: Option<&str>, all: bool) -> Result<()> {
    let config_dir = get_config_dir()?;
    let cache_dir = get_cache_dir()?;

    if all {
        // Show diff for all customized templates
        let mut found_any = false;
        for name in TEMPLATE_NAMES {
            let custom_path = config_dir.join(name);
            if custom_path.exists() {
                found_any = true;
                show_single_diff(name, &config_dir, &cache_dir)?;
            }
        }
        if !found_any {
            println!("No customized templates found.");
        }
    } else if let Some(name) = template {
        show_single_diff(name, &config_dir, &cache_dir)?;
    } else {
        anyhow::bail!("Please specify a template name or use --all");
    }

    Ok(())
}

/// Show diff for a single template
fn show_single_diff(name: &str, config_dir: &std::path::Path, cache_dir: &std::path::Path) -> Result<()> {
    let custom_path = config_dir.join(name);
    let default_path = cache_dir.join(name);

    let custom_content = if custom_path.exists() {
        std::fs::read_to_string(&custom_path)?
    } else {
        anyhow::bail!("Template '{name}' is not customized");
    };

    let default_content = if default_path.exists() {
        std::fs::read_to_string(&default_path)?
    } else {
        // Try to download
        let url = format!("{GITHUB_RAW_BASE}/{name}");
        download_template(&url).unwrap_or_else(|_| String::new())
    };

    if default_content.is_empty() {
        println!("Cannot show diff: default template not available");
        println!("Run 'acton htmx templates init' to download defaults");
        return Ok(());
    }

    println!("{FILE}{}", style(name).bold());
    println!();

    let diff = TextDiff::from_lines(&default_content, &custom_content);

    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => {
                print!("{}", style(format!("-{change}")).red());
            }
            ChangeTag::Insert => {
                print!("{}", style(format!("+{change}")).green());
            }
            ChangeTag::Equal => {
                print!(" {change}");
            }
        }
    }
    println!();

    Ok(())
}

/// Reset template to default
fn reset_templates(template: Option<&str>, all: bool) -> Result<()> {
    let config_dir = get_config_dir()?;
    let cache_dir = get_cache_dir()?;

    if all {
        println!("This will reset ALL customized templates to defaults.");
        println!("Your customizations will be lost.");
        println!();

        // Count customized templates
        let customized: Vec<_> = TEMPLATE_NAMES
            .iter()
            .filter(|name| config_dir.join(name).exists())
            .collect();

        if customized.is_empty() {
            println!("No customized templates to reset.");
            return Ok(());
        }

        println!("Templates to reset:");
        for name in &customized {
            println!("  - {name}");
        }
        println!();

        // Ask for confirmation
        println!(
            "Type '{}' to confirm:",
            style("reset").red()
        );

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim() != "reset" {
            println!("Aborted.");
            return Ok(());
        }

        for name in customized {
            let path = config_dir.join(name);
            if path.exists() {
                std::fs::remove_file(&path)?;
                println!("  {CHECK}Reset {name}");
            }
        }
    } else if let Some(name) = template {
        let custom_path = config_dir.join(name);

        if !custom_path.exists() {
            println!("Template '{name}' is not customized (using default)");
            return Ok(());
        }

        // Ensure we have the default to restore
        let default_path = cache_dir.join(name);
        if !default_path.exists() {
            println!("Default template not cached. Run 'acton htmx templates init' first.");
            return Ok(());
        }

        std::fs::remove_file(&custom_path)?;
        println!("{CHECK}Reset {name} to default");
    } else {
        anyhow::bail!("Please specify a template name or use --all");
    }

    Ok(())
}

/// Open template in editor for customization
fn edit_template(name: &str) -> Result<()> {
    // Validate template name
    if !TEMPLATE_NAMES.contains(&name) {
        println!("Unknown template: {}", style(name).red());
        println!();
        println!("Available templates:");
        for t in TEMPLATE_NAMES {
            println!("  - {t}");
        }
        anyhow::bail!("Invalid template name");
    }

    let config_dir = get_config_dir()?;
    let cache_dir = get_cache_dir()?;

    let custom_path = config_dir.join(name);

    // If not customized yet, copy from cache/default
    if !custom_path.exists() {
        // Create parent directories
        if let Some(parent) = custom_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let default_path = cache_dir.join(name);
        if default_path.exists() {
            std::fs::copy(&default_path, &custom_path)?;
        } else {
            // Download from GitHub
            let url = format!("{GITHUB_RAW_BASE}/{name}");
            let content = download_template(&url)?;
            std::fs::write(&custom_path, content)?;
        }

        println!("{CHECK}Created customizable copy at:");
        println!("  {}", style(custom_path.display()).cyan());
        println!();
    }

    // Get editor from environment
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_string());

    println!("Opening {} in {}...", name, style(&editor).cyan());

    std::process::Command::new(&editor)
        .arg(&custom_path)
        .status()
        .with_context(|| format!("Failed to open editor: {editor}"))?;

    println!();
    println!("{CHECK}Template saved. Changes will take effect on next server restart.");
    println!();
    println!("Tip: In development mode, templates hot-reload automatically.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_config_dir() {
        let dir = get_config_dir();
        assert!(dir.is_ok());
        let path = dir.unwrap();
        assert!(path.to_string_lossy().contains("acton-dx"));
        assert!(path.to_string_lossy().contains("framework"));
    }

    #[test]
    fn test_get_cache_dir() {
        let dir = get_cache_dir();
        assert!(dir.is_ok());
        let path = dir.unwrap();
        assert!(path.to_string_lossy().contains("acton-dx"));
    }

    #[test]
    fn test_template_names_valid() {
        for name in TEMPLATE_NAMES {
            assert!(name.contains('/'), "Template name should have category: {name}");
            assert!(
                std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("html")),
                "Template should be HTML: {name}"
            );
        }
    }
}
