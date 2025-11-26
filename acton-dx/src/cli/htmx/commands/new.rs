//! Project scaffolding command

use anyhow::{Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::PathBuf;

use super::super::{DatabaseBackend, ProjectTemplateManager};

/// Create a new acton-dx project
pub struct NewCommand {
    name: String,
    output_dir: PathBuf,
    database: DatabaseBackend,
}

impl NewCommand {
    /// Create a new command instance
    ///
    /// # Arguments
    ///
    /// * `name` - Project name (must be valid Rust crate name)
    /// * `database` - Database backend (`SQLite` or `PostgreSQL`)
    ///
    /// # Errors
    ///
    /// Returns an error if the project name is invalid or the directory already exists
    pub fn new(name: String, database: DatabaseBackend) -> Result<Self> {
        // Validate project name (must be valid Rust identifier)
        if !is_valid_crate_name(&name) {
            anyhow::bail!(
                "Invalid project name: {name}. Must be a valid Rust crate name (lowercase, alphanumeric, hyphens, underscores)"
            );
        }

        let output_dir = PathBuf::from(&name);

        // Check if directory already exists
        if output_dir.exists() {
            anyhow::bail!(
                "Directory '{name}' already exists. Please choose a different name or remove the existing directory."
            );
        }

        Ok(Self { name, output_dir, database })
    }

    /// Execute the command
    ///
    /// # Errors
    ///
    /// Returns an error if project creation fails
    pub fn execute(&self) -> Result<()> {
        let db_name = match self.database {
            DatabaseBackend::Sqlite => "SQLite",
            DatabaseBackend::Postgres => "PostgreSQL",
        };

        println!(
            "{} {} {} {} {}",
            style("Creating").green().bold(),
            style("Acton HTMX project:").bold(),
            style(&self.name).cyan().bold(),
            style("with").dim(),
            style(db_name).yellow().bold()
        );
        println!();

        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .context("Failed to set progress style")?,
        );
        spinner.enable_steady_tick(std::time::Duration::from_millis(100));

        // Create project structure
        spinner.set_message("Creating project structure...");
        self.create_structure()?;

        // Generate project files
        spinner.set_message("Generating project files...");
        self.generate_files()?;

        spinner.finish_and_clear();

        // Print success message
        self.print_success();

        Ok(())
    }

    /// Create directory structure
    fn create_structure(&self) -> Result<()> {
        let mut dirs = vec![
            "",
            "src",
            "src/handlers",
            "src/models",
            "templates",
            "templates/layouts",
            "templates/auth",
            "templates/partials",
            "config",
            "migrations",
            "static",
            "static/css",
            "static/js",
            "tests",
        ];

        // Add data directory for SQLite
        if matches!(self.database, DatabaseBackend::Sqlite) {
            dirs.push("data");
        }

        for dir in &dirs {
            let path = self.output_dir.join(dir);
            fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
        }

        // Create .gitkeep in data directory for SQLite
        if matches!(self.database, DatabaseBackend::Sqlite) {
            let gitkeep_path = self.output_dir.join("data/.gitkeep");
            fs::write(&gitkeep_path, "# SQLite database files are stored here\n")
                .with_context(|| format!("Failed to create .gitkeep: {}", gitkeep_path.display()))?;
        }

        Ok(())
    }

    /// Generate project files from templates
    fn generate_files(&self) -> Result<()> {
        let template_manager = ProjectTemplateManager::new()?;

        // Ensure templates are downloaded
        template_manager.ensure_templates(self.database)?;

        // Generate project from templates
        template_manager.generate_project(&self.name, &self.output_dir, self.database)?;

        Ok(())
    }

    /// Print success message with next steps
    fn print_success(&self) {
        println!("{}", style("✓ Project created successfully!").green().bold());
        println!();
        println!("{}", style("Next steps:").bold());
        println!();

        match self.database {
            DatabaseBackend::Sqlite => {
                // SQLite: Zero setup, just run!
                println!("  {} Navigate to project:", style("1.").cyan());
                println!("     {} {}", style("$").dim(), style(format!("cd {}", self.name)).cyan());
                println!();
                println!("  {} Start development server:", style("2.").cyan());
                println!("     {} {}", style("$").dim(), style("acton htmx dev").cyan());
                println!();
                println!("     {} Database is created automatically on first run!", style("✓").green());
                println!();
                println!("  {} Open in browser:", style("3.").cyan());
                println!("     {}", style("http://localhost:3000").cyan().underlined());
            }
            DatabaseBackend::Postgres => {
                // PostgreSQL: Requires database setup
                println!("  {} Navigate to project:", style("1.").cyan());
                println!("     {} {}", style("$").dim(), style(format!("cd {}", self.name)).cyan());
                println!();
                println!("  {} Set up database:", style("2.").cyan());
                let db_name = self.name.replace('-', "_");
                println!("     {} {}", style("$").dim(), style(format!("createdb {db_name}_dev")).cyan());
                println!("     {} {}", style("$").dim(), style("acton htmx db migrate").cyan());
                println!();
                println!("  {} Start development server:", style("3.").cyan());
                println!("     {} {}", style("$").dim(), style("acton htmx dev").cyan());
                println!();
                println!("  {} Open in browser:", style("4.").cyan());
                println!("     {}", style("http://localhost:3000").cyan().underlined());
            }
        }

        println!();
        println!(
            "{}",
            style("Happy building with Acton HTMX! 🚀").green().bold()
        );
    }
}

/// Validate that a string is a valid Rust crate name
fn is_valid_crate_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // Must start with letter or underscore
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_lowercase() && first_char != '_' {
        return false;
    }

    // All characters must be alphanumeric, underscore, or hyphen
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_crate_names() {
        assert!(is_valid_crate_name("my_project"));
        assert!(is_valid_crate_name("my-project"));
        assert!(is_valid_crate_name("myproject"));
        assert!(is_valid_crate_name("my_project_123"));
        assert!(is_valid_crate_name("_private"));
    }

    #[test]
    fn test_invalid_crate_names() {
        assert!(!is_valid_crate_name(""));
        assert!(!is_valid_crate_name("MyProject")); // uppercase
        assert!(!is_valid_crate_name("123project")); // starts with number
        assert!(!is_valid_crate_name("my project")); // space
        assert!(!is_valid_crate_name("my.project")); // dot
        assert!(!is_valid_crate_name("my@project")); // special char
    }

    #[test]
    fn test_new_command_validates_name() {
        let result = NewCommand::new("InvalidName".to_string(), DatabaseBackend::Sqlite);
        assert!(result.is_err());

        let result = NewCommand::new("valid_name".to_string(), DatabaseBackend::Sqlite);
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_command_accepts_database_backend() {
        let result = NewCommand::new("test_sqlite".to_string(), DatabaseBackend::Sqlite);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap().database, DatabaseBackend::Sqlite));

        let result = NewCommand::new("test_postgres".to_string(), DatabaseBackend::Postgres);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap().database, DatabaseBackend::Postgres));
    }
}
