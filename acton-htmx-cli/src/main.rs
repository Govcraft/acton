//! acton-htmx CLI tool

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::multiple_crate_versions)]

mod commands;
pub mod templates;

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{DbCommand, DeployCommand, DevCommand, GenerateCommand, JobsCommand, NewCommand, OAuth2Command, ScaffoldCommand};

// Re-export for library usage
pub use templates::ProjectTemplate;

#[derive(Parser)]
#[command(name = "acton-htmx")]
#[command(version)]
#[command(about = "CLI tool for acton-htmx framework", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new acton-htmx project
    New {
        /// Project name
        name: String,
    },
    /// Start development server with hot reload
    Dev,
    /// Database management commands
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },
    /// Generate CRUD scaffold
    Scaffold {
        #[command(subcommand)]
        command: ScaffoldCommands,
    },
    /// Generate code (jobs, models, etc.)
    Generate {
        #[command(subcommand)]
        command: GenerateCommand,
    },
    /// Manage background jobs
    Jobs {
        #[command(subcommand)]
        command: JobsCommand,
    },
    /// Deploy to production
    Deploy {
        #[command(subcommand)]
        command: DeployCommand,
    },
    /// Check application health
    HealthCheck {
        /// Health check URL (default: <http://localhost:8080/health>)
        #[arg(long, default_value = "http://localhost:8080/health")]
        url: String,
    },
}

#[derive(Subcommand)]
enum ScaffoldCommands {
    /// Generate complete CRUD resource
    Crud {
        /// Model name (`PascalCase`, e.g., `Post`, `UserProfile`)
        model: String,
        /// Field definitions (e.g., `title:string`, `author:references:User`)
        #[arg(required = true)]
        fields: Vec<String>,
    },
    /// Set up `OAuth2` authentication for a provider
    OAuth2 {
        /// Provider name (google, github, oidc)
        provider: String,
    },
}

#[derive(Subcommand)]
enum DbCommands {
    /// Run pending migrations
    Migrate,
    /// Reset database (drop, create, migrate)
    Reset,
    /// Create new migration
    Create {
        /// Migration name
        name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::New { name } => {
            let cmd = NewCommand::new(name)?;
            cmd.execute()?;
        }
        Commands::Dev => {
            DevCommand::execute()?;
        }
        Commands::Db { command } => {
            let db_cmd = match command {
                DbCommands::Migrate => DbCommand::Migrate,
                DbCommands::Reset => DbCommand::Reset,
                DbCommands::Create { name } => DbCommand::Create { name },
            };
            db_cmd.execute()?;
        }
        Commands::Scaffold { command } => {
            match command {
                ScaffoldCommands::Crud { model, fields } => {
                    let cmd = ScaffoldCommand::new(model, fields);
                    cmd.execute()?;
                }
                ScaffoldCommands::OAuth2 { provider } => {
                    let cmd = OAuth2Command::new(provider);
                    cmd.execute()?;
                }
            }
        }
        Commands::Generate { command } => {
            command.execute()?;
        }
        Commands::Jobs { command } => {
            command.execute()?;
        }
        Commands::Deploy { command } => {
            command.execute()?;
        }
        Commands::HealthCheck { url } => {
            health_check(&url)?;
        }
    }

    Ok(())
}

/// Check application health
fn health_check(url: &str) -> Result<()> {
    use console::{style, Emoji};

    static CHECKING: Emoji = Emoji("🔍", ">>>");
    static SUCCESS: Emoji = Emoji("✓", "√");
    static ERROR: Emoji = Emoji("✗", "x");

    println!("{} Checking application health at: {}", CHECKING, style(url).cyan());
    println!();

    // Make HTTP request (ureq 3.x call() returns Result with timeout handling)
    let response = ureq::get(url).call();

    match response {
        Ok(mut resp) => {
            let status = resp.status();
            let body = resp.body_mut().read_to_string().unwrap_or_else(|_| "Could not read response".to_string());

            if status == 200 {
                println!("  {SUCCESS} Application is healthy (HTTP {status})");
                println!();
                println!("{}", style("Response:").bold());
                println!("{body}");
                println!();
                Ok(())
            } else {
                println!("  {ERROR} Application health check failed (HTTP {status})");
                println!();
                println!("{}", style("Response:").bold());
                println!("{body}");
                println!();
                anyhow::bail!("Health check returned status: {status}");
            }
        }
        Err(e) => {
            println!("  {ERROR} Health check failed: {e}");
            println!();
            println!("Possible issues:");
            println!("  - Application is not running");
            println!("  - Wrong URL (check host and port)");
            println!("  - Health endpoint not configured");
            println!();
            anyhow::bail!("Could not reach health endpoint");
        }
    }
}
