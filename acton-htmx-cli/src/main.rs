//! acton-htmx CLI tool

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "acton-htmx")]
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
    /// Run database migrations
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },
}

#[derive(Subcommand)]
enum DbCommands {
    /// Run pending migrations
    Migrate,
    /// Reset database
    Reset,
    /// Create new migration
    Create {
        /// Migration name
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::New { name } => {
            println!("Creating new project: {name}");
            Ok(())
        }
        Commands::Dev => {
            println!("Starting development server...");
            Ok(())
        }
        Commands::Db { command } => match command {
            DbCommands::Migrate => {
                println!("Running migrations...");
                Ok(())
            }
            DbCommands::Reset => {
                println!("Resetting database...");
                Ok(())
            }
            DbCommands::Create { name } => {
                println!("Creating migration: {name}");
                Ok(())
            }
        },
    }
}
