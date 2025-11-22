//! Deployment commands for production environments

use anyhow::{Context, Result};
use clap::Subcommand;
use console::{style, Emoji};
use std::path::PathBuf;
use std::process::Command;

static ROCKET: Emoji = Emoji("🚀", ">>>");
static SUCCESS: Emoji = Emoji("✓", "√");
static ERROR: Emoji = Emoji("✗", "x");

/// Deployment commands
#[derive(Debug, Subcommand)]
pub enum DeployCommand {
    /// Build and push Docker image to registry
    ///
    /// Examples:
    ///   acton-htmx deploy docker
    ///   acton-htmx deploy docker --registry=ghcr.io/myorg
    ///   acton-htmx deploy docker --tag=v1.0.0
    Docker {
        /// Docker registry to push to (e.g., ghcr.io/myorg, docker.io/username)
        #[arg(long)]
        registry: Option<String>,

        /// Image tag (default: latest)
        #[arg(long, default_value = "latest")]
        tag: String,

        /// Build platform (e.g., linux/amd64,linux/arm64)
        #[arg(long)]
        platform: Option<String>,

        /// Skip pushing to registry (build only)
        #[arg(long)]
        no_push: bool,

        /// Dockerfile path
        #[arg(long, default_value = "Dockerfile")]
        dockerfile: PathBuf,
    },
}

impl DeployCommand {
    /// Execute the deploy command
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Docker is not installed
    /// - Build fails
    /// - Push fails
    pub fn execute(&self) -> Result<()> {
        match self {
            Self::Docker {
                registry,
                tag,
                platform,
                no_push,
                dockerfile,
            } => Self::deploy_docker(registry.as_ref(), tag, platform.as_ref(), *no_push, dockerfile),
        }
    }

    fn deploy_docker(
        registry: Option<&String>,
        tag: &str,
        platform: Option<&String>,
        no_push: bool,
        dockerfile: &PathBuf,
    ) -> Result<()> {
        // Check if Docker is installed
        Self::check_docker()?;

        // Check if Dockerfile exists
        if !dockerfile.exists() {
            anyhow::bail!(
                "Dockerfile not found at: {}. Run `acton-htmx generate deployment docker` first.",
                dockerfile.display()
            );
        }

        // Get project name from Cargo.toml
        let project_name = Self::get_project_name()?;

        // Build image name
        let image_name = registry.map_or_else(
            || format!("{project_name}:{tag}"),
            |reg| format!("{reg}/{project_name}:{tag}"),
        );

        println!("{} Building Docker image: {}", ROCKET, style(&image_name).cyan());
        println!();

        // Build Docker command
        let mut docker_build = Command::new("docker");
        docker_build
            .arg("build")
            .arg("-t")
            .arg(&image_name)
            .arg("-f")
            .arg(dockerfile)
            .arg(".");

        // Add platform if specified
        if let Some(plat) = platform {
            docker_build.arg("--platform").arg(plat);
        }

        // Execute build
        let status = docker_build
            .status()
            .context("Failed to execute docker build")?;

        if !status.success() {
            anyhow::bail!("Docker build failed");
        }

        println!();
        println!("  {SUCCESS} Docker image built successfully");

        // Push to registry if not skipped
        println!();
        if no_push {
            println!("  {} Skipping push (--no-push specified)", style("ℹ").blue());
        } else if registry.is_none() {
            println!("  {} Skipping push (no registry specified)", style("ℹ").blue());
            println!();
            println!("  To push to a registry, use:");
            println!("    acton-htmx deploy docker --registry=ghcr.io/myorg");
        } else {
            println!("  {ROCKET} Pushing to registry...");

            let push_status = Command::new("docker")
                .arg("push")
                .arg(&image_name)
                .status()
                .context("Failed to execute docker push")?;

            if !push_status.success() {
                println!();
                println!("  {ERROR} Docker push failed");
                println!();
                println!("  Make sure you're logged in:");
                println!("    docker login {}", registry.as_ref().unwrap().split('/').next().unwrap_or(""));
                anyhow::bail!("Docker push failed");
            }

            println!();
            println!("  {SUCCESS} Docker image pushed successfully");
        }

        println!();
        println!("{}", style("Deployment image ready!").green().bold());
        println!();
        println!("Next steps:");
        println!("  1. Deploy the image to your infrastructure");
        println!("  2. Run migrations: docker exec <container> acton-htmx db migrate");
        println!("  3. Monitor logs and health checks");
        println!();
        println!("Image: {}", style(&image_name).cyan());

        Ok(())
    }

    fn check_docker() -> Result<()> {
        let output = Command::new("docker")
            .arg("--version")
            .output()
            .context("Failed to check Docker installation")?;

        if !output.status.success() {
            anyhow::bail!("Docker is not installed or not in PATH");
        }

        Ok(())
    }

    fn get_project_name() -> Result<String> {
        let cargo_toml = std::fs::read_to_string("Cargo.toml")
            .context("Failed to read Cargo.toml. Are you in a project directory?")?;

        // Simple TOML parsing for project name
        for line in cargo_toml.lines() {
            if line.starts_with("name") {
                if let Some(name) = line.split('=').nth(1) {
                    return Ok(name.trim().trim_matches('"').to_string());
                }
            }
        }

        anyhow::bail!("Could not find project name in Cargo.toml");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_project_name_valid() {
        // This test would need to be in a mock project directory
        // For now, just test the logic
        let toml_content = r#"
[package]
name = "my-app"
version = "1.0.0"
"#;

        // Simple parsing test
        for line in toml_content.lines() {
            if line.starts_with("name") {
                if let Some(name) = line.split('=').nth(1) {
                    let project_name = name.trim().trim_matches('"');
                    assert_eq!(project_name, "my-app");
                }
            }
        }
    }
}
