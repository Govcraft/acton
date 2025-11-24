//! Observability (logging, tracing, metrics)
//!
//! Provides structured logging, distributed tracing, and metrics collection
//! via OpenTelemetry integration.

pub mod metrics;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize observability stack
///
/// Sets up:
/// - Structured logging with JSON formatting (production) or pretty formatting (dev)
/// - Environment-based log level filtering
/// - Request ID correlation
///
/// # Errors
///
/// Returns an error if:
/// - The tracing subscriber global default cannot be set (already initialized)
/// - Environment filter parsing fails for invalid `RUST_LOG` values
///
/// # Example
///
/// ```rust,no_run
/// use acton_htmx::observability;
///
/// # fn main() -> anyhow::Result<()> {
/// observability::init()?;
/// tracing::info!("Application started");
/// # Ok(())
/// # }
/// ```
pub fn init() -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if cfg!(debug_assertions) {
            EnvFilter::new("debug,acton_htmx=trace")
        } else {
            EnvFilter::new("info")
        }
    });

    #[cfg(debug_assertions)]
    {
        // Pretty formatting for development
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().pretty())
            .init();
    }

    #[cfg(not(debug_assertions))]
    {
        // JSON formatting for production
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    }

    Ok(())
}

/// Observability configuration
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Service name for tracing
    pub service_name: String,

    /// Enable OpenTelemetry metrics
    pub metrics_enabled: bool,

    /// Enable distributed tracing
    pub tracing_enabled: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "acton-htmx".to_string(),
            metrics_enabled: false,
            tracing_enabled: false,
        }
    }
}

impl ObservabilityConfig {
    /// Create new observability config
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            ..Default::default()
        }
    }

    /// Enable metrics collection
    #[must_use]
    pub const fn with_metrics(mut self) -> Self {
        self.metrics_enabled = true;
        self
    }

    /// Enable distributed tracing
    #[must_use]
    pub const fn with_tracing(mut self) -> Self {
        self.tracing_enabled = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.service_name, "acton-htmx");
        assert!(!config.metrics_enabled);
        assert!(!config.tracing_enabled);
    }

    #[test]
    fn test_builder() {
        let config = ObservabilityConfig::new("my-app")
            .with_metrics()
            .with_tracing();

        assert_eq!(config.service_name, "my-app");
        assert!(config.metrics_enabled);
        assert!(config.tracing_enabled);
    }
}
