//! OAuth2 provider implementations
//!
//! This module contains implementations for various OAuth2 providers:
//! - Google OAuth2 (with OpenID Connect)
//! - GitHub OAuth2
//! - Generic OpenID Connect provider

pub mod github;
pub mod google;
pub mod oidc;

pub use github::GitHubProvider;
pub use google::GoogleProvider;
pub use oidc::OidcProvider;
