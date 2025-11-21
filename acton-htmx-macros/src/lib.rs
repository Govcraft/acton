//! Procedural macros for acton-htmx

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]

use proc_macro::TokenStream;

/// Derive macro for form handling (placeholder)
#[proc_macro_derive(AskamaForm)]
pub fn derive_askama_form(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// Derive macro for policy-based authorization (placeholder)
#[proc_macro_derive(Policy)]
pub fn derive_policy(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// Derive macro for model binding (placeholder)
#[proc_macro_derive(ModelBinding)]
pub fn derive_model_binding(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}
