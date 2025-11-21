//! HTMX response types and extractors
//!
//! Type-safe wrappers for HTMX HTTP headers.

#![allow(dead_code)]

// TODO: Implement HTMX types

/// HTMX request extractor
pub struct HxRequest;

/// HTMX response wrapper
pub struct HxResponse;

/// HX-Redirect response
pub struct HxRedirect;

/// HX-Trigger response
pub struct HxTrigger;

/// HX-Swap-OOB response
pub struct HxSwapOob;

/// HX-Reswap response
pub struct HxReswap;

/// HX-Retarget response
pub struct HxRetarget;
