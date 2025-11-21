//! Authentication and session management

#![allow(dead_code)]

// TODO: Implement authentication

/// Authenticated user extractor
pub struct Authenticated<T>(std::marker::PhantomData<T>);

/// Optional authentication extractor
pub struct OptionalAuth<T>(std::marker::PhantomData<T>);

/// Session data
pub struct Session;
