// Simple Cedar policies for acton-htmx
//
// This is a minimal example to get started with Cedar authorization.
// For a complete example with more patterns, see example_blog.cedar

// =============================================================================
// Admin Override
// =============================================================================

// Administrators can do anything
permit(
    principal,
    action,
    resource
)
when {
    principal.roles.contains("admin")
};

// =============================================================================
// Public Access
// =============================================================================

// Allow everyone to access health check
permit(
    principal,
    action == Action::"GET /health",
    resource
);

// Allow everyone to access readiness check
permit(
    principal,
    action == Action::"GET /ready",
    resource
);

// =============================================================================
// Authenticated User Access
// =============================================================================

// Authenticated users can access the dashboard
permit(
    principal,
    action == Action::"GET /dashboard",
    resource
)
when {
    // principal exists (any authenticated user)
    principal
};

// =============================================================================
// Default Deny
// =============================================================================
// If no policy matches, access is denied.
// This is Cedar's secure default behavior.
