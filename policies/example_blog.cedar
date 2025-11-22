// Example Cedar policies for a blog application with HTMX
//
// This file demonstrates Cedar policy-based authorization patterns for acton-htmx.
// Cedar provides declarative, human-readable authorization with support for:
// - Role-based access control (RBAC)
// - Attribute-based access control (ABAC)
// - Resource ownership patterns
// - Time-based restrictions
//
// Usage:
// 1. Copy this file to your application's policies/ directory
// 2. Update policy_path in config: [cedar] policy_path = "policies/blog.cedar"
// 3. Customize for your application's routes and permissions

// =============================================================================
// Admin Override Policy
// =============================================================================
// Administrators can perform any action
permit(
    principal,
    action,
    resource
)
when {
    principal.roles.contains("admin")
};

// =============================================================================
// Public Routes (No Authentication Required)
// =============================================================================

// Allow anyone to view list of posts
permit(
    principal,
    action == Action::"GET /posts",
    resource
);

// Allow anyone to view a single post
permit(
    principal,
    action == Action::"GET /posts/{id}",
    resource
);

// =============================================================================
// Authenticated User Routes
// =============================================================================

// Authenticated users can view the new post form
permit(
    principal,
    action == Action::"GET /posts/new",
    resource
)
when {
    // principal exists (any authenticated user)
    principal
};

// Verified users can create posts
permit(
    principal,
    action == Action::"POST /posts",
    resource
)
when {
    principal has verified &&
    principal.verified == true
};

// =============================================================================
// Owner-Only Routes (Edit, Delete)
// =============================================================================

// Note: For owner-only policies, you would need to pass the post's author_id
// as a resource attribute. This example uses a generic resource.
// In a real application, you would extend build_resource() to include:
//   resource == Post::"123" with attrs { author_id: 456 }

// Users can edit their own posts (or admins can edit any post)
// permit(
//     principal,
//     action == Action::"GET /posts/{id}/edit",
//     resource
// )
// when {
//     principal.id == resource.author_id ||
//     principal.roles.contains("admin")
// };

// Users can update their own posts (or admins can update any post)
// permit(
//     principal,
//     action == Action::"PUT /posts/{id}",
//     resource
// )
// when {
//     principal.id == resource.author_id ||
//     principal.roles.contains("admin")
// };

// Users can delete their own posts (or admins can delete any post)
// permit(
//     principal,
//     action == Action::"DELETE /posts/{id}",
//     resource
// )
// when {
//     principal.id == resource.author_id ||
//     principal.roles.contains("admin")
// };

// =============================================================================
// Moderator Policies
// =============================================================================

// Moderators can delete any post
// permit(
//     principal,
//     action == Action::"DELETE /posts/{id}",
//     resource
// )
// when {
//     principal.roles.contains("moderator")
// };

// =============================================================================
// Time-Based Restrictions (Example)
// =============================================================================

// Prevent post deletion outside business hours (9 AM - 5 PM)
// except for admins
forbid(
    principal,
    action == Action::"DELETE /posts/{id}",
    resource
)
when {
    context has timestamp &&
    (context.timestamp.hour < 9 || context.timestamp.hour >= 17)
}
unless {
    principal.roles.contains("admin")
};

// =============================================================================
// Permission-Based Access (Example)
// =============================================================================

// Users with "posts:publish" permission can publish posts
// (This would be for a separate publish action)
// permit(
//     principal,
//     action == Action::"POST /posts/{id}/publish",
//     resource
// )
// when {
//     principal.permissions.contains("posts:publish")
// };

// =============================================================================
// Default Deny
// =============================================================================
// Cedar uses default deny - if no permit policy matches, access is denied.
// This is the secure default and requires explicit permits for all actions.
