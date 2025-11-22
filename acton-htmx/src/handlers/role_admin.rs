//! Role management handlers
//!
//! This module provides HTTP handlers for managing user roles.
//! These handlers should be protected with admin-only authorization.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use acton_htmx::handlers::role_admin;
//! use axum::Router;
//!
//! let admin_routes = Router::new()
//!     .route("/admin/users/:id/roles", get(role_admin::get_user_roles))
//!     .route("/admin/users/:id/roles", post(role_admin::assign_role))
//!     .route("/admin/users/:id/roles/:role", delete(role_admin::remove_role));
//! ```

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::auth::{user::User, Authenticated};

/// Request body for assigning a role to a user
#[derive(Debug, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    /// The role to assign (e.g., "admin", "moderator", "user")
    pub role: String,
}

/// Response for role operations
#[derive(Debug, Serialize, Deserialize)]
pub struct RoleResponse {
    /// User ID
    pub user_id: i64,

    /// Current roles for the user
    pub roles: Vec<String>,

    /// Success message
    pub message: String,
}

/// Get roles for a specific user
///
/// Returns the current roles assigned to a user.
/// Requires admin role.
///
/// # Example
///
/// ```bash
/// GET /admin/users/123/roles
/// ```
///
/// Response:
/// ```json
/// {
///   "user_id": 123,
///   "roles": ["user", "moderator"],
///   "message": "Roles retrieved successfully"
/// }
/// ```
pub async fn get_user_roles(
    State(db): State<PgPool>,
    Authenticated(admin): Authenticated<User>,
    Path(user_id): Path<i64>,
) -> Result<Response, StatusCode> {
    // Verify admin role
    if !admin.roles.contains(&"admin".to_string()) {
        tracing::warn!(
            admin_id = admin.id,
            user_id = user_id,
            "Non-admin attempted to view user roles"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Fetch user
    let user = match User::find_by_id(user_id, &db).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(error = ?e, user_id = user_id, "Failed to fetch user");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    let response = RoleResponse {
        user_id: user.id,
        roles: user.roles,
        message: "Roles retrieved successfully".to_string(),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Assign a role to a user
///
/// Adds a role to the user's roles list if not already present.
/// Requires admin role.
///
/// # Example
///
/// ```bash
/// POST /admin/users/123/roles
/// Content-Type: application/json
///
/// {
///   "role": "moderator"
/// }
/// ```
///
/// Response:
/// ```json
/// {
///   "user_id": 123,
///   "roles": ["user", "moderator"],
///   "message": "Role 'moderator' assigned successfully"
/// }
/// ```
#[allow(clippy::cognitive_complexity)] // Complex role validation and database logic
pub async fn assign_role(
    State(db): State<PgPool>,
    Authenticated(admin): Authenticated<User>,
    Path(user_id): Path<i64>,
    Json(request): Json<AssignRoleRequest>,
) -> Result<Response, StatusCode> {
    // Verify admin role
    if !admin.roles.contains(&"admin".to_string()) {
        tracing::warn!(
            admin_id = admin.id,
            user_id = user_id,
            role = %request.role,
            "Non-admin attempted to assign role"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate role name
    let valid_roles = ["user", "moderator", "admin"];
    if !valid_roles.contains(&request.role.as_str()) {
        tracing::warn!(role = %request.role, "Invalid role name");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Fetch user
    let mut user = match User::find_by_id(user_id, &db).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(error = ?e, user_id = user_id, "Failed to fetch user");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Add role if not already present
    if !user.roles.contains(&request.role) {
        user.roles.push(request.role.clone());

        // Update user in database
        match sqlx::query(
            r"UPDATE users SET roles = $1 WHERE id = $2"
        )
        .bind(&user.roles)
        .bind(user.id)
        .execute(&db)
        .await
        {
            Ok(_) => {
                tracing::info!(
                    admin_id = admin.id,
                    user_id = user.id,
                    role = %request.role,
                    "Role assigned successfully"
                );
            }
            Err(e) => {
                tracing::error!(error = ?e, user_id = user.id, "Failed to update user roles");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    let response = RoleResponse {
        user_id: user.id,
        roles: user.roles.clone(),
        message: format!("Role '{}' assigned successfully", request.role),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Remove a role from a user
///
/// Removes a role from the user's roles list.
/// Requires admin role.
///
/// # Example
///
/// ```bash
/// DELETE /admin/users/123/roles/moderator
/// ```
///
/// Response:
/// ```json
/// {
///   "user_id": 123,
///   "roles": ["user"],
///   "message": "Role 'moderator' removed successfully"
/// }
/// ```
#[allow(clippy::cognitive_complexity)] // Complex role validation and database logic
pub async fn remove_role(
    State(db): State<PgPool>,
    Authenticated(admin): Authenticated<User>,
    Path((user_id, role)): Path<(i64, String)>,
) -> Result<Response, StatusCode> {
    // Verify admin role
    if !admin.roles.contains(&"admin".to_string()) {
        tracing::warn!(
            admin_id = admin.id,
            user_id = user_id,
            role = %role,
            "Non-admin attempted to remove role"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Fetch user
    let mut user = match User::find_by_id(user_id, &db).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(error = ?e, user_id = user_id, "Failed to fetch user");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Prevent removing the "user" role (everyone should have at least "user")
    if role == "user" {
        tracing::warn!(
            admin_id = admin.id,
            user_id = user.id,
            "Attempted to remove required 'user' role"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Remove role
    user.roles.retain(|r| r != &role);

    // Update user in database
    match sqlx::query(
        r"UPDATE users SET roles = $1 WHERE id = $2"
    )
    .bind(&user.roles)
    .bind(user.id)
    .execute(&db)
    .await
    {
        Ok(_) => {
            tracing::info!(
                admin_id = admin.id,
                user_id = user.id,
                role = %role,
                "Role removed successfully"
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, user_id = user.id, "Failed to update user roles");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let response = RoleResponse {
        user_id: user.id,
        roles: user.roles.clone(),
        message: format!("Role '{role}' removed successfully"),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_role_request_serialization() {
        let request = AssignRoleRequest {
            role: "moderator".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("moderator"));
    }

    #[test]
    fn test_role_response_serialization() {
        let response = RoleResponse {
            user_id: 123,
            roles: vec!["user".to_string(), "moderator".to_string()],
            message: "Success".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"user_id\":123"));
        assert!(json.contains("moderator"));
    }
}
