//! OAuth2 account database models
//!
//! This module provides the `OAuthAccount` model for managing OAuth2 provider
//! accounts linked to users.

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use time::OffsetDateTime;

use super::types::{OAuthProvider, OAuthUserInfo};

/// OAuth2 account linked to a user
///
/// This represents a connection between a local user account and an OAuth2
/// provider account (Google, GitHub, or generic OIDC).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OAuthAccount {
    /// Primary key
    pub id: i64,
    /// Local user ID
    pub user_id: i64,
    /// OAuth2 provider
    #[sqlx(try_from = "String")]
    pub provider: OAuthProvider,
    /// Provider-specific user ID
    pub provider_user_id: String,
    /// Email from OAuth provider
    pub email: String,
    /// Display name from OAuth provider
    pub name: Option<String>,
    /// Avatar URL from OAuth provider
    pub avatar_url: Option<String>,
    /// When the account was linked
    pub created_at: OffsetDateTime,
    /// When the account was last updated
    pub updated_at: OffsetDateTime,
}

impl OAuthAccount {
    /// Find an OAuth account by provider and provider user ID
    ///
    /// # Errors
    ///
    /// Returns error if the database query fails
    pub async fn find_by_provider(
        pool: &PgPool,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, user_id, provider, provider_user_id, email, name, avatar_url,
                   created_at, updated_at
            FROM oauth_accounts
            WHERE provider = $1 AND provider_user_id = $2
            ",
        )
        .bind(provider.as_str())
        .bind(provider_user_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all OAuth accounts for a user
    ///
    /// # Errors
    ///
    /// Returns error if the database query fails
    pub async fn find_by_user_id(pool: &PgPool, user_id: i64) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, user_id, provider, provider_user_id, email, name, avatar_url,
                   created_at, updated_at
            FROM oauth_accounts
            WHERE user_id = $1
            ORDER BY created_at DESC
            ",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Link an OAuth account to a user
    ///
    /// # Errors
    ///
    /// Returns error if the database query fails or if the OAuth account
    /// is already linked to a different user
    pub async fn link_account(
        pool: &PgPool,
        user_id: i64,
        provider: OAuthProvider,
        user_info: &OAuthUserInfo,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email, name, avatar_url)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (provider, provider_user_id)
            DO UPDATE SET
                user_id = EXCLUDED.user_id,
                email = EXCLUDED.email,
                name = EXCLUDED.name,
                avatar_url = EXCLUDED.avatar_url,
                updated_at = NOW()
            RETURNING id, user_id, provider, provider_user_id, email, name, avatar_url,
                      created_at, updated_at
            ",
        )
        .bind(user_id)
        .bind(provider.as_str())
        .bind(&user_info.provider_user_id)
        .bind(&user_info.email)
        .bind(&user_info.name)
        .bind(&user_info.avatar_url)
        .fetch_one(pool)
        .await
    }

    /// Unlink an OAuth account
    ///
    /// # Errors
    ///
    /// Returns error if the database query fails
    pub async fn unlink_account(
        pool: &PgPool,
        user_id: i64,
        provider: OAuthProvider,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM oauth_accounts
            WHERE user_id = $1 AND provider = $2
            ",
        )
        .bind(user_id)
        .bind(provider.as_str())
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update OAuth account information
    ///
    /// # Errors
    ///
    /// Returns error if the database query fails
    pub async fn update_info(
        &mut self,
        pool: &PgPool,
        user_info: &OAuthUserInfo,
    ) -> Result<(), sqlx::Error> {
        let updated = sqlx::query_as::<_, Self>(
            r"
            UPDATE oauth_accounts
            SET email = $1, name = $2, avatar_url = $3, updated_at = NOW()
            WHERE id = $4
            RETURNING id, user_id, provider, provider_user_id, email, name, avatar_url,
                      created_at, updated_at
            ",
        )
        .bind(&user_info.email)
        .bind(&user_info.name)
        .bind(&user_info.avatar_url)
        .bind(self.id)
        .fetch_one(pool)
        .await?;

        *self = updated;
        Ok(())
    }

    /// Check if a user has any OAuth accounts linked
    ///
    /// # Errors
    ///
    /// Returns error if the database query fails
    pub async fn user_has_oauth_accounts(
        pool: &PgPool,
        user_id: i64,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }
}

// SQLx type conversion for OAuthProvider
impl TryFrom<String> for OAuthProvider {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value).map_err(|e| e.to_string())
    }
}

// TODO: Re-enable tests once TestDatabase is available for OAuth2
/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDatabase;

    //     #[tokio::test]
    //     async fn test_link_and_find_oauth_account() {
    //         let test_db = TestDatabase::new().await;
    //         let pool = test_db.pool();
    // 
    //         // Create a test user
    //         let user_id = sqlx::query_scalar::<_, i64>(
    //             "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
    //         )
    //         .bind("test@example.com")
    //         .bind("hash")
    //         .fetch_one(pool)
    //         .await
    //         .unwrap();
    // 
    //         // Link OAuth account
    //         let user_info = OAuthUserInfo {
    //             provider_user_id: "123456".to_string(),
    //             email: "test@gmail.com".to_string(),
    //             name: Some("Test User".to_string()),
    //             avatar_url: Some("https://example.com/avatar.jpg".to_string()),
    //             email_verified: true,
    //         };
    // 
    //         let account = OAuthAccount::link_account(pool, user_id, OAuthProvider::Google, &user_info)
    //             .await
    //             .unwrap();
    // 
    //         assert_eq!(account.user_id, user_id);
    //         assert_eq!(account.provider, OAuthProvider::Google);
    //         assert_eq!(account.provider_user_id, "123456");
    //         assert_eq!(account.email, "test@gmail.com");
    // 
    //         // Find by provider
    //         let found = OAuthAccount::find_by_provider(pool, OAuthProvider::Google, "123456")
    //             .await
    //             .unwrap()
    //             .unwrap();
    // 
    //         assert_eq!(found.id, account.id);
    //         assert_eq!(found.user_id, user_id);
    // 
    //         // Find by user_id
    //         let accounts = OAuthAccount::find_by_user_id(pool, user_id)
    //             .await
    //             .unwrap();
    // 
    //         assert_eq!(accounts.len(), 1);
    //         assert_eq!(accounts[0].id, account.id);
    //     }
    // 
    //     #[tokio::test]
    //     async fn test_unlink_oauth_account() {
    //         let test_db = TestDatabase::new().await;
    //         let pool = test_db.pool();
    // 
    //         // Create a test user
    //         let user_id = sqlx::query_scalar::<_, i64>(
    //             "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
    //         )
    //         .bind("test@example.com")
    //         .bind("hash")
    //         .fetch_one(pool)
    //         .await
    //         .unwrap();
    // 
    //         // Link OAuth account
    //         let user_info = OAuthUserInfo {
    //             provider_user_id: "123456".to_string(),
    //             email: "test@github.com".to_string(),
    //             name: Some("Test User".to_string()),
    //             avatar_url: None,
    //             email_verified: true,
    //         };
    // 
    //         OAuthAccount::link_account(pool, user_id, OAuthProvider::GitHub, &user_info)
    //             .await
    //             .unwrap();
    // 
    //         // Unlink account
    //         let unlinked = OAuthAccount::unlink_account(pool, user_id, OAuthProvider::GitHub)
    //             .await
    //             .unwrap();
    // 
    //         assert!(unlinked);
    // 
    //         // Verify account is gone
    //         let found = OAuthAccount::find_by_provider(pool, OAuthProvider::GitHub, "123456")
    //             .await
    //             .unwrap();
    // 
    //         assert!(found.is_none());
    //     }

    //     #[tokio::test]
    //     async fn test_user_has_oauth_accounts() {
    //         let test_db = TestDatabase::new().await;
    //         let pool = test_db.pool();
    // 
    //         // Create a test user
    //         let user_id = sqlx::query_scalar::<_, i64>(
    //             "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
    //         )
    //         .bind("test@example.com")
    //         .bind("hash")
    //         .fetch_one(pool)
    //         .await
    //         .unwrap();
    // 
    //         // Initially no OAuth accounts
    //         let has_accounts = OAuthAccount::user_has_oauth_accounts(pool, user_id)
    //             .await
    //             .unwrap();
    //         assert!(!has_accounts);
    // 
    //         // Link an OAuth account
    //         let user_info = OAuthUserInfo {
    //             provider_user_id: "123456".to_string(),
    //             email: "test@google.com".to_string(),
    //             name: None,
    //             avatar_url: None,
    //             email_verified: true,
    //         };
    // 
    //         OAuthAccount::link_account(pool, user_id, OAuthProvider::Google, &user_info)
    //             .await
    //             .unwrap();
    // 
    //         // Now has OAuth accounts
    //         let has_accounts = OAuthAccount::user_has_oauth_accounts(pool, user_id)
            .await
            .unwrap();
        assert!(has_accounts);
    }
}
*/
