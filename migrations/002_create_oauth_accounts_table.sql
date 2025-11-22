-- Create oauth_accounts table for OAuth2 authentication
--
-- This migration creates the oauth_accounts table for linking users to their
-- OAuth2 provider accounts (Google, GitHub, generic OIDC). This allows:
-- - Social login (OAuth-only accounts)
-- - Account linking (link OAuth account to existing email/password account)
-- - Multiple OAuth providers per user (e.g., both Google and GitHub)
--
-- Design decisions:
-- - provider + provider_user_id must be unique (one OAuth account per provider)
-- - Multiple OAuth accounts can link to the same user_id
-- - Foreign key to users table with CASCADE delete (orphan cleanup)
-- - Email stored for reference (may differ from primary user email)

-- Create oauth_accounts table
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('google', 'github', 'oidc')),
    provider_user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Foreign key constraint
    CONSTRAINT fk_oauth_accounts_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    -- Unique constraint on provider + provider_user_id
    -- (prevents duplicate OAuth accounts)
    CONSTRAINT unique_oauth_account
        UNIQUE (provider, provider_user_id)
);

-- Create index on user_id for fast lookups
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id
    ON oauth_accounts(user_id);

-- Create index on provider for filtering
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider
    ON oauth_accounts(provider);

-- Create trigger to automatically update updated_at timestamp
CREATE TRIGGER update_oauth_accounts_updated_at
    BEFORE UPDATE ON oauth_accounts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE oauth_accounts IS 'OAuth2 provider accounts linked to users';
COMMENT ON COLUMN oauth_accounts.id IS 'Primary key, auto-incrementing';
COMMENT ON COLUMN oauth_accounts.user_id IS 'Reference to users.id (local user)';
COMMENT ON COLUMN oauth_accounts.provider IS 'OAuth2 provider (google, github, oidc)';
COMMENT ON COLUMN oauth_accounts.provider_user_id IS 'User ID from OAuth provider';
COMMENT ON COLUMN oauth_accounts.email IS 'Email address from OAuth provider';
COMMENT ON COLUMN oauth_accounts.name IS 'Display name from OAuth provider';
COMMENT ON COLUMN oauth_accounts.avatar_url IS 'Avatar/profile picture URL from OAuth provider';
COMMENT ON COLUMN oauth_accounts.created_at IS 'Timestamp when OAuth account was linked';
COMMENT ON COLUMN oauth_accounts.updated_at IS 'Timestamp when OAuth account was last updated';
