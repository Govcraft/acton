-- Add Cedar authorization fields to users table
-- Migration: 003_add_cedar_authorization_to_users
-- Purpose: Add roles, permissions, and email verification for Cedar policy-based authorization

-- Add roles column (TEXT array with default "user" role)
ALTER TABLE users
ADD COLUMN roles TEXT[] NOT NULL DEFAULT '{"user"}';

-- Add permissions column (TEXT array, empty by default)
ALTER TABLE users
ADD COLUMN permissions TEXT[] NOT NULL DEFAULT '{}';

-- Add email_verified column (boolean, false by default)
ALTER TABLE users
ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Create GIN index on roles for efficient role-based queries
CREATE INDEX idx_users_roles ON users USING GIN(roles);

-- Create index on email_verified for efficient filtering
CREATE INDEX idx_users_email_verified ON users(email_verified);

-- ROLLBACK INSTRUCTIONS (if needed):
-- DROP INDEX IF EXISTS idx_users_email_verified;
-- DROP INDEX IF EXISTS idx_users_roles;
-- ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
-- ALTER TABLE users DROP COLUMN IF EXISTS permissions;
-- ALTER TABLE users DROP COLUMN IF EXISTS roles;
