-- =============================================================================
-- LegacyKeep Auth Service - Add Hash Columns for Efficient Search
-- Migration: V9__Add_hash_columns_for_search.sql
-- Description: Adds hash columns for email and username to enable efficient
--              searching while maintaining data encryption
-- =============================================================================

-- Add hash columns for efficient searching of encrypted fields
ALTER TABLE users
ADD COLUMN email_hash VARCHAR(64) NOT NULL DEFAULT '',
ADD COLUMN username_hash VARCHAR(64) NOT NULL DEFAULT '';

-- Create unique indexes on hash columns for fast lookups
CREATE UNIQUE INDEX idx_users_email_hash ON users(email_hash);
CREATE UNIQUE INDEX idx_users_username_hash ON users(username_hash);

-- Add comments for documentation
COMMENT ON COLUMN users.email_hash IS 'SHA-256 hash of email for efficient searching';
COMMENT ON COLUMN users.username_hash IS 'SHA-256 hash of username for efficient searching';

-- Note: The hash values will be populated by the application when users are created
-- or when existing data is processed through the HashService
