-- =============================================================================
-- LegacyKeep Auth Service - Make email optional for phone registration
-- Migration: V11__Make_email_optional_for_phone_registration.sql
-- Description: Makes email and email_hash nullable to support phone-only registration
-- =============================================================================

-- Make email column nullable
ALTER TABLE users 
ALTER COLUMN email DROP NOT NULL;

-- Make email_hash column nullable
ALTER TABLE users 
ALTER COLUMN email_hash DROP NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN users.email IS 'User email address (optional when phone number is provided)';
COMMENT ON COLUMN users.email_hash IS 'Hash of email address for searching (optional when phone number is provided)';
