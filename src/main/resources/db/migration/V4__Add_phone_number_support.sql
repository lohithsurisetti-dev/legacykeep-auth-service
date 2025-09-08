-- =============================================================================
-- Migration: Add Phone Number Support
-- Version: V4
-- Description: Add phone number fields and indexes to users table
-- =============================================================================

-- Add phone number fields to users table
ALTER TABLE users 
ADD COLUMN phone_number VARCHAR(20),
ADD COLUMN phone_number_hash VARCHAR(64),
ADD COLUMN phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN phone_verification_token VARCHAR(255),
ADD COLUMN phone_verification_expires_at TIMESTAMP;

-- Add unique constraint for phone number hash
ALTER TABLE users 
ADD CONSTRAINT uk_users_phone_number_hash UNIQUE (phone_number_hash);

-- Add indexes for phone number fields
CREATE INDEX idx_users_phone_number ON users (phone_number);
CREATE INDEX idx_users_phone_verification_token ON users (phone_verification_token);

-- Add comments for documentation
COMMENT ON COLUMN users.phone_number IS 'Encrypted phone number for user authentication';
COMMENT ON COLUMN users.phone_number_hash IS 'SHA-256 hash of phone number for efficient searching';
COMMENT ON COLUMN users.phone_verified IS 'Whether the phone number has been verified';
COMMENT ON COLUMN users.phone_verification_token IS 'Token for phone number verification';
COMMENT ON COLUMN users.phone_verification_expires_at IS 'Expiration time for phone verification token';