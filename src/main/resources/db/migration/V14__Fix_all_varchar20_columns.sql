-- =============================================================================
-- LegacyKeep Auth Service - Fix all VARCHAR(20) columns
-- Migration: V14__Fix_all_varchar20_columns.sql
-- Description: Increases all VARCHAR(20) columns that might cause issues
-- =============================================================================

-- Increase phone_number column length to accommodate longer phone numbers
ALTER TABLE users 
ALTER COLUMN phone_number TYPE VARCHAR(30);

-- Increase security_level column length in user_sessions
ALTER TABLE user_sessions 
ALTER COLUMN security_level TYPE VARCHAR(30);

-- Increase token_type column length in blacklisted_tokens
ALTER TABLE blacklisted_tokens 
ALTER COLUMN token_type TYPE VARCHAR(30);

-- Add comments for documentation
COMMENT ON COLUMN users.phone_number IS 'Phone number (VARCHAR(30) to accommodate international formats)';
COMMENT ON COLUMN user_sessions.security_level IS 'Security level (VARCHAR(30) to accommodate longer enum values)';
COMMENT ON COLUMN blacklisted_tokens.token_type IS 'Token type (VARCHAR(30) to accommodate longer token types)';
