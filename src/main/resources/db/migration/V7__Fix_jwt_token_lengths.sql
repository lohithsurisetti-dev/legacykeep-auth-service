-- =============================================================================
-- LegacyKeep Auth Service - Fix JWT Token Lengths
-- Migration: V7__Fix_jwt_token_lengths.sql
-- Description: Increases token column lengths to accommodate JWT tokens
-- =============================================================================

-- Increase session_token and refresh_token column lengths to accommodate JWT tokens
-- JWT tokens can be 500+ characters long, so we need to increase from VARCHAR(255)
ALTER TABLE user_sessions 
ALTER COLUMN session_token TYPE VARCHAR(1000),
ALTER COLUMN refresh_token TYPE VARCHAR(1000);

-- Also increase token hash length in blacklisted_tokens table
ALTER TABLE blacklisted_tokens 
ALTER COLUMN token_hash TYPE VARCHAR(1000);

-- Add comments for documentation
COMMENT ON COLUMN user_sessions.session_token IS 'JWT access token (can be 500+ characters)';
COMMENT ON COLUMN user_sessions.refresh_token IS 'JWT refresh token (can be 500+ characters)';
COMMENT ON COLUMN blacklisted_tokens.token_hash IS 'Hash of blacklisted JWT token (can be 500+ characters)';
