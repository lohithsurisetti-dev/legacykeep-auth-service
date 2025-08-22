-- =============================================================================
-- LegacyKeep Auth Service - Add missing user_sessions columns
-- Migration: V3__Add_missing_user_sessions_columns.sql
-- Description: Adds missing columns to user_sessions table to match UserSession entity
-- =============================================================================

-- Add missing columns to user_sessions table
ALTER TABLE user_sessions 
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '1 hour'),
ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITHOUT TIME ZONE,
ADD COLUMN IF NOT EXISTS revoked_reason VARCHAR(255),
ADD COLUMN IF NOT EXISTS revoked_by BIGINT,
ADD COLUMN IF NOT EXISTS login_location VARCHAR(255),
ADD COLUMN IF NOT EXISTS login_method VARCHAR(50),
ADD COLUMN IF NOT EXISTS session_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS security_level VARCHAR(20),
ADD COLUMN IF NOT EXISTS two_factor_verified BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN IF NOT EXISTS remember_me BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;

-- Add comments for documentation
COMMENT ON COLUMN user_sessions.expires_at IS 'Session expiration timestamp';
COMMENT ON COLUMN user_sessions.last_used_at IS 'Last time the session was used';
COMMENT ON COLUMN user_sessions.is_active IS 'Whether the session is currently active';
COMMENT ON COLUMN user_sessions.revoked_at IS 'When the session was revoked';
COMMENT ON COLUMN user_sessions.revoked_reason IS 'Reason for session revocation';
COMMENT ON COLUMN user_sessions.revoked_by IS 'User ID who revoked the session';
COMMENT ON COLUMN user_sessions.login_location IS 'Geographic location of login';
COMMENT ON COLUMN user_sessions.login_method IS 'Authentication method used (PASSWORD, GOOGLE, etc.)';
COMMENT ON COLUMN user_sessions.session_type IS 'Type of session (WEB, MOBILE, DESKTOP, API)';
COMMENT ON COLUMN user_sessions.security_level IS 'Security level (LOW, MEDIUM, HIGH, CRITICAL)';
COMMENT ON COLUMN user_sessions.two_factor_verified IS 'Whether 2FA was verified for this session';
COMMENT ON COLUMN user_sessions.remember_me IS 'Whether this is a remember-me session';
COMMENT ON COLUMN user_sessions.version IS 'Optimistic locking version';

