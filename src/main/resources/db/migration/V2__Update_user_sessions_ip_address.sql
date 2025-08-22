-- =============================================================================
-- LegacyKeep Auth Service - Update user_sessions ip_address column
-- Migration: V2__Update_user_sessions_ip_address.sql
-- Description: Updates ip_address column type from INET to VARCHAR(255)
-- =============================================================================

-- Update ip_address column type from INET to VARCHAR(255)
ALTER TABLE user_sessions 
ALTER COLUMN ip_address TYPE VARCHAR(255);

-- Add comment for documentation
COMMENT ON COLUMN user_sessions.ip_address IS 'IP address of the session (stored as VARCHAR for flexibility)';

