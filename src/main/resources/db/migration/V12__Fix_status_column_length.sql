-- =============================================================================
-- LegacyKeep Auth Service - Fix status column length
-- Migration: V12__Fix_status_column_length.sql
-- Description: Increases status column length to accommodate longer enum values
-- =============================================================================

-- Increase status column length to accommodate longer enum values
ALTER TABLE users 
ALTER COLUMN status TYPE VARCHAR(30);

-- Increase role column length as well for consistency
ALTER TABLE users 
ALTER COLUMN role TYPE VARCHAR(30);

-- Add comment for documentation
COMMENT ON COLUMN users.status IS 'User account status (VARCHAR(30) to accommodate longer enum values)';
COMMENT ON COLUMN users.role IS 'User role (VARCHAR(30) to accommodate longer enum values)';
