-- =============================================================================
-- LegacyKeep Auth Service - Fix audit_logs details column type
-- Migration: V5__Fix_audit_logs_details_column.sql
-- Description: Fixes details column type from JSONB to TEXT to match entity
-- =============================================================================

-- Drop views that depend on the details column
DROP VIEW IF EXISTS security_audit_logs;
DROP VIEW IF EXISTS authentication_audit_logs;
DROP VIEW IF EXISTS failed_audit_logs;

-- Update details column type from JSONB to TEXT
ALTER TABLE audit_logs 
ALTER COLUMN details TYPE TEXT;

-- Recreate views
CREATE VIEW security_audit_logs AS
SELECT * FROM audit_logs 
WHERE event_category = 'SECURITY' 
   OR severity IN ('HIGH', 'CRITICAL')
ORDER BY created_at DESC;

CREATE VIEW authentication_audit_logs AS
SELECT * FROM audit_logs 
WHERE event_category = 'AUTHENTICATION'
ORDER BY created_at DESC;

CREATE VIEW failed_audit_logs AS
SELECT * FROM audit_logs 
WHERE is_successful = false
ORDER BY created_at DESC;

-- Add comment for documentation
COMMENT ON COLUMN audit_logs.details IS 'Encrypted detailed information about the event (TEXT format)';
