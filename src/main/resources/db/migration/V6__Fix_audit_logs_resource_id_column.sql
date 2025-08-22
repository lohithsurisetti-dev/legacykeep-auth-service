-- =============================================================================
-- LegacyKeep Auth Service - Fix audit_logs resource_id column type
-- Migration: V6__Fix_audit_logs_resource_id_column.sql
-- Description: Fixes resource_id column type from BIGINT to VARCHAR to match entity
-- =============================================================================

-- Drop views that depend on the audit_logs table
DROP VIEW IF EXISTS security_audit_logs;
DROP VIEW IF EXISTS authentication_audit_logs;
DROP VIEW IF EXISTS failed_audit_logs;

-- Update resource_id column type from BIGINT to VARCHAR(255)
ALTER TABLE audit_logs 
ALTER COLUMN resource_id TYPE VARCHAR(255);

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
COMMENT ON COLUMN audit_logs.resource_id IS 'ID of the specific resource (VARCHAR for flexibility)';

