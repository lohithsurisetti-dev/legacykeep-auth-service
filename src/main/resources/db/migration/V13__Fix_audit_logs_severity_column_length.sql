-- =============================================================================
-- LegacyKeep Auth Service - Fix audit_logs severity column length
-- Migration: V13__Fix_audit_logs_severity_column_length.sql
-- Description: Increases severity column length to accommodate longer enum values
-- =============================================================================

-- Drop views that depend on the severity column
DROP VIEW IF EXISTS security_audit_logs;
DROP VIEW IF EXISTS authentication_audit_logs;
DROP VIEW IF EXISTS failed_audit_logs;

-- Increase severity column length to accommodate longer enum values
ALTER TABLE audit_logs 
ALTER COLUMN severity TYPE VARCHAR(30);

-- Recreate the views (from V10 migration)
CREATE VIEW security_audit_logs AS
SELECT 
    id,
    user_id,
    session_id,
    event_type,
    event_category,
    severity,
    description,
    details,
    ip_address,
    user_agent,
    created_at
FROM audit_logs 
WHERE event_category IN ('SECURITY', 'AUTHENTICATION', 'AUTHORIZATION')
ORDER BY created_at DESC;

CREATE VIEW authentication_audit_logs AS
SELECT 
    id,
    user_id,
    session_id,
    event_type,
    event_category,
    severity,
    description,
    details,
    ip_address,
    user_agent,
    created_at
FROM audit_logs 
WHERE event_category = 'AUTHENTICATION'
ORDER BY created_at DESC;

CREATE VIEW failed_audit_logs AS
SELECT 
    id,
    user_id,
    session_id,
    event_type,
    event_category,
    severity,
    description,
    details,
    ip_address,
    user_agent,
    created_at
FROM audit_logs 
WHERE severity IN ('HIGH', 'CRITICAL')
ORDER BY created_at DESC;

-- Add comment for documentation
COMMENT ON COLUMN audit_logs.severity IS 'Audit log severity level (VARCHAR(30) to accommodate longer enum values)';
