-- =============================================================================
-- LegacyKeep Auth Service - Update audit_logs table structure
-- Migration: V4__Update_audit_logs_structure.sql
-- Description: Updates existing audit_logs table to match comprehensive AuditLog entity
-- =============================================================================

-- Drop existing views if they exist
DROP VIEW IF EXISTS security_audit_logs;
DROP VIEW IF EXISTS authentication_audit_logs;
DROP VIEW IF EXISTS failed_audit_logs;

-- Drop existing trigger and function if they exist
DROP TRIGGER IF EXISTS trigger_set_audit_log_retention ON audit_logs;
DROP FUNCTION IF EXISTS set_audit_log_retention();

-- Add new columns to match our entity
ALTER TABLE audit_logs 
ADD COLUMN IF NOT EXISTS session_id BIGINT,
ADD COLUMN IF NOT EXISTS event_type VARCHAR(100),
ADD COLUMN IF NOT EXISTS event_category VARCHAR(50),
ADD COLUMN IF NOT EXISTS severity VARCHAR(20),
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS request_method VARCHAR(10),
ADD COLUMN IF NOT EXISTS request_url TEXT,
ADD COLUMN IF NOT EXISTS request_headers TEXT,
ADD COLUMN IF NOT EXISTS response_status INTEGER,
ADD COLUMN IF NOT EXISTS response_time_ms BIGINT,
ADD COLUMN IF NOT EXISTS error_message TEXT,
ADD COLUMN IF NOT EXISTS stack_trace TEXT,
ADD COLUMN IF NOT EXISTS affected_user_id BIGINT,
ADD COLUMN IF NOT EXISTS performed_by BIGINT,
ADD COLUMN IF NOT EXISTS old_values TEXT,
ADD COLUMN IF NOT EXISTS new_values TEXT,
ADD COLUMN IF NOT EXISTS location VARCHAR(255),
ADD COLUMN IF NOT EXISTS device_info TEXT,
ADD COLUMN IF NOT EXISTS browser_info VARCHAR(255),
ADD COLUMN IF NOT EXISTS os_info VARCHAR(255),
ADD COLUMN IF NOT EXISTS is_successful BOOLEAN DEFAULT true,
ADD COLUMN IF NOT EXISTS retention_days INTEGER,
ADD COLUMN IF NOT EXISTS version BIGINT DEFAULT 0;

-- Update existing data to set default values
UPDATE audit_logs SET 
    event_type = action,
    event_category = 'SYSTEM',
    severity = 'MEDIUM',
    description = 'Legacy audit log entry',
    is_successful = true,
    version = 0
WHERE event_type IS NULL;

-- Make required columns NOT NULL after setting default values
ALTER TABLE audit_logs 
ALTER COLUMN event_type SET NOT NULL,
ALTER COLUMN event_category SET NOT NULL,
ALTER COLUMN severity SET NOT NULL,
ALTER COLUMN is_successful SET NOT NULL,
ALTER COLUMN version SET NOT NULL;

-- Drop old columns that are no longer needed
ALTER TABLE audit_logs DROP COLUMN IF EXISTS action;

-- Update IP address column type from INET to VARCHAR
ALTER TABLE audit_logs ALTER COLUMN ip_address TYPE VARCHAR(45);

-- Create new indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_category ON audit_logs(event_category);
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity ON audit_logs(severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id ON audit_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_affected_user_id ON audit_logs(affected_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_performed_by ON audit_logs(performed_by);
CREATE INDEX IF NOT EXISTS idx_audit_logs_is_successful ON audit_logs(is_successful);

-- Create composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_event_category ON audit_logs(user_id, event_category);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_severity ON audit_logs(user_id, severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type_category ON audit_logs(event_type, event_category);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_time_range ON audit_logs(ip_address, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity_created ON audit_logs(severity, created_at);

-- Create a function to automatically set retention days for security events
CREATE OR REPLACE FUNCTION set_audit_log_retention()
RETURNS TRIGGER AS $$
BEGIN
    -- Set retention days based on severity
    CASE NEW.severity
        WHEN 'CRITICAL' THEN NEW.retention_days := 2555; -- 7 years
        WHEN 'HIGH' THEN NEW.retention_days := 1095;     -- 3 years
        WHEN 'MEDIUM' THEN NEW.retention_days := 365;    -- 1 year
        WHEN 'LOW' THEN NEW.retention_days := 90;        -- 3 months
        ELSE NEW.retention_days := 365;                  -- Default 1 year
    END CASE;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically set retention days
CREATE TRIGGER trigger_set_audit_log_retention
    BEFORE INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION set_audit_log_retention();

-- Create views for common query patterns
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

-- Add comments for documentation
COMMENT ON TABLE audit_logs IS 'Comprehensive audit logging table for tracking all authentication and security events';
COMMENT ON COLUMN audit_logs.event_type IS 'Type of event (e.g., LOGIN, LOGOUT, PASSWORD_CHANGE, etc.)';
COMMENT ON COLUMN audit_logs.event_category IS 'Category of event (AUTHENTICATION, AUTHORIZATION, SECURITY, USER_MANAGEMENT, etc.)';
COMMENT ON COLUMN audit_logs.severity IS 'Severity level (LOW, MEDIUM, HIGH, CRITICAL)';
COMMENT ON COLUMN audit_logs.description IS 'Human-readable description of the event';
COMMENT ON COLUMN audit_logs.is_successful IS 'Whether the operation was successful';
COMMENT ON COLUMN audit_logs.retention_days IS 'Number of days to retain this log (null = retain indefinitely)';

