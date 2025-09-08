-- =============================================================================
-- LegacyKeep Auth Service - Fix audit_logs details column type
-- Migration: V5__Fix_audit_logs_details_column.sql
-- Description: Fixes details column type from JSONB to TEXT to match entity
-- =============================================================================

-- Update details column type from JSONB to TEXT
ALTER TABLE audit_logs 
ALTER COLUMN details TYPE TEXT;

-- Add comment for documentation
COMMENT ON COLUMN audit_logs.details IS 'Encrypted detailed information about the event (TEXT format)';
