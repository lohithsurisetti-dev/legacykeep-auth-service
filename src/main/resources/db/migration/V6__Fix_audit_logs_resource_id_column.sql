-- =============================================================================
-- LegacyKeep Auth Service - Fix audit_logs resource_id column type
-- Migration: V6__Fix_audit_logs_resource_id_column.sql
-- Description: Fixes resource_id column type from BIGINT to VARCHAR to match entity
-- =============================================================================

-- Drop views that depend on the resource_id column
DROP VIEW IF EXISTS security_audit_logs;
DROP VIEW IF EXISTS authentication_audit_logs;
DROP VIEW IF EXISTS failed_audit_logs;

-- Update resource_id column type from BIGINT to VARCHAR(255)
ALTER TABLE audit_logs 
ALTER COLUMN resource_id TYPE VARCHAR(255);

-- Add comment for documentation
COMMENT ON COLUMN audit_logs.resource_id IS 'ID of the specific resource (VARCHAR for flexibility)';

