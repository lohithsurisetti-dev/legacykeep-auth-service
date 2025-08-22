package com.legacykeep.auth.entity;

/**
 * AuditSeverity enum for categorizing audit log severity levels.
 * 
 * Used to classify the importance and impact of audit events
 * for filtering, alerting, and compliance purposes.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public enum AuditSeverity {
    /**
     * Low severity - informational events, normal operations
     * Examples: User login, profile view, successful operations
     */
    LOW,
    
    /**
     * Medium severity - notable events, potential concerns
     * Examples: Failed login attempts, unusual activity patterns
     */
    MEDIUM,
    
    /**
     * High severity - security events, violations
     * Examples: Multiple failed logins, suspicious activity, policy violations
     */
    HIGH,
    
    /**
     * Critical severity - immediate security threats
     * Examples: Account compromise, data breach, system intrusion
     */
    CRITICAL
}
