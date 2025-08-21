package com.legacykeep.auth.entity;

/**
 * User role enumeration for authorization and access control.
 * 
 * Defines all possible roles a user can have within the LegacyKeep system.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public enum UserRole {
    
    /**
     * Regular user with basic access.
     */
    USER,
    
    /**
     * Premium user with enhanced features.
     */
    PREMIUM_USER,
    
    /**
     * Family group administrator.
     */
    FAMILY_ADMIN,
    
    /**
     * Content moderator with moderation privileges.
     */
    MODERATOR,
    
    /**
     * System administrator with management privileges.
     */
    ADMIN,
    
    /**
     * Super administrator with full system access.
     */
    SUPER_ADMIN
}
