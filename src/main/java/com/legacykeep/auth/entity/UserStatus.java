package com.legacykeep.auth.entity;

/**
 * User status enumeration for authentication and account management.
 * 
 * Defines all possible states a user account can be in within the Auth Service.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public enum UserStatus {
    
    /**
     * User has registered but email verification is pending.
     */
    PENDING_VERIFICATION,
    
    /**
     * User account is active and can perform all operations.
     */
    ACTIVE,
    
    /**
     * User account is temporarily suspended (admin action).
     */
    SUSPENDED,
    
    /**
     * User account is permanently banned (admin action).
     */
    BANNED,
    
    /**
     * User account is locked due to failed login attempts.
     */
    LOCKED,
    
    /**
     * User has deactivated their own account (reversible).
     */
    DEACTIVATED,
    
    /**
     * User account is soft deleted (30-day grace period).
     */
    DELETED,
    
    /**
     * User account is on hold (payment issues, compliance, etc.).
     */
    HOLD,
    
    /**
     * User account requires admin approval.
     */
    PENDING_APPROVAL,
    
    /**
     * User account has limited functionality.
     */
    RESTRICTED
}

