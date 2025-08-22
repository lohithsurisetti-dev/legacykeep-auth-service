package com.legacykeep.auth.service;

import com.legacykeep.auth.dto.RegisterRequestDto;
import com.legacykeep.auth.dto.RegisterResponseDto;
import com.legacykeep.auth.entity.User;

/**
 * Authentication Service Interface
 * 
 * Defines the contract for authentication operations including
 * user registration, login, logout, and account management.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public interface AuthService {

    // =============================================================================
    // User Registration and Authentication
    // =============================================================================

    /**
     * Register a new user account.
     * 
     * @param request Registration request data
     * @param deviceInfo Client device information
     * @param ipAddress Client IP address
     * @param location Client location
     * @return Registration response with user details
     */
    RegisterResponseDto registerUser(RegisterRequestDto request, String deviceInfo, String ipAddress, String location);

    /**
     * Authenticate user and generate JWT tokens.
     * 
     * @param identifier User email or username
     * @param password User password
     * @param deviceInfo Client device information
     * @param ipAddress Client IP address
     * @param location Client location
     * @return JWT token response
     */
    com.legacykeep.auth.dto.JwtTokenDto authenticateUser(String identifier, String password, String deviceInfo, String ipAddress, String location);

    /**
     * Logout user and revoke tokens.
     * 
     * @param accessToken User's access token
     * @param ipAddress Client IP address
     */
    void logoutUser(String accessToken, String ipAddress);

    // =============================================================================
    // Email Verification
    // =============================================================================

    /**
     * Verify email address with verification token.
     * 
     * @param token Email verification token
     * @param ipAddress Client IP address
     */
    void verifyEmail(String token, String ipAddress);

    // =============================================================================
    // Password Management
    // =============================================================================

    /**
     * Request password reset.
     * 
     * @param email User email address
     * @param ipAddress Client IP address
     */
    void requestPasswordReset(String email, String ipAddress);

    /**
     * Reset password with reset token.
     * 
     * @param token Password reset token
     * @param newPassword New password
     * @param ipAddress Client IP address
     */
    void resetPassword(String token, String newPassword, String ipAddress);

    // =============================================================================
    // User Management
    // =============================================================================

    /**
     * Get user by ID.
     * 
     * @param userId User ID
     * @return User entity
     */
    User getUserById(Long userId);

    /**
     * Get user by email.
     * 
     * @param email User email
     * @return User entity
     */
    User getUserByEmail(String email);

    /**
     * Get user by username.
     * 
     * @param username User username
     * @return User entity
     */
    User getUserByUsername(String username);

    /**
     * Update user profile.
     * 
     * @param userId User ID
     * @param updates User update data
     * @return Updated user entity
     */
    User updateUserProfile(Long userId, Object updates);

    /**
     * Delete user account.
     * 
     * @param userId User ID
     * @param ipAddress Client IP address
     */
    void deleteUserAccount(Long userId, String ipAddress);

    // =============================================================================
    // Account Status Management
    // =============================================================================

    /**
     * Activate user account.
     * 
     * @param userId User ID
     * @param ipAddress Client IP address
     */
    void activateAccount(Long userId, String ipAddress);

    /**
     * Deactivate user account.
     * 
     * @param userId User ID
     * @param ipAddress Client IP address
     */
    void deactivateAccount(Long userId, String ipAddress);

    /**
     * Lock user account.
     * 
     * @param userId User ID
     * @param reason Lock reason
     * @param ipAddress Client IP address
     */
    void lockAccount(Long userId, String reason, String ipAddress);

    /**
     * Unlock user account.
     * 
     * @param userId User ID
     * @param ipAddress Client IP address
     */
    void unlockAccount(Long userId, String ipAddress);

    // =============================================================================
    // Security and Audit
    // =============================================================================

    /**
     * Log security audit event.
     * 
     * @param userId User ID (can be null for system events)
     * @param eventType Type of security event
     * @param severity Event severity
     * @param message Event message
     * @param ipAddress Client IP address
     * @param userAgent Client user agent
     */
    void logSecurityEvent(Long userId, String eventType, String severity, String message, String ipAddress, String userAgent);

    /**
     * Check if user account is locked.
     * 
     * @param userId User ID
     * @return True if account is locked
     */
    boolean isAccountLocked(Long userId);

    /**
     * Check if user account is active.
     * 
     * @param userId User ID
     * @return True if account is active
     */
    boolean isAccountActive(Long userId);

    /**
     * Get user login attempts count.
     * 
     * @param userId User ID
     * @return Number of failed login attempts
     */
    int getLoginAttemptsCount(Long userId);

    /**
     * Reset user login attempts.
     * 
     * @param userId User ID
     */
    void resetLoginAttempts(Long userId);
}
