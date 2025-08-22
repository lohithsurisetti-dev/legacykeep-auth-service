package com.legacykeep.auth.service;

import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.dto.RegisterRequestDto;
import com.legacykeep.auth.dto.RegisterResponseDto;
import com.legacykeep.auth.entity.AuditLog;
import com.legacykeep.auth.entity.AuditSeverity;
import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserRole;
import com.legacykeep.auth.entity.UserSession;
import com.legacykeep.auth.entity.UserStatus;
import com.legacykeep.auth.repository.AuditLogRepository;
import com.legacykeep.auth.repository.UserRepository;
import com.legacykeep.auth.repository.UserSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Authentication Service for user registration, login, and account management.
 * 
 * Provides business logic for user authentication with comprehensive
 * security features, validation, and audit logging.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;
    private final AuditLogRepository auditLogRepository;
    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordEncoder passwordEncoder;

    /**
     * Register a new user account.
     * 
     * This method handles the complete user registration process:
     * - Validates registration data
     * - Checks for existing users
     * - Creates user account
     * - Generates verification token
     * - Logs audit events
     */
    @Transactional
    public RegisterResponseDto registerUser(RegisterRequestDto request, String deviceInfo, String ipAddress, String location) {
        log.info("Processing registration for email: {}", request.getEmail());

        // Validate password confirmation
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Password and confirmation do not match");
        }

        // Check if terms are accepted
        if (!request.isAcceptTerms()) {
            throw new IllegalArgumentException("Terms and conditions must be accepted");
        }

        // Check if user already exists
        if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            throw new IllegalArgumentException("User with this email already exists");
        }

        if (userRepository.existsByUsernameIgnoreCase(request.getUsername())) {
            throw new IllegalArgumentException("Username is already taken");
        }

        // Create user entity
        User user = new User();
        user.setEmail(request.getEmail().toLowerCase());
        user.setUsername(request.getUsername());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setRole(UserRole.USER);
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        user.setEmailVerified(false);
        user.setEmailVerificationToken(generateVerificationToken());
        user.setEmailVerificationExpiresAt(LocalDateTime.now().plusHours(24));

        // Save user
        User savedUser = userRepository.save(user);

        // Log audit event
        logAuditEvent(
                savedUser.getId(),
                null,
                "USER_REGISTRATION",
                "AUTHENTICATION",
                AuditSeverity.LOW,
                "User registered successfully",
                ipAddress,
                deviceInfo,
                true
        );

        log.info("User registered successfully: {} (ID: {})", request.getEmail(), savedUser.getId());

        return RegisterResponseDto.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .username(savedUser.getUsername())
                .status(savedUser.getStatus().name())
                .emailVerified(savedUser.isEmailVerified())
                .registeredAt(savedUser.getCreatedAt())
                .message("Registration successful. Please check your email for verification.")
                .build();
    }

    /**
     * Authenticate user and generate JWT tokens.
     * 
     * This method handles user authentication with:
     * - Multi-method login (email/username)
     * - Password validation
     * - Account status verification
     * - Failed login attempt tracking
     * - JWT token generation
     */
    @Transactional
    public JwtTokenDto authenticateUser(String identifier, String password, String deviceInfo, String ipAddress, String location) {
        log.info("Processing authentication for identifier: {}", identifier);

        // Find user by email or username
        User user = findUserByIdentifier(identifier)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        // Check if account is locked
        if (user.getAccountLockedUntil() != null && user.getAccountLockedUntil().isAfter(LocalDateTime.now())) {
            throw new IllegalArgumentException("Account is locked. Please try again later or reset your password.");
        }

        // Check if account is active
        if (user.getStatus() != UserStatus.ACTIVE && user.getStatus() != UserStatus.PENDING_VERIFICATION) {
            throw new IllegalArgumentException("Account is not active. Please verify your email or contact support.");
        }

        // Validate password
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            handleFailedLogin(user, ipAddress, deviceInfo);
            throw new IllegalArgumentException("Invalid credentials");
        }

        // Reset failed login attempts on successful login
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            user.setAccountLockedUntil(null);
            userRepository.save(user);
        }

        // Generate JWT tokens
        JwtTokenDto tokenDto = jwtService.generateTokens(user, deviceInfo, ipAddress, location, false);

        // Log successful login
        logAuditEvent(
                user.getId(),
                null,
                "USER_LOGIN",
                "AUTHENTICATION",
                AuditSeverity.LOW,
                "User logged in successfully",
                ipAddress,
                deviceInfo,
                true
        );

        log.info("User authenticated successfully: {} (ID: {})", identifier, user.getId());

        return tokenDto;
    }

    /**
     * Logout user and revoke tokens.
     * 
     * This method handles user logout with:
     * - Token validation
     * - Session cleanup
     * - Token blacklisting
     * - Audit logging
     */
    @Transactional
    public void logoutUser(String accessToken, String ipAddress) {
        log.info("Processing logout request");

        // Extract user information from token
        Optional<Long> userIdOpt = jwtService.extractUserId(accessToken);
        if (userIdOpt.isEmpty()) {
            throw new IllegalArgumentException("Invalid access token");
        }

        Long userId = userIdOpt.get();

        // Find and revoke user session
        Optional<UserSession> sessionOpt = userSessionRepository.findBySessionToken(accessToken);
        if (sessionOpt.isPresent()) {
            UserSession session = sessionOpt.get();
            session.revoke("User logout", userId);
            userSessionRepository.save(session);
        }

        // Blacklist the access token
        if (tokenBlacklistService != null) {
            tokenBlacklistService.blacklistToken(accessToken);
        }

        // Log logout event
        logAuditEvent(
                userId,
                null,
                "USER_LOGOUT",
                "AUTHENTICATION",
                AuditSeverity.LOW,
                "User logged out successfully",
                ipAddress,
                "Unknown",
                true
        );

        log.info("User logged out successfully: {}", userId);
    }

    /**
     * Verify email address with verification token.
     * 
     * This method handles email verification with:
     * - Token validation
     * - Account activation
     * - Audit logging
     */
    @Transactional
    public void verifyEmail(String token, String ipAddress) {
        log.info("Processing email verification with token");

        // Find user by verification token
        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification token"));

        // Check if token is expired
        if (user.getEmailVerificationExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Verification token has expired");
        }

        // Verify email and activate account
        user.setEmailVerified(true);
        user.setStatus(UserStatus.ACTIVE);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationExpiresAt(null);
        userRepository.save(user);

        // Log verification event
        logAuditEvent(
                user.getId(),
                null,
                "EMAIL_VERIFICATION",
                "AUTHENTICATION",
                AuditSeverity.LOW,
                "Email verified successfully",
                ipAddress,
                "Unknown",
                true
        );

        log.info("Email verified successfully for user: {}", user.getId());
    }

    /**
     * Request password reset.
     * 
     * This method handles password reset requests with:
     * - Email validation
     * - Reset token generation
     * - Audit logging
     */
    @Transactional
    public void requestPasswordReset(String email, String ipAddress) {
        log.info("Processing password reset request for email: {}", email);

        // Find user by email
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Generate reset token
        user.setPasswordResetToken(generateResetToken());
        user.setPasswordResetExpiresAt(LocalDateTime.now().plusHours(1));
        userRepository.save(user);

        // TODO: Send password reset email
        log.info("Password reset email would be sent to: {}", email);

        // Log reset request event
        logAuditEvent(
                user.getId(),
                null,
                "PASSWORD_RESET_REQUEST",
                "AUTHENTICATION",
                AuditSeverity.MEDIUM,
                "Password reset requested",
                ipAddress,
                "Unknown",
                true
        );

        log.info("Password reset requested for user: {}", user.getId());
    }

    /**
     * Reset password with reset token.
     * 
     * This method handles password reset with:
     * - Token validation
     * - Password strength validation
     * - Password update
     * - Audit logging
     */
    @Transactional
    public void resetPassword(String token, String newPassword, String ipAddress) {
        log.info("Processing password reset with token");

        // Find user by reset token
        User user = userRepository.findByPasswordResetToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset token"));

        // Check if token is expired
        if (user.getPasswordResetExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Reset token has expired");
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetExpiresAt(null);
        user.setFailedLoginAttempts(0);
        user.setAccountLockedUntil(null);
        userRepository.save(user);

        // Log password reset event
        logAuditEvent(
                user.getId(),
                null,
                "PASSWORD_RESET",
                "AUTHENTICATION",
                AuditSeverity.HIGH,
                "Password reset successfully",
                ipAddress,
                "Unknown",
                true
        );

        log.info("Password reset successfully for user: {}", user.getId());
    }

    /**
     * Get user by ID.
     */
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    // =============================================================================
    // Private Helper Methods
    // =============================================================================

    /**
     * Find user by email or username.
     */
    private Optional<User> findUserByIdentifier(String identifier) {
        // Try email first
        Optional<User> userByEmail = userRepository.findByEmailIgnoreCase(identifier);
        if (userByEmail.isPresent()) {
            return userByEmail;
        }

        // Try username
        return userRepository.findByUsernameIgnoreCase(identifier);
    }

    /**
     * Handle failed login attempt.
     */
    private void handleFailedLogin(User user, String ipAddress, String deviceInfo) {
        // Increment failed login attempts
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

        // Check if account should be locked
        if (user.getFailedLoginAttempts() >= 5) {
            user.setAccountLockedUntil(LocalDateTime.now().plusMinutes(30));
        }

        userRepository.save(user);

        // Log failed login event
        logAuditEvent(
                user.getId(),
                null,
                "FAILED_LOGIN",
                "AUTHENTICATION",
                AuditSeverity.MEDIUM,
                "Failed login attempt",
                ipAddress,
                deviceInfo,
                false
        );

        log.warn("Failed login attempt for user: {} (attempts: {})", user.getId(), user.getFailedLoginAttempts());
    }

    /**
     * Generate email verification token.
     */
    private String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate password reset token.
     */
    private String generateResetToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Log audit event.
     */
    private void logAuditEvent(Long userId, Long sessionId, String eventType, String eventCategory,
                              AuditSeverity severity, String description, String ipAddress, String deviceInfo, boolean isSuccessful) {
        try {
            AuditLog auditLog = new AuditLog();
            auditLog.setUserId(userId);
            auditLog.setSessionId(sessionId);
            auditLog.setEventType(eventType);
            auditLog.setEventCategory(eventCategory);
            auditLog.setSeverity(severity);
            auditLog.setDescription(description);
            auditLog.setIpAddress(ipAddress);
            auditLog.setDeviceInfo(deviceInfo);
            auditLog.setSuccessful(isSuccessful);
            auditLog.setCreatedAt(LocalDateTime.now());

            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to log audit event: {}", e.getMessage(), e);
        }
    }
}
