package com.legacykeep.auth.service.impl;

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
import com.legacykeep.auth.service.AuthService;
import com.legacykeep.auth.service.EventPublisherService;
import com.legacykeep.auth.service.JwtService;
import com.legacykeep.auth.service.TokenBlacklistService;
import com.legacykeep.auth.event.dto.UserRegisteredEvent;
import com.legacykeep.auth.event.dto.UserEmailVerifiedEvent;
import com.legacykeep.auth.event.dto.UserPasswordResetRequestedEvent;
import com.legacykeep.auth.event.dto.UserEmailVerificationRequestedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

/**
 * Authentication Service Implementation
 * 
 * Provides the concrete implementation of authentication operations
 * including user registration, login, logout, and account management.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;
    private final AuditLogRepository auditLogRepository;
    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordEncoder passwordEncoder;
    private final EventPublisherService eventPublisherService;

    // =============================================================================
    // User Registration and Authentication
    // =============================================================================

    @Override
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

        // Publish user registration event
        try {
            var userRegisteredEvent = UserRegisteredEvent.builder()
                    .userId(savedUser.getId())
                    .email(savedUser.getEmail())
                    .username(savedUser.getUsername())
                    .firstName(request.getFirstName())
                    .lastName(request.getLastName())
                    .build();
            
            eventPublisherService.publishUserRegisteredEvent(userRegisteredEvent);
            log.info("User registration event published: userId={}, eventId={}", 
                    savedUser.getId(), userRegisteredEvent.getEventId());
        } catch (Exception e) {
            log.error("Failed to publish user registration event: userId={}, error={}", 
                    savedUser.getId(), e.getMessage(), e);
            // Don't fail the registration if event publishing fails
        }

        // Publish email verification requested event
        try {
            var emailVerificationEvent = UserEmailVerificationRequestedEvent.create(
                    savedUser.getId(),
                    savedUser.getEmail(),
                    savedUser.getUsername(),
                    request.getFirstName(),
                    request.getLastName(),
                    savedUser.getEmailVerificationToken(),
                    savedUser.getEmailVerificationExpiresAt()
            );
            
            eventPublisherService.publishUserEmailVerificationRequestedEvent(emailVerificationEvent);
            log.info("Email verification requested event published: userId={}, eventId={}", 
                    savedUser.getId(), emailVerificationEvent.getEventId());
        } catch (Exception e) {
            log.error("Failed to publish email verification requested event: userId={}, error={}", 
                    savedUser.getId(), e.getMessage(), e);
            // Don't fail the registration if event publishing fails
        }

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

    @Override
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

        // Check if account is active and email is verified
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new IllegalArgumentException("Account is not active. Please verify your email or contact support.");
        }
        
        // Check if email is verified
        if (!user.isEmailVerified()) {
            throw new IllegalArgumentException("Email not verified. Please check your email and click the verification link.");
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

    @Override
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

    // =============================================================================
    // Email Verification
    // =============================================================================

    @Override
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

        // Publish email verification event
        try {
            var emailVerifiedEvent = UserEmailVerifiedEvent.create(
                    user.getId().toString(),
                    user.getEmail(),
                    LocalDateTime.now().toInstant(ZoneOffset.UTC),
                    ipAddress,
                    "Unknown" // deviceInfo not available in this context
            );
            
            eventPublisherService.publishUserEmailVerifiedEvent(emailVerifiedEvent);
            log.info("Email verification event published: userId={}, eventId={}", 
                    user.getId(), emailVerifiedEvent.getEventId());
        } catch (Exception e) {
            log.error("Failed to publish email verification event: userId={}, error={}", 
                    user.getId(), e.getMessage(), e);
            // Don't fail the verification if event publishing fails
        }

        log.info("Email verified successfully for user: {}", user.getId());
    }

    // =============================================================================
    // Password Management
    // =============================================================================

    @Override
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

        // Publish password reset requested event
        try {
            var passwordResetEvent = UserPasswordResetRequestedEvent.create(
                    user.getId().toString(),
                    user.getEmail(),
                    user.getPasswordResetToken(),
                    user.getPasswordResetExpiresAt().toInstant(ZoneOffset.UTC),
                    ipAddress,
                    "Unknown" // deviceInfo not available in this context
            );
            
            eventPublisherService.publishUserPasswordResetRequestedEvent(passwordResetEvent);
            log.info("Password reset requested event published: userId={}, eventId={}", 
                    user.getId(), passwordResetEvent.getEventId());
        } catch (Exception e) {
            log.error("Failed to publish password reset requested event: userId={}, error={}", 
                    user.getId(), e.getMessage(), e);
            // Don't fail the password reset request if event publishing fails
        }

        log.info("Password reset requested for user: {}", user.getId());
    }

    @Override
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

    // =============================================================================
    // User Management
    // =============================================================================

    @Override
    @Transactional(readOnly = true)
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserByUsername(String username) {
        return userRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    @Override
    @Transactional
    public User updateUserProfile(Long userId, Object updates) {
        // TODO: Implement user profile update logic
        log.info("Updating user profile for user: {}", userId);
        User user = getUserById(userId);
        // Apply updates to user entity
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public void deleteUserAccount(Long userId, String ipAddress) {
        log.info("Deleting user account: {}", userId);
        
        User user = getUserById(userId);
        user.setStatus(UserStatus.DELETED);
        userRepository.save(user);

        // Log account deletion event
        logAuditEvent(
                userId,
                null,
                "ACCOUNT_DELETION",
                "AUTHENTICATION",
                AuditSeverity.HIGH,
                "User account deleted",
                ipAddress,
                "Unknown",
                true
        );

        log.info("User account deleted: {}", userId);
    }

    // =============================================================================
    // Account Status Management
    // =============================================================================

    @Override
    @Transactional
    public void activateAccount(Long userId, String ipAddress) {
        log.info("Activating account for user: {}", userId);
        
        User user = getUserById(userId);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        logAuditEvent(
                userId,
                null,
                "ACCOUNT_ACTIVATION",
                "AUTHENTICATION",
                AuditSeverity.LOW,
                "Account activated",
                ipAddress,
                "Unknown",
                true
        );
    }

    @Override
    @Transactional
    public void deactivateAccount(Long userId, String ipAddress) {
        log.info("Deactivating account for user: {}", userId);
        
        User user = getUserById(userId);
        user.setStatus(UserStatus.DEACTIVATED);
        userRepository.save(user);

        logAuditEvent(
                userId,
                null,
                "ACCOUNT_DEACTIVATION",
                "AUTHENTICATION",
                AuditSeverity.MEDIUM,
                "Account deactivated",
                ipAddress,
                "Unknown",
                true
        );
    }

    @Override
    @Transactional
    public void lockAccount(Long userId, String reason, String ipAddress) {
        log.info("Locking account for user: {} - reason: {}", userId, reason);
        
        User user = getUserById(userId);
        user.setAccountLockedUntil(LocalDateTime.now().plusHours(24));
        userRepository.save(user);

        logAuditEvent(
                userId,
                null,
                "ACCOUNT_LOCKED",
                "AUTHENTICATION",
                AuditSeverity.HIGH,
                "Account locked: " + reason,
                ipAddress,
                "Unknown",
                true
        );
    }

    @Override
    @Transactional
    public void unlockAccount(Long userId, String ipAddress) {
        log.info("Unlocking account for user: {}", userId);
        
        User user = getUserById(userId);
        user.setAccountLockedUntil(null);
        user.setFailedLoginAttempts(0);
        userRepository.save(user);

        logAuditEvent(
                userId,
                null,
                "ACCOUNT_UNLOCKED",
                "AUTHENTICATION",
                AuditSeverity.MEDIUM,
                "Account unlocked",
                ipAddress,
                "Unknown",
                true
        );
    }

    // =============================================================================
    // Security and Audit
    // =============================================================================

    @Override
    public void logSecurityEvent(Long userId, String eventType, String severity, String message, String ipAddress, String userAgent) {
        try {
            AuditLog auditLog = new AuditLog();
            auditLog.setUserId(userId);
            auditLog.setEventType(eventType);
            auditLog.setSeverity(AuditSeverity.valueOf(severity.toUpperCase()));
            auditLog.setDescription(message);
            auditLog.setIpAddress(ipAddress);
            auditLog.setDeviceInfo(userAgent);
            auditLog.setSuccessful(true);
            auditLog.setCreatedAt(LocalDateTime.now());

            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to log security event: {}", e.getMessage(), e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isAccountLocked(Long userId) {
        User user = getUserById(userId);
        return user.getAccountLockedUntil() != null && user.getAccountLockedUntil().isAfter(LocalDateTime.now());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isAccountActive(Long userId) {
        User user = getUserById(userId);
        return user.getStatus() == UserStatus.ACTIVE;
    }

    @Override
    @Transactional(readOnly = true)
    public int getLoginAttemptsCount(Long userId) {
        User user = getUserById(userId);
        return user.getFailedLoginAttempts();
    }

    @Override
    @Transactional
    public void resetLoginAttempts(Long userId) {
        User user = getUserById(userId);
        user.setFailedLoginAttempts(0);
        user.setAccountLockedUntil(null);
        userRepository.save(user);
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









