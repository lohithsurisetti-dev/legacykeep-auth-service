package com.legacykeep.auth.controller;

import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.dto.LoginRequestDto;
import com.legacykeep.auth.dto.RegisterRequestDto;
import com.legacykeep.auth.dto.RegisterResponseDto;
import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserRole;
import com.legacykeep.auth.entity.UserStatus;
import com.legacykeep.auth.service.AuthService;
import com.legacykeep.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Optional;

/**
 * Authentication Controller for user registration, login, and logout.
 * 
 * Provides secure endpoints for user authentication with comprehensive
 * security features, audit logging, and JWT token management.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    /**
     * Register a new user account.
     * 
     * This endpoint handles user registration with:
     * - Email/username validation
     * - Password strength validation
     * - Email verification setup
     * - Account activation workflow
     * - Security audit logging
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestBody RegisterRequestDto request,
            HttpServletRequest httpRequest) {

        try {
            // Get client information for security tracking
            String deviceInfo = httpRequest.getHeader("User-Agent");
            String ipAddress = getClientIpAddress(httpRequest);
            String location = "Unknown"; // TODO: Implement geolocation service

            log.info("Registration attempt for email: {} from IP: {}", request.getEmail(), ipAddress);

            // Register the user
            RegisterResponseDto response = authService.registerUser(request, deviceInfo, ipAddress, location);

            log.info("User registered successfully: {} (ID: {})", request.getEmail(), response.getUserId());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Registration failed for email: {} - {}", request.getEmail(), e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Registration failed", "REGISTRATION_ERROR", e.getMessage()));
        }
    }

    /**
     * Authenticate user and generate JWT tokens.
     * 
     * This endpoint handles user login with:
     * - Multi-method authentication (email/username)
     * - Password validation
     * - Account status verification
     * - JWT token generation
     * - Session management
     * - Security audit logging
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequestDto request,
            HttpServletRequest httpRequest) {

        try {
            // Get client information for security tracking
            String deviceInfo = httpRequest.getHeader("User-Agent");
            String ipAddress = getClientIpAddress(httpRequest);
            String location = "Unknown"; // TODO: Implement geolocation service

            log.info("Login attempt for identifier: {} from IP: {}", request.getIdentifier(), ipAddress);

            // Authenticate user and generate tokens
            JwtTokenDto tokenDto = authService.authenticateUser(
                    request.getIdentifier(),
                    request.getPassword(),
                    deviceInfo,
                    ipAddress,
                    location
            );

            log.info("User logged in successfully: {} (ID: {})", request.getIdentifier(), tokenDto.getUserId());

            return ResponseEntity.ok(tokenDto);

        } catch (Exception e) {
            log.error("Login failed for identifier: {} - {}", request.getIdentifier(), e.getMessage(), e);
            
            return ResponseEntity.status(401)
                    .body(new ErrorResponse("Authentication failed", "AUTHENTICATION_ERROR", e.getMessage()));
        }
    }

    /**
     * Logout user and revoke tokens.
     * 
     * This endpoint handles user logout with:
     * - Token revocation
     * - Session cleanup
     * - Security audit logging
     * - Blacklist management
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader("Authorization") String authorizationHeader,
            HttpServletRequest httpRequest) {

        try {
            // Extract access token
            String accessToken = extractAccessToken(authorizationHeader);
            if (accessToken == null) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Invalid authorization header", "INVALID_TOKEN"));
            }

            String ipAddress = getClientIpAddress(httpRequest);
            log.info("Logout request from IP: {}", ipAddress);

            // Logout user and revoke tokens
            authService.logoutUser(accessToken, ipAddress);

            return ResponseEntity.ok()
                    .body(new SuccessResponse("Logged out successfully"));

        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(new ErrorResponse("Logout failed", "LOGOUT_ERROR", e.getMessage()));
        }
    }

    /**
     * Verify email address with verification token.
     * 
     * This endpoint handles email verification with:
     * - Token validation
     * - Account activation
     * - Security audit logging
     */
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(
            @RequestParam String token,
            HttpServletRequest httpRequest) {

        try {
            String ipAddress = getClientIpAddress(httpRequest);
            log.info("Email verification attempt with token from IP: {}", ipAddress);

            // Verify email
            authService.verifyEmail(token, ipAddress);

            return ResponseEntity.ok()
                    .body(new SuccessResponse("Email verified successfully"));

        } catch (Exception e) {
            log.error("Email verification failed: {}", e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Email verification failed", "VERIFICATION_ERROR", e.getMessage()));
        }
    }

    /**
     * Request password reset.
     * 
     * This endpoint handles password reset requests with:
     * - Email validation
     * - Reset token generation
     * - Email notification
     * - Security audit logging
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(
            @RequestParam String email,
            HttpServletRequest httpRequest) {

        try {
            String ipAddress = getClientIpAddress(httpRequest);
            log.info("Password reset request for email: {} from IP: {}", email, ipAddress);

            // Request password reset
            authService.requestPasswordReset(email, ipAddress);

            return ResponseEntity.ok()
                    .body(new SuccessResponse("Password reset email sent"));

        } catch (Exception e) {
            log.error("Password reset request failed for email: {} - {}", email, e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Password reset request failed", "RESET_ERROR", e.getMessage()));
        }
    }

    /**
     * Reset password with reset token.
     * 
     * This endpoint handles password reset with:
     * - Token validation
     * - Password strength validation
     * - Password update
     * - Security audit logging
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(
            @RequestParam String token,
            @RequestParam String newPassword,
            HttpServletRequest httpRequest) {

        try {
            String ipAddress = getClientIpAddress(httpRequest);
            log.info("Password reset attempt with token from IP: {}", ipAddress);

            // Reset password
            authService.resetPassword(token, newPassword, ipAddress);

            return ResponseEntity.ok()
                    .body(new SuccessResponse("Password reset successfully"));

        } catch (Exception e) {
            log.error("Password reset failed: {}", e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Password reset failed", "RESET_ERROR", e.getMessage()));
        }
    }

    /**
     * Get current user information.
     * 
     * This endpoint returns current user information from JWT token.
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest httpRequest) {
        try {
            Long userId = (Long) httpRequest.getAttribute("userId");
            String email = (String) httpRequest.getAttribute("userEmail");
            String role = (String) httpRequest.getAttribute("userRole");

            if (userId == null) {
                return ResponseEntity.status(401)
                        .body(new ErrorResponse("User not authenticated", "UNAUTHORIZED"));
            }

            User user = authService.getUserById(userId);
            
            return ResponseEntity.ok(new UserInfoResponse(
                    user.getId(),
                    user.getEmail(),
                    user.getUsername(),
                    user.getRole().name(),
                    user.getStatus().name(),
                    user.isEmailVerified()
            ));

        } catch (Exception e) {
            log.error("Failed to get current user: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(new ErrorResponse("Failed to get user info", "USER_INFO_ERROR", e.getMessage()));
        }
    }

    /**
     * Extract access token from Authorization header.
     */
    private String extractAccessToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

    /**
     * Get client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader != null && !xForwardedForHeader.isEmpty()) {
            return xForwardedForHeader.split(",")[0].trim();
        }
        
        String xRealIpHeader = request.getHeader("X-Real-IP");
        if (xRealIpHeader != null && !xRealIpHeader.isEmpty()) {
            return xRealIpHeader;
        }
        
        return request.getRemoteAddr();
    }

    // =============================================================================
    // Response DTOs
    // =============================================================================

    /**
     * Error response DTO.
     */
    public record ErrorResponse(String message, String code, String details) {
        public ErrorResponse(String message, String code) {
            this(message, code, null);
        }
    }

    /**
     * Success response DTO.
     */
    public record SuccessResponse(String message) {}

    /**
     * User information response DTO.
     */
    public record UserInfoResponse(
            Long id,
            String email,
            String username,
            String role,
            String status,
            boolean emailVerified
    ) {}
}
