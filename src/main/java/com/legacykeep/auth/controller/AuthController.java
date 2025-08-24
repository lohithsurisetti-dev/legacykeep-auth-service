package com.legacykeep.auth.controller;

import com.legacykeep.auth.dto.ApiResponse;
import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.dto.LoginRequestDto;
import com.legacykeep.auth.dto.RegisterRequestDto;
import com.legacykeep.auth.dto.RegisterResponseDto;
import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserRole;
import com.legacykeep.auth.entity.UserStatus;
import com.legacykeep.auth.service.AuthService;
import com.legacykeep.auth.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "APIs for user authentication, registration, and authorization")
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
    @Operation(
        summary = "Register New User",
        description = "Registers a new user account with email verification and security features"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "User registered successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid request data or registration failed"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "409", description = "User already exists")
    })
    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Parameter(description = "User registration details", required = true)
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

            return ResponseEntity.ok(ApiResponse.success(response, "User registered successfully"));

        } catch (Exception e) {
            log.error("Registration failed for email: {} - {}", request.getEmail(), e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Registration failed", e.getMessage(), 400));
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
    @Operation(
        summary = "User Login",
        description = "Authenticates user and generates JWT access and refresh tokens"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Login successful"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid credentials"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Authentication failed"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "Account disabled or locked")
    })
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Parameter(description = "Login credentials", required = true)
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

            return ResponseEntity.ok(ApiResponse.success(tokenDto, "User logged in successfully"));

        } catch (Exception e) {
            log.error("Login failed for identifier: {} - {}", request.getIdentifier(), e.getMessage(), e);
            
            return ResponseEntity.status(401)
                    .body(ApiResponse.error("Authentication failed", e.getMessage(), 401));
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
                    .body(ApiResponse.error("Invalid authorization header", "Missing or invalid token", 400));
            }

            String ipAddress = getClientIpAddress(httpRequest);
            log.info("Logout request from IP: {}", ipAddress);

            // Logout user and revoke tokens
            authService.logoutUser(accessToken, ipAddress);

            return ResponseEntity.ok()
                    .body(ApiResponse.success("Logged out successfully"));

        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Logout failed", e.getMessage(), 500));
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
                    .body(ApiResponse.success("Email verified successfully"));

        } catch (Exception e) {
            log.error("Email verification failed: {}", e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Email verification failed", e.getMessage(), 400));
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
                    .body(ApiResponse.success("Password reset email sent"));

        } catch (Exception e) {
            log.error("Password reset request failed for email: {} - {}", email, e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Password reset request failed", e.getMessage(), 400));
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
                    .body(ApiResponse.success("Password reset successfully"));

        } catch (Exception e) {
            log.error("Password reset failed: {}", e.getMessage(), e);
            
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Password reset failed", e.getMessage(), 400));
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
                    .body(ApiResponse.error("User not authenticated", "User session expired or invalid", 401));
            }

            User user = authService.getUserById(userId);
            
            return ResponseEntity.ok(ApiResponse.success(new UserInfoResponse(
                    user.getId(),
                    user.getEmail(),
                    user.getUsername(),
                    user.getRole().name(),
                    user.getStatus().name(),
                    user.isEmailVerified()
            ), "User information retrieved successfully"));

        } catch (Exception e) {
            log.error("Failed to get current user: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to get user info", e.getMessage(), 500));
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
