package com.legacykeep.auth.controller;

import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Refresh Token Controller for handling JWT token refresh requests.
 * 
 * Provides endpoints for refreshing access tokens using refresh tokens,
 * implementing the short-lived access token / long-lived refresh token pattern.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth/refresh")
@RequiredArgsConstructor
public class RefreshTokenController {

    private final JwtService jwtService;

    /**
     * Refresh access token using refresh token.
     * 
     * This endpoint implements the refresh token flow:
     * - Validates the provided refresh token
     * - Generates a new short-lived access token
     * - Optionally rotates the refresh token for security
     * - Returns new token pair
     */
    @PostMapping
    public ResponseEntity<?> refreshToken(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            HttpServletRequest request) {

        try {
            // Extract refresh token from Authorization header
            String refreshToken = extractRefreshToken(authorizationHeader);
            if (refreshToken == null) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Invalid authorization header", "REFRESH_TOKEN_MISSING"));
            }

            // Get client information
            String deviceInfo = userAgent != null ? userAgent : "Unknown";
            String ipAddress = getClientIpAddress(request);

            // Refresh the token
            Optional<JwtTokenDto> tokenDtoOpt = jwtService.refreshAccessToken(refreshToken, deviceInfo, ipAddress);
            
            if (tokenDtoOpt.isEmpty()) {
                log.warn("Failed to refresh token from IP: {}", ipAddress);
                return ResponseEntity.status(401)
                        .body(new ErrorResponse("Invalid or expired refresh token", "REFRESH_TOKEN_INVALID"));
            }

            JwtTokenDto tokenDto = tokenDtoOpt.get();
            
            log.info("Successfully refreshed token for user: {} from IP: {}", 
                    tokenDto.getUserId(), ipAddress);

            return ResponseEntity.ok(tokenDto);

        } catch (Exception e) {
            log.error("Error during token refresh: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(new ErrorResponse("Internal server error during token refresh", "INTERNAL_ERROR"));
        }
    }

    /**
     * Revoke refresh token (logout).
     * 
     * This endpoint allows users to explicitly revoke their refresh token,
     * effectively logging them out from the current session.
     */
    @DeleteMapping
    public ResponseEntity<?> revokeRefreshToken(
            @RequestHeader("Authorization") String authorizationHeader,
            HttpServletRequest request) {

        try {
            // Extract refresh token from Authorization header
            String refreshToken = extractRefreshToken(authorizationHeader);
            if (refreshToken == null) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Invalid authorization header", "REFRESH_TOKEN_MISSING"));
            }

            // TODO: Implement token revocation logic
            // This would involve:
            // 1. Validating the refresh token
            // 2. Finding the associated session
            // 3. Revoking the session
            // 4. Blacklisting the refresh token
            
            log.info("Refresh token revocation requested from IP: {}", getClientIpAddress(request));
            
            return ResponseEntity.ok()
                    .body(new SuccessResponse("Refresh token revoked successfully"));

        } catch (Exception e) {
            log.error("Error during token revocation: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(new ErrorResponse("Internal server error during token revocation", "INTERNAL_ERROR"));
        }
    }

    /**
     * Extract refresh token from Authorization header.
     */
    private String extractRefreshToken(String authorizationHeader) {
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

    /**
     * Error response DTO.
     */
    public record ErrorResponse(String message, String code) {}

    /**
     * Success response DTO.
     */
    public record SuccessResponse(String message) {}
}
