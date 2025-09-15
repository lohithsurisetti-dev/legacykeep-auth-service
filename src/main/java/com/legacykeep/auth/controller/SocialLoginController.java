package com.legacykeep.auth.controller;

import com.legacykeep.auth.dto.ApiResponse;
import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.dto.SocialLoginRequestDto;
import com.legacykeep.auth.service.SocialLoginService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Social Login Controller.
 * 
 * Provides endpoints for social login integration with Google, Apple, and Facebook.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/social")
@RequiredArgsConstructor
@Tag(name = "Social Login", description = "APIs for social login integration")
public class SocialLoginController {

    private final SocialLoginService socialLoginService;

    /**
     * Login with Google.
     */
    @Operation(
        summary = "Google Login",
        description = "Authenticate user with Google OAuth2"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Login successful"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid Google token"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/google")
    public ResponseEntity<?> googleLogin(
            @Valid @RequestBody SocialLoginRequestDto request,
            HttpServletRequest httpRequest) {
        try {
            String deviceInfo = httpRequest.getHeader("User-Agent");
            String ipAddress = getClientIpAddress(httpRequest);

            log.info("Google login attempt from IP: {}", ipAddress);

            JwtTokenDto tokenDto = socialLoginService.processGoogleLogin(
                    request.getToken(),
                    deviceInfo,
                    ipAddress
            );

            log.info("Google login successful");
            return ResponseEntity.ok(ApiResponse.success(tokenDto, "Google login successful"));

        } catch (Exception e) {
            log.error("Google login failed: {}", e.getMessage(), e);
            return ResponseEntity.status(400)
                    .body(ApiResponse.error("Google login failed", e.getMessage(), 400));
        }
    }

    /**
     * Login with Apple.
     */
    @Operation(
        summary = "Apple Login",
        description = "Authenticate user with Apple Sign-In"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Login successful"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid Apple token"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/apple")
    public ResponseEntity<?> appleLogin(
            @Valid @RequestBody SocialLoginRequestDto request,
            HttpServletRequest httpRequest) {
        try {
            String deviceInfo = httpRequest.getHeader("User-Agent");
            String ipAddress = getClientIpAddress(httpRequest);

            log.info("Apple login attempt from IP: {}", ipAddress);

            JwtTokenDto tokenDto = socialLoginService.processAppleLogin(
                    request.getToken(),
                    deviceInfo,
                    ipAddress
            );

            log.info("Apple login successful");
            return ResponseEntity.ok(ApiResponse.success(tokenDto, "Apple login successful"));

        } catch (Exception e) {
            log.error("Apple login failed: {}", e.getMessage(), e);
            return ResponseEntity.status(400)
                    .body(ApiResponse.error("Apple login failed", e.getMessage(), 400));
        }
    }

    /**
     * Login with Facebook.
     */
    @Operation(
        summary = "Facebook Login",
        description = "Authenticate user with Facebook"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Login successful"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid Facebook token"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/facebook")
    public ResponseEntity<?> facebookLogin(
            @Valid @RequestBody SocialLoginRequestDto request,
            HttpServletRequest httpRequest) {
        try {
            String deviceInfo = httpRequest.getHeader("User-Agent");
            String ipAddress = getClientIpAddress(httpRequest);

            log.info("Facebook login attempt from IP: {}", ipAddress);

            JwtTokenDto tokenDto = socialLoginService.processFacebookLogin(
                    request.getToken(),
                    deviceInfo,
                    ipAddress
            );

            log.info("Facebook login successful");
            return ResponseEntity.ok(ApiResponse.success(tokenDto, "Facebook login successful"));

        } catch (Exception e) {
            log.error("Facebook login failed: {}", e.getMessage(), e);
            return ResponseEntity.status(400)
                    .body(ApiResponse.error("Facebook login failed", e.getMessage(), 400));
        }
    }

    /**
     * Get client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}
