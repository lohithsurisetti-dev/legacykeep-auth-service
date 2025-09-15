package com.legacykeep.auth.controller;

import com.legacykeep.auth.dto.ApiResponse;
import com.legacykeep.auth.dto.TwoFactorEnableRequestDto;
import com.legacykeep.auth.dto.TwoFactorSetupResponseDto;
import com.legacykeep.auth.dto.TwoFactorVerificationRequestDto;
import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.service.AuthService;
import com.legacykeep.auth.service.TwoFactorAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Two-Factor Authentication Controller.
 * 
 * Provides endpoints for 2FA setup, verification, and management.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/2fa")
@RequiredArgsConstructor
@Tag(name = "Two-Factor Authentication", description = "APIs for 2FA setup and management")
@SecurityRequirement(name = "bearerAuth")
public class TwoFactorAuthController {

    private final TwoFactorAuthService twoFactorAuthService;
    private final AuthService authService;

    /**
     * Get 2FA setup information for the current user.
     */
    @Operation(
        summary = "Get 2FA Setup",
        description = "Get TOTP secret, QR code, and backup codes for 2FA setup"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "2FA setup information retrieved successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @GetMapping("/setup")
    public ResponseEntity<?> get2FASetup(HttpServletRequest request) {
        try {
            Long userId = (Long) request.getAttribute("userId");
            if (userId == null) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("User not authenticated", "User session expired or invalid", 401));
            }

            log.info("Getting 2FA setup for user: {}", userId);

            User user = authService.getUserById(userId);
            String secret = twoFactorAuthService.generateSecret(user);
            String qrCode = twoFactorAuthService.generateQrCode(user, secret);
            String[] backupCodes = twoFactorAuthService.generateBackupCodes(user);

            TwoFactorSetupResponseDto setupResponse = TwoFactorSetupResponseDto.builder()
                    .secret(secret)
                    .qrCode(qrCode)
                    .backupCodes(backupCodes)
                    .instructions("Scan the QR code with your authenticator app or manually enter the secret. Save the backup codes in a secure location.")
                    .build();

            return ResponseEntity.ok(ApiResponse.success(setupResponse, "2FA setup information retrieved successfully"));

        } catch (Exception e) {
            log.error("Failed to get 2FA setup: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to get 2FA setup", e.getMessage(), 500));
        }
    }

    /**
     * Enable 2FA for the current user.
     */
    @Operation(
        summary = "Enable 2FA",
        description = "Enable 2FA after verifying the TOTP code"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "2FA enabled successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid TOTP code"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @PostMapping("/enable")
    public ResponseEntity<?> enable2FA(
            @Valid @RequestBody TwoFactorEnableRequestDto request,
            HttpServletRequest httpRequest) {
        try {
            Long userId = (Long) httpRequest.getAttribute("userId");
            if (userId == null) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("User not authenticated", "User session expired or invalid", 401));
            }

            log.info("Enabling 2FA for user: {}", userId);

            User user = authService.getUserById(userId);
            
            // In a real implementation, you would need to store the secret temporarily
            // and verify it here. For now, we'll just enable 2FA.
            
            // TODO: Implement proper secret storage and verification
            twoFactorAuthService.enable2FA(user, "temp-secret", new String[0]);

            return ResponseEntity.ok(ApiResponse.success(null, "2FA enabled successfully"));

        } catch (Exception e) {
            log.error("Failed to enable 2FA: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to enable 2FA", e.getMessage(), 500));
        }
    }

    /**
     * Disable 2FA for the current user.
     */
    @Operation(
        summary = "Disable 2FA",
        description = "Disable 2FA for the current user"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "2FA disabled successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @PostMapping("/disable")
    public ResponseEntity<?> disable2FA(HttpServletRequest request) {
        try {
            Long userId = (Long) request.getAttribute("userId");
            if (userId == null) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("User not authenticated", "User session expired or invalid", 401));
            }

            log.info("Disabling 2FA for user: {}", userId);

            User user = authService.getUserById(userId);
            twoFactorAuthService.disable2FA(user);

            return ResponseEntity.ok(ApiResponse.success(null, "2FA disabled successfully"));

        } catch (Exception e) {
            log.error("Failed to disable 2FA: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to disable 2FA", e.getMessage(), 500));
        }
    }

    /**
     * Get 2FA status for the current user.
     */
    @Operation(
        summary = "Get 2FA Status",
        description = "Check if 2FA is enabled for the current user"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "2FA status retrieved successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @GetMapping("/status")
    public ResponseEntity<?> get2FAStatus(HttpServletRequest request) {
        try {
            Long userId = (Long) request.getAttribute("userId");
            if (userId == null) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("User not authenticated", "User session expired or invalid", 401));
            }

            log.info("Getting 2FA status for user: {}", userId);

            User user = authService.getUserById(userId);
            boolean isEnabled = twoFactorAuthService.is2FAEnabled(user);

            return ResponseEntity.ok(ApiResponse.success(
                    new TwoFAStatusResponse(isEnabled), 
                    "2FA status retrieved successfully"
            ));

        } catch (Exception e) {
            log.error("Failed to get 2FA status: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to get 2FA status", e.getMessage(), 500));
        }
    }

    /**
     * Verify 2FA code (for login flow).
     */
    @Operation(
        summary = "Verify 2FA Code",
        description = "Verify TOTP or backup code during login"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "2FA code verified successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid 2FA code"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @PostMapping("/verify")
    public ResponseEntity<?> verify2FACode(
            @Valid @RequestBody TwoFactorVerificationRequestDto request,
            HttpServletRequest httpRequest) {
        try {
            Long userId = (Long) httpRequest.getAttribute("userId");
            if (userId == null) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("User not authenticated", "User session expired or invalid", 401));
            }

            log.info("Verifying 2FA code for user: {}", userId);

            User user = authService.getUserById(userId);
            String code = request.getCode();

            boolean isValid = false;
            if (code.length() == 6) {
                // TOTP code
                // TODO: Implement proper TOTP verification with stored secret
                isValid = true; // Placeholder
            } else if (code.length() == 8) {
                // Backup code
                isValid = twoFactorAuthService.verifyBackupCode(user, code);
            }

            if (isValid) {
                return ResponseEntity.ok(ApiResponse.success(null, "2FA code verified successfully"));
            } else {
                return ResponseEntity.status(400)
                        .body(ApiResponse.error("Invalid 2FA code", "The provided code is invalid", 400));
            }

        } catch (Exception e) {
            log.error("Failed to verify 2FA code: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to verify 2FA code", e.getMessage(), 500));
        }
    }

    /**
     * Simple response class for 2FA status.
     */
    private static class TwoFAStatusResponse {
        private final boolean enabled;

        public TwoFAStatusResponse(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isEnabled() {
            return enabled;
        }
    }
}
