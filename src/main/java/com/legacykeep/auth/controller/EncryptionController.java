package com.legacykeep.auth.controller;

import com.legacykeep.auth.dto.ApiResponse;
import com.legacykeep.auth.dto.EncryptionStatistics;
import com.legacykeep.auth.service.DataEncryptionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Encryption Management Controller.
 * 
 * Provides endpoints for managing data encryption and verifying encryption status.
 * These endpoints are restricted to administrators only.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/admin/encryption")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Encryption Management", description = "APIs for managing data encryption")
public class EncryptionController {

    private final DataEncryptionService dataEncryptionService;

    /**
     * Encrypt all existing sensitive data in the database.
     * This endpoint should be called after deploying encryption changes.
     */
    @Operation(
        summary = "Encrypt Existing Data",
        description = "Encrypts all existing sensitive data in the database"
    )
    @PostMapping("/encrypt-existing")
    public ResponseEntity<?> encryptExistingData() {
        try {
            log.info("Admin requested encryption of existing sensitive data");
            
            dataEncryptionService.encryptExistingData();
            
            return ResponseEntity.ok(ApiResponse.success(
                "Existing sensitive data encrypted successfully"
            ));
            
        } catch (Exception e) {
            log.error("Failed to encrypt existing data: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Encryption failed", e.getMessage(), 500));
        }
    }

    /**
     * Verify that all sensitive data is properly encrypted.
     */
    @Operation(
        summary = "Verify Data Encryption",
        description = "Verifies that all sensitive data is properly encrypted"
    )
    @GetMapping("/verify")
    public ResponseEntity<?> verifyDataEncryption() {
        try {
            log.info("Admin requested verification of data encryption");
            
            boolean isEncrypted = dataEncryptionService.verifyDataEncryption();
            
            if (isEncrypted) {
                return ResponseEntity.ok(ApiResponse.success(
                    "All sensitive data is properly encrypted"
                ));
            } else {
                return ResponseEntity.status(500)
                        .body(ApiResponse.error("Data encryption verification failed", 
                            "Some data may not be encrypted", 500));
            }
            
        } catch (Exception e) {
            log.error("Failed to verify data encryption: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Verification failed", e.getMessage(), 500));
        }
    }

    /**
     * Get encryption statistics and status.
     */
    @Operation(
        summary = "Get Encryption Statistics",
        description = "Returns statistics about data encryption status"
    )
    @GetMapping("/statistics")
    public ResponseEntity<?> getEncryptionStatistics() {
        try {
            log.info("Admin requested encryption statistics");
            
            EncryptionStatistics statistics = dataEncryptionService.getEncryptionStatistics();
            
            return ResponseEntity.ok(ApiResponse.success(statistics, "Encryption statistics retrieved"));
            
        } catch (Exception e) {
            log.error("Failed to get encryption statistics: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to get statistics", e.getMessage(), 500));
        }
    }

    /**
     * Encrypt existing user data only.
     */
    @Operation(
        summary = "Encrypt User Data",
        description = "Encrypts existing user data (emails, usernames)"
    )
    @PostMapping("/encrypt-users")
    public ResponseEntity<?> encryptUserData() {
        try {
            log.info("Admin requested encryption of user data");
            
            dataEncryptionService.encryptExistingUserData();
            
            return ResponseEntity.ok(ApiResponse.success(
                "User data encrypted successfully"
            ));
            
        } catch (Exception e) {
            log.error("Failed to encrypt user data: {}", e.getMessage(), e);
            
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("User data encryption failed", e.getMessage(), 500));
        }
    }

    /**
     * Encrypt existing session data only.
     */
    @Operation(
        summary = "Encrypt Session Data",
        description = "Encrypts existing session data (IP addresses, locations)"
    )
    @PostMapping("/encrypt-sessions")
    public ResponseEntity<?> encryptSessionData() {
        try {
            dataEncryptionService.encryptExistingSessionData();
            return ResponseEntity.ok(ApiResponse.success(null, "Session data encryption completed successfully"));
        } catch (Exception e) {
            log.error("Failed to encrypt session data: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Encryption failed", e.getMessage(), 400));
        }
    }

    @PostMapping("/populate-hashes")
    public ResponseEntity<?> populateHashValues() {
        try {
            dataEncryptionService.populateHashValues();
            return ResponseEntity.ok(ApiResponse.success(null, "Hash values populated successfully"));
        } catch (Exception e) {
            log.error("Failed to populate hash values: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Hash population failed", e.getMessage(), 400));
        }
    }
}
