package com.legacykeep.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for 2FA setup response.
 * 
 * Contains the TOTP secret, QR code, and backup codes for 2FA setup.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorSetupResponseDto {

    /**
     * The TOTP secret for manual entry.
     */
    private String secret;

    /**
     * QR code as data URL for easy scanning.
     */
    private String qrCode;

    /**
     * Backup codes for account recovery.
     */
    private String[] backupCodes;

    /**
     * Instructions for setting up 2FA.
     */
    private String instructions;
}
