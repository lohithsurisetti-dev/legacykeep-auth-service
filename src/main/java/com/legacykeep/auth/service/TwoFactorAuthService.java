package com.legacykeep.auth.service;

import com.legacykeep.auth.entity.User;

/**
 * Two-Factor Authentication Service Interface.
 * 
 * Provides methods for TOTP-based 2FA including:
 * - Secret generation
 * - QR code generation
 * - TOTP verification
 * - Backup codes management
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public interface TwoFactorAuthService {

    /**
     * Generate a new TOTP secret for a user.
     * 
     * @param user the user to generate secret for
     * @return the generated secret
     */
    String generateSecret(User user);

    /**
     * Generate QR code data URL for TOTP setup.
     * 
     * @param user the user
     * @param secret the TOTP secret
     * @return QR code as data URL
     */
    String generateQrCode(User user, String secret);

    /**
     * Verify a TOTP code.
     * 
     * @param secret the TOTP secret
     * @param code the code to verify
     * @return true if valid, false otherwise
     */
    boolean verifyTotpCode(String secret, String code);

    /**
     * Generate backup codes for a user.
     * 
     * @param user the user
     * @return array of backup codes
     */
    String[] generateBackupCodes(User user);

    /**
     * Verify a backup code.
     * 
     * @param user the user
     * @param code the backup code to verify
     * @return true if valid, false otherwise
     */
    boolean verifyBackupCode(User user, String code);

    /**
     * Enable 2FA for a user.
     * 
     * @param user the user
     * @param secret the TOTP secret
     * @param backupCodes the backup codes
     */
    void enable2FA(User user, String secret, String[] backupCodes);

    /**
     * Disable 2FA for a user.
     * 
     * @param user the user
     */
    void disable2FA(User user);

    /**
     * Check if 2FA is enabled for a user.
     * 
     * @param user the user
     * @return true if enabled, false otherwise
     */
    boolean is2FAEnabled(User user);
}
