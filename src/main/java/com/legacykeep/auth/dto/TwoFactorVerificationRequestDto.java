package com.legacykeep.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * DTO for 2FA verification requests.
 * 
 * Contains the TOTP code or backup code for verification.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
public class TwoFactorVerificationRequestDto {

    @NotBlank(message = "Verification code is required")
    @Pattern(regexp = "^\\d{6}$|^\\d{8}$", message = "Code must be either 6 digits (TOTP) or 8 digits (backup)")
    private String code;
}
