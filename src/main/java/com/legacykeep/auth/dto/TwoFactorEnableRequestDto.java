package com.legacykeep.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * DTO for enabling 2FA.
 * 
 * Contains the TOTP code to verify before enabling 2FA.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
public class TwoFactorEnableRequestDto {

    @NotBlank(message = "TOTP code is required")
    @Pattern(regexp = "^\\d{6}$", message = "TOTP code must be 6 digits")
    private String totpCode;
}
