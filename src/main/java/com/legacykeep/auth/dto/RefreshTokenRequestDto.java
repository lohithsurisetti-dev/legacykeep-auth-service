package com.legacykeep.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO for refresh token requests.
 * 
 * Contains the refresh token for obtaining new access tokens.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
public class RefreshTokenRequestDto {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
