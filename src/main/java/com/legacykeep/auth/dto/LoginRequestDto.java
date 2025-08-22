package com.legacykeep.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO for user login requests.
 * 
 * Supports multi-method authentication (email or username)
 * with password and remember me functionality.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
public class LoginRequestDto {

    @NotBlank(message = "Email or username is required")
    private String identifier; // Can be email or username

    @NotBlank(message = "Password is required")
    private String password;

    private boolean rememberMe = false;
}

