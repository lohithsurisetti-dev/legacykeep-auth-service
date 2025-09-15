package com.legacykeep.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO for social login requests.
 * 
 * Contains the social provider token for authentication.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
public class SocialLoginRequestDto {

    @NotBlank(message = "Social token is required")
    private String token;
}
