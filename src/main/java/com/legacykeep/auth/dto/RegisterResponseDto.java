package com.legacykeep.auth.dto;

import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO for user registration responses.
 * 
 * Contains user information and verification status
 * after successful registration.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponseDto {

    private Long userId;
    private String email;
    private String username;
    private String status;
    private boolean emailVerified;
    private LocalDateTime registeredAt;
    private String message;
}

