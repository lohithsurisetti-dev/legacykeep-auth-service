package com.legacykeep.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * JWT Token DTO for authentication responses.
 * 
 * Contains access token, refresh token, and related information.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class JwtTokenDto {

    /**
     * Access token for API authentication.
     */
    private String accessToken;

    /**
     * Refresh token for obtaining new access tokens.
     */
    private String refreshToken;

    /**
     * Token type (usually "Bearer").
     */
    @Builder.Default
    private String tokenType = "Bearer";

    /**
     * Access token expiration time in seconds.
     */
    private Long expiresIn;

    /**
     * Refresh token expiration time in seconds.
     */
    private Long refreshExpiresIn;

    /**
     * User ID associated with the token.
     */
    private Long userId;

    /**
     * User email associated with the token.
     */
    private String email;

    /**
     * User username associated with the token.
     */
    private String username;

    /**
     * User roles associated with the token.
     */
    private String[] roles;

    /**
     * Session ID for this token.
     */
    private Long sessionId;

    /**
     * Whether this is a remember-me session.
     */
    private Boolean rememberMe;

    /**
     * Token issued at timestamp.
     */
    private LocalDateTime issuedAt;

    /**
     * Access token expiration timestamp.
     */
    private LocalDateTime expiresAt;

    /**
     * Refresh token expiration timestamp.
     */
    private LocalDateTime refreshExpiresAt;

    /**
     * Device information for this session.
     */
    private String deviceInfo;

    /**
     * IP address for this session.
     */
    private String ipAddress;

    /**
     * Location information for this session.
     */
    private String location;
}
