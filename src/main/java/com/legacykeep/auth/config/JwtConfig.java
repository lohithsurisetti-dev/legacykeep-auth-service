package com.legacykeep.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * JWT Configuration properties.
 * 
 * Manages JWT token settings, expiration times, and security configurations.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Component
@ConfigurationProperties(prefix = "auth.jwt")
public class JwtConfig {

    /**
     * JWT secret key for signing tokens.
     * Should be at least 256 bits (32 characters) for security.
     */
    private String secretKey = "legacykeep-jwt-secret-key-change-in-production-512-bits-minimum-required-for-hs512-algorithm";

    /**
     * JWT issuer claim.
     */
    private String issuer = "LegacyKeep";

    /**
     * JWT audience claim.
     */
    private String audience = "LegacyKeep-Users";

    /**
     * Access token expiration time in minutes.
     */
    private long accessTokenExpirationMinutes = 15;

    /**
     * Refresh token expiration time in days.
     */
    private long refreshTokenExpirationDays = 30;

    /**
     * Remember me token expiration time in days.
     */
    private long rememberMeExpirationDays = 90;

    /**
     * Maximum number of concurrent sessions per user.
     */
    private int maxConcurrentSessions = 5;

    /**
     * Token rotation enabled.
     */
    private boolean tokenRotationEnabled = true;

    /**
     * Blacklist expired tokens.
     */
    private boolean blacklistExpiredTokens = true;

    /**
     * Include user roles in JWT claims.
     */
    private boolean includeRolesInClaims = true;

    /**
     * Include user permissions in JWT claims.
     */
    private boolean includePermissionsInClaims = true;

    /**
     * Include device info in JWT claims.
     */
    private boolean includeDeviceInfoInClaims = true;

    /**
     * JWT algorithm for signing.
     */
    private String algorithm = "HS256";

    /**
     * Token prefix for Authorization header.
     */
    private String tokenPrefix = "Bearer ";

    /**
     * Header name for JWT token.
     */
    private String headerName = "Authorization";

    /**
     * Cookie name for refresh token.
     */
    private String refreshTokenCookieName = "refresh_token";

    /**
     * Cookie name for remember me token.
     */
    private String rememberMeCookieName = "remember_me";

    /**
     * Secure cookies (HTTPS only).
     */
    private boolean secureCookies = false;

    /**
     * HTTP only cookies.
     */
    private boolean httpOnlyCookies = true;

    /**
     * Same site cookie policy.
     */
    private String sameSitePolicy = "Strict";

    /**
     * Get access token expiration time in milliseconds.
     */
    public long getAccessTokenExpirationMillis() {
        return accessTokenExpirationMinutes * 60 * 1000;
    }

    /**
     * Get refresh token expiration time in milliseconds.
     */
    public long getRefreshTokenExpirationMillis() {
        return refreshTokenExpirationDays * 24 * 60 * 60 * 1000L;
    }

    /**
     * Get remember me expiration time in milliseconds.
     */
    public long getRememberMeExpirationMillis() {
        return rememberMeExpirationDays * 24 * 60 * 60 * 1000L;
    }
}
