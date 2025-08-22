package com.legacykeep.auth.service;

import com.legacykeep.auth.config.JwtConfig;
import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserSession;
import com.legacykeep.auth.repository.UserSessionRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * JWT Service for token generation, validation, and management.
 * 
 * Handles JWT token lifecycle including creation, validation, refresh,
 * and blacklisting for security.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtConfig jwtConfig;
    private final UserSessionRepository userSessionRepository;

    /**
     * Generate JWT tokens for user authentication.
     */
    public JwtTokenDto generateTokens(User user, String deviceInfo, String ipAddress, String location, boolean rememberMe) {
        try {
            // Generate unique session ID
            String sessionId = UUID.randomUUID().toString();
            
            // Calculate expiration times
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime accessTokenExpiresAt = now.plusMinutes(jwtConfig.getAccessTokenExpirationMinutes());
            LocalDateTime refreshTokenExpiresAt = rememberMe ? 
                now.plusDays(jwtConfig.getRememberMeExpirationDays()) : 
                now.plusDays(jwtConfig.getRefreshTokenExpirationDays());

            // Create access token
            String accessToken = generateAccessToken(user, sessionId, accessTokenExpiresAt);
            
            // Create refresh token
            String refreshToken = generateRefreshToken(user, sessionId, refreshTokenExpiresAt);

            // Save session to database
            UserSession userSession = new UserSession();
            userSession.setUserId(user.getId());
            userSession.setSessionToken(accessToken);
            userSession.setRefreshToken(refreshToken);
            userSession.setExpiresAt(refreshTokenExpiresAt);
            userSession.setDeviceInfo(deviceInfo);
            userSession.setIpAddress(ipAddress);
            userSession.setLoginLocation(location);
            userSession.setLoginMethod("PASSWORD");
            userSession.setSessionType("WEB");
            userSession.setSecurityLevel("MEDIUM");
            userSession.setRememberMe(rememberMe);
            userSession.setTwoFactorVerified(false); // Will be updated if 2FA is enabled

            UserSession savedSession = userSessionRepository.save(userSession);

            // Build response
            return JwtTokenDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtConfig.getAccessTokenExpirationMinutes() * 60L)
                    .refreshExpiresIn((refreshTokenExpiresAt.toEpochSecond(java.time.ZoneOffset.UTC) - now.toEpochSecond(java.time.ZoneOffset.UTC)))
                    .userId(user.getId())
                    .email(user.getEmail())
                    .username(user.getUsername())
                    .roles(new String[]{user.getRole().name()})
                    .sessionId(savedSession.getId())
                    .rememberMe(rememberMe)
                    .issuedAt(now)
                    .expiresAt(accessTokenExpiresAt)
                    .refreshExpiresAt(refreshTokenExpiresAt)
                    .deviceInfo(deviceInfo)
                    .ipAddress(ipAddress)
                    .location(location)
                    .build();

        } catch (Exception e) {
            log.error("Error generating JWT tokens for user {}: {}", user.getId(), e.getMessage(), e);
            throw new RuntimeException("Failed to generate authentication tokens", e);
        }
    }

    /**
     * Generate access token with user claims.
     */
    private String generateAccessToken(User user, String sessionId, LocalDateTime expiresAt) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("email", user.getEmail());
        claims.put("username", user.getUsername());
        claims.put("role", user.getRole().name());
        claims.put("sessionId", sessionId);
        claims.put("type", "ACCESS");

        // Always include roles in claims for authorization
        claims.put("roles", new String[]{user.getRole().name()});

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getEmail())
                .setIssuer(jwtConfig.getIssuer())
                .setAudience(jwtConfig.getAudience())
                .setIssuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant()))
                .setId(sessionId)
                .signWith(getSigningKey(), SignatureAlgorithm.valueOf(jwtConfig.getAlgorithm()))
                .compact();
    }

    /**
     * Generate refresh token with minimal claims.
     */
    private String generateRefreshToken(User user, String sessionId, LocalDateTime expiresAt) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("sessionId", sessionId);
        claims.put("type", "REFRESH");

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getEmail())
                .setIssuer(jwtConfig.getIssuer())
                .setAudience(jwtConfig.getAudience())
                .setIssuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant()))
                .setId(sessionId)
                .signWith(getSigningKey(), SignatureAlgorithm.valueOf(jwtConfig.getAlgorithm()))
                .compact();
    }

    /**
     * Validate and extract claims from JWT token.
     */
    public Optional<Claims> validateAndExtractClaims(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Check if token is blacklisted (if blacklisting is enabled)
            if (jwtConfig.isBlacklistExpiredTokens() && isTokenBlacklisted(token)) {
                log.warn("Token is blacklisted: {}", token);
                return Optional.empty();
            }

            return Optional.of(claims);
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
            return Optional.empty();
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}", e.getMessage());
            return Optional.empty();
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token: {}", e.getMessage());
            return Optional.empty();
        } catch (SecurityException e) {
            log.warn("Invalid JWT signature: {}", e.getMessage());
            return Optional.empty();
        } catch (IllegalArgumentException e) {
            log.warn("JWT token is empty: {}", e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            log.error("Error validating JWT token: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Extract user ID from JWT token.
     */
    public Optional<Long> extractUserId(String token) {
        return validateAndExtractClaims(token)
                .map(claims -> claims.get("userId", Long.class));
    }

    /**
     * Extract session ID from JWT token.
     */
    public Optional<String> extractSessionId(String token) {
        return validateAndExtractClaims(token)
                .map(claims -> claims.get("sessionId", String.class));
    }

    /**
     * Extract email from JWT token.
     */
    public Optional<String> extractEmail(String token) {
        return validateAndExtractClaims(token)
                .map(Claims::getSubject);
    }

    /**
     * Extract roles from JWT token.
     */
    public Optional<String[]> extractRoles(String token) {
        return validateAndExtractClaims(token)
                .map(claims -> {
                    Object rolesObj = claims.get("roles");
                    if (rolesObj instanceof String[]) {
                        return (String[]) rolesObj;
                    } else if (rolesObj instanceof String) {
                        return new String[]{(String) rolesObj};
                    }
                    return new String[0];
                });
    }

    /**
     * Check if token is expired.
     */
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Refresh access token using refresh token.
     */
    public Optional<JwtTokenDto> refreshAccessToken(String refreshToken) {
        try {
            Optional<Claims> claimsOpt = validateAndExtractClaims(refreshToken);
            if (claimsOpt.isEmpty()) {
                return Optional.empty();
            }

            Claims claims = claimsOpt.get();
            String tokenType = claims.get("type", String.class);
            
            if (!"REFRESH".equals(tokenType)) {
                log.warn("Invalid token type for refresh: {}", tokenType);
                return Optional.empty();
            }

            // Find the session in database
            String sessionId = claims.get("sessionId", String.class);
            Optional<UserSession> sessionOpt = userSessionRepository.findByRefreshToken(refreshToken);
            
            if (sessionOpt.isEmpty()) {
                log.warn("Session not found for refresh token");
                return Optional.empty();
            }

            UserSession session = sessionOpt.get();
            
            // Check if session is still valid
            if (!session.isValid()) {
                log.warn("Session is no longer valid for refresh");
                return Optional.empty();
            }

            // TODO: Get user from database using session.getUserId()
            // For now, we'll return empty as we need User entity
            
            return Optional.empty();

        } catch (Exception e) {
            log.error("Error refreshing access token: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Revoke token by blacklisting it.
     */
    public boolean revokeToken(String token) {
        try {
            // TODO: Implement token blacklisting with Redis
            // For now, we'll mark the session as revoked in database
            
            Optional<String> sessionIdOpt = extractSessionId(token);
            if (sessionIdOpt.isPresent()) {
                Optional<UserSession> sessionOpt = userSessionRepository.findBySessionToken(token);
                if (sessionOpt.isPresent()) {
                    UserSession session = sessionOpt.get();
                    session.revoke("MANUAL_REVOCATION", session.getUserId());
                    userSessionRepository.save(session);
                    return true;
                }
            }
            
            return false;
        } catch (Exception e) {
            log.error("Error revoking token: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Get signing key for JWT operations.
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Check if token is blacklisted.
     */
    private boolean isTokenBlacklisted(String token) {
        // TODO: Implement Redis-based token blacklisting
        // For now, return false
        return false;
    }
}
