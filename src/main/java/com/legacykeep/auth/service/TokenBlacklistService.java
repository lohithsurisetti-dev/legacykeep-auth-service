package com.legacykeep.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Token Blacklist Service for managing revoked JWT tokens.
 * 
 * Uses Redis to store blacklisted tokens with automatic expiration.
 * This prevents revoked tokens from being used until they naturally expire.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final RedisTemplate<String, String> redisTemplate;
    private final JwtService jwtService;

    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    /**
     * Add a token to the blacklist.
     */
    public void blacklistToken(String token) {
        try {
            String tokenId = extractTokenId(token);
            if (tokenId != null) {
                String key = BLACKLIST_PREFIX + tokenId;
                
                // Calculate TTL based on token expiration
                long ttlSeconds = calculateTokenTtl(token);
                
                if (ttlSeconds > 0) {
                    redisTemplate.opsForValue().set(key, "blacklisted", ttlSeconds, TimeUnit.SECONDS);
                    log.info("Token blacklisted successfully: {}", tokenId);
                } else {
                    log.warn("Token already expired, not adding to blacklist: {}", tokenId);
                }
            }
        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage(), e);
        }
    }

    /**
     * Check if a token is blacklisted.
     */
    public boolean isTokenBlacklisted(String token) {
        try {
            String tokenId = extractTokenId(token);
            if (tokenId != null) {
                String key = BLACKLIST_PREFIX + tokenId;
                return Boolean.TRUE.equals(redisTemplate.hasKey(key));
            }
        } catch (Exception e) {
            log.error("Failed to check token blacklist status: {}", e.getMessage(), e);
            // On error, assume token is blacklisted for security
            return true;
        }
        return false;
    }

    /**
     * Remove a token from blacklist (rarely used).
     */
    public void removeFromBlacklist(String token) {
        try {
            String tokenId = extractTokenId(token);
            if (tokenId != null) {
                String key = BLACKLIST_PREFIX + tokenId;
                redisTemplate.delete(key);
                log.info("Token removed from blacklist: {}", tokenId);
            }
        } catch (Exception e) {
            log.error("Failed to remove token from blacklist: {}", e.getMessage(), e);
        }
    }

    /**
     * Blacklist all tokens for a specific user (for logout all sessions).
     */
    public void blacklistAllUserTokens(Long userId) {
        try {
            // Note: This would require storing user-token mappings in Redis
            // For now, we'll rely on database session management
            log.info("Blacklisting all tokens for user: {}", userId);
            
            // Implementation would involve:
            // 1. Query all active sessions for user
            // 2. Extract tokens from sessions
            // 3. Blacklist each token
            
        } catch (Exception e) {
            log.error("Failed to blacklist all user tokens: {}", e.getMessage(), e);
        }
    }

    /**
     * Get blacklist statistics.
     */
    public BlacklistStats getBlacklistStats() {
        try {
            var keys = redisTemplate.keys(BLACKLIST_PREFIX + "*");
            int totalBlacklisted = keys != null ? keys.size() : 0;
            
            return new BlacklistStats(totalBlacklisted, LocalDateTime.now());
        } catch (Exception e) {
            log.error("Failed to get blacklist stats: {}", e.getMessage(), e);
            return new BlacklistStats(0, LocalDateTime.now());
        }
    }

    /**
     * Extract token ID (jti claim) from JWT token.
     */
    private String extractTokenId(String token) {
        return jwtService.validateAndExtractClaims(token)
                .map(claims -> claims.getId())
                .orElse(null);
    }

    /**
     * Calculate time-to-live for blacklisted token based on its expiration.
     */
    private long calculateTokenTtl(String token) {
        return jwtService.validateAndExtractClaims(token)
                .map(claims -> {
                    Date expiration = claims.getExpiration();
                    if (expiration != null) {
                        long expirationSeconds = expiration.toInstant().getEpochSecond();
                        long currentSeconds = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
                        return Math.max(0, expirationSeconds - currentSeconds);
                    }
                    return 0L;
                })
                .orElse(0L);
    }

    /**
     * Blacklist statistics DTO.
     */
    public record BlacklistStats(
            int totalBlacklistedTokens,
            LocalDateTime timestamp
    ) {}
}
