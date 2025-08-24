package com.legacykeep.auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * UserSession entity for JWT token and session management.
 * 
 * This entity manages user sessions, JWT tokens, and device tracking
 * for authentication and security purposes.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Entity
@Table(name = "user_sessions", indexes = {
    @Index(name = "idx_user_sessions_user_id", columnList = "user_id"),
    @Index(name = "idx_user_sessions_session_token", columnList = "session_token"),
    @Index(name = "idx_user_sessions_refresh_token", columnList = "refresh_token"),
    @Index(name = "idx_user_sessions_expires_at", columnList = "expires_at"),
    @Index(name = "idx_user_sessions_is_active", columnList = "is_active"),
    @Index(name = "idx_user_sessions_created_at", columnList = "created_at"),
    @Index(name = "idx_user_sessions_last_used_at", columnList = "last_used_at")
})
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull(message = "User ID is required")
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @NotNull(message = "Session token is required")
    @Column(name = "session_token", unique = true, nullable = false, length = 500)
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String sessionToken;

    @NotNull(message = "Refresh token is required")
    @Column(name = "refresh_token", unique = true, nullable = false, length = 500)
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String refreshToken;

    @Column(name = "device_info", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String deviceInfo;

    @Column(name = "ip_address")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String userAgent;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @NotNull(message = "Expiration time is required")
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @UpdateTimestamp
    @Column(name = "last_used_at", nullable = false)
    private LocalDateTime lastUsedAt;

    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @Column(name = "revoked_reason", length = 255)
    private String revokedReason;

    @Column(name = "revoked_by")
    private Long revokedBy;

    @Column(name = "login_location", length = 255)
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String loginLocation;

    @Column(name = "login_method", length = 50)
    private String loginMethod; // PASSWORD, GOOGLE, APPLE, FACEBOOK, etc.

    @Column(name = "session_type", length = 50)
    private String sessionType; // WEB, MOBILE, DESKTOP, API

    @Column(name = "security_level", length = 20)
    private String securityLevel; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(name = "two_factor_verified", nullable = false)
    private boolean twoFactorVerified = false;

    @Column(name = "remember_me", nullable = false)
    private boolean rememberMe = false;

    @Version
    @Column(nullable = false)
    private Long version = 0L;

    // =============================================================================
    // Constructors
    // =============================================================================

    public UserSession() {
        // Default constructor for JPA
    }

    public UserSession(Long userId, String sessionToken, String refreshToken, LocalDateTime expiresAt) {
        this.userId = userId;
        this.sessionToken = sessionToken;
        this.refreshToken = refreshToken;
        this.expiresAt = expiresAt;
        this.lastUsedAt = LocalDateTime.now();
    }

    // =============================================================================
    // Business Logic Methods
    // =============================================================================

    /**
     * Check if the session is expired.
     */
    @JsonIgnore
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Check if the session is valid (active and not expired).
     */
    @JsonIgnore
    public boolean isValid() {
        return isActive && !isExpired() && revokedAt == null;
    }

    /**
     * Check if the session is revoked.
     */
    @JsonIgnore
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /**
     * Revoke the session.
     */
    public void revoke(String reason, Long revokedBy) {
        this.isActive = false;
        this.revokedAt = LocalDateTime.now();
        this.revokedReason = reason;
        this.revokedBy = revokedBy;
    }

    /**
     * Update the last used timestamp.
     */
    public void updateLastUsed() {
        this.lastUsedAt = LocalDateTime.now();
    }

    /**
     * Extend the session expiration time.
     */
    public void extendSession(LocalDateTime newExpiresAt) {
        this.expiresAt = newExpiresAt;
        this.lastUsedAt = LocalDateTime.now();
    }

    /**
     * Get session duration in minutes.
     */
    @JsonIgnore
    public long getSessionDurationMinutes() {
        return java.time.Duration.between(createdAt, LocalDateTime.now()).toMinutes();
    }

    /**
     * Get remaining time in minutes before expiration.
     */
    @JsonIgnore
    public long getRemainingTimeMinutes() {
        if (isExpired()) {
            return 0;
        }
        return java.time.Duration.between(LocalDateTime.now(), expiresAt).toMinutes();
    }

    // =============================================================================
    // Getters and Setters
    // =============================================================================

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getDeviceInfo() {
        return deviceInfo;
    }

    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getLastUsedAt() {
        return lastUsedAt;
    }

    public void setLastUsedAt(LocalDateTime lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(LocalDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getRevokedReason() {
        return revokedReason;
    }

    public void setRevokedReason(String revokedReason) {
        this.revokedReason = revokedReason;
    }

    public Long getRevokedBy() {
        return revokedBy;
    }

    public void setRevokedBy(Long revokedBy) {
        this.revokedBy = revokedBy;
    }

    public String getLoginLocation() {
        return loginLocation;
    }

    public void setLoginLocation(String loginLocation) {
        this.loginLocation = loginLocation;
    }

    public String getLoginMethod() {
        return loginMethod;
    }

    public void setLoginMethod(String loginMethod) {
        this.loginMethod = loginMethod;
    }

    public String getSessionType() {
        return sessionType;
    }

    public void setSessionType(String sessionType) {
        this.sessionType = sessionType;
    }

    public String getSecurityLevel() {
        return securityLevel;
    }

    public void setSecurityLevel(String securityLevel) {
        this.securityLevel = securityLevel;
    }

    public boolean isTwoFactorVerified() {
        return twoFactorVerified;
    }

    public void setTwoFactorVerified(boolean twoFactorVerified) {
        this.twoFactorVerified = twoFactorVerified;
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    // =============================================================================
    // equals, hashCode, toString
    // =============================================================================

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserSession that = (UserSession) o;
        return Objects.equals(id, that.id) && Objects.equals(sessionToken, that.sessionToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, sessionToken);
    }

    @Override
    public String toString() {
        return "UserSession{" +
                "id=" + id +
                ", userId=" + userId +
                ", sessionType='" + sessionType + '\'' +
                ", loginMethod='" + loginMethod + '\'' +
                ", isActive=" + isActive +
                ", expiresAt=" + expiresAt +
                ", createdAt=" + createdAt +
                '}';
    }
}

