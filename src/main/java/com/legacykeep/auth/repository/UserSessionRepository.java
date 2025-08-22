package com.legacykeep.auth.repository;

import com.legacykeep.auth.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for UserSession entity operations.
 * 
 * Provides data access methods for session management and JWT token operations.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    // =============================================================================
    // Token-based Queries
    // =============================================================================

    /**
     * Find session by session token.
     */
    Optional<UserSession> findBySessionToken(String sessionToken);

    /**
     * Find session by refresh token.
     */
    Optional<UserSession> findByRefreshToken(String refreshToken);

    /**
     * Check if session token exists.
     */
    boolean existsBySessionToken(String sessionToken);

    /**
     * Check if refresh token exists.
     */
    boolean existsByRefreshToken(String refreshToken);

    // =============================================================================
    // User-based Queries
    // =============================================================================

    /**
     * Find all active sessions for a user.
     */
    @Query("SELECT us FROM UserSession us WHERE us.userId = :userId AND us.isActive = true AND us.revokedAt IS NULL")
    List<UserSession> findActiveSessionsByUserId(@Param("userId") Long userId);

    /**
     * Find all sessions for a user (including inactive).
     */
    List<UserSession> findByUserIdOrderByCreatedAtDesc(Long userId);

    /**
     * Count active sessions for a user.
     */
    @Query("SELECT COUNT(us) FROM UserSession us WHERE us.userId = :userId AND us.isActive = true AND us.revokedAt IS NULL")
    long countActiveSessionsByUserId(@Param("userId") Long userId);

    /**
     * Find sessions by user ID and session type.
     */
    @Query("SELECT us FROM UserSession us WHERE us.userId = :userId AND us.sessionType = :sessionType AND us.isActive = true")
    List<UserSession> findByUserIdAndSessionType(@Param("userId") Long userId, @Param("sessionType") String sessionType);

    // =============================================================================
    // Status-based Queries
    // =============================================================================

    /**
     * Find all active sessions.
     */
    @Query("SELECT us FROM UserSession us WHERE us.isActive = true AND us.revokedAt IS NULL")
    List<UserSession> findAllActiveSessions();

    /**
     * Find expired sessions.
     */
    @Query("SELECT us FROM UserSession us WHERE us.expiresAt <= :now")
    List<UserSession> findExpiredSessions(@Param("now") LocalDateTime now);

    /**
     * Find sessions expiring soon (within specified minutes).
     */
    @Query("SELECT us FROM UserSession us WHERE us.expiresAt BETWEEN :now AND :expiryThreshold AND us.isActive = true")
    List<UserSession> findSessionsExpiringSoon(@Param("now") LocalDateTime now, @Param("expiryThreshold") LocalDateTime expiryThreshold);

    /**
     * Find revoked sessions.
     */
    @Query("SELECT us FROM UserSession us WHERE us.revokedAt IS NOT NULL")
    List<UserSession> findRevokedSessions();

    /**
     * Find sessions by security level.
     */
    List<UserSession> findBySecurityLevelAndIsActiveTrue(String securityLevel);

    // =============================================================================
    // Device and Location Queries
    // =============================================================================

    /**
     * Find sessions by IP address.
     */
    List<UserSession> findByIpAddressAndIsActiveTrue(String ipAddress);

    /**
     * Find sessions by login location.
     */
    List<UserSession> findByLoginLocationAndIsActiveTrue(String loginLocation);

    /**
     * Find sessions by login method.
     */
    List<UserSession> findByLoginMethodAndIsActiveTrue(String loginMethod);

    /**
     * Find sessions by session type.
     */
    List<UserSession> findBySessionTypeAndIsActiveTrue(String sessionType);

    // =============================================================================
    // Time-based Queries
    // =============================================================================

    /**
     * Find sessions created in date range.
     */
    @Query("SELECT us FROM UserSession us WHERE us.createdAt BETWEEN :startDate AND :endDate")
    List<UserSession> findSessionsCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find sessions last used in date range.
     */
    @Query("SELECT us FROM UserSession us WHERE us.lastUsedAt BETWEEN :startDate AND :endDate")
    List<UserSession> findSessionsLastUsedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find sessions that haven't been used recently.
     */
    @Query("SELECT us FROM UserSession us WHERE us.lastUsedAt <= :threshold AND us.isActive = true")
    List<UserSession> findInactiveSessions(@Param("threshold") LocalDateTime threshold);

    // =============================================================================
    // Count Queries
    // =============================================================================

    /**
     * Count total active sessions.
     */
    @Query("SELECT COUNT(us) FROM UserSession us WHERE us.isActive = true AND us.revokedAt IS NULL")
    long countActiveSessions();

    /**
     * Count sessions by session type.
     */
    @Query("SELECT COUNT(us) FROM UserSession us WHERE us.sessionType = :sessionType AND us.isActive = true")
    long countActiveSessionsByType(@Param("sessionType") String sessionType);

    /**
     * Count sessions by login method.
     */
    @Query("SELECT COUNT(us) FROM UserSession us WHERE us.loginMethod = :loginMethod AND us.isActive = true")
    long countActiveSessionsByLoginMethod(@Param("loginMethod") String loginMethod);

    /**
     * Count sessions created in date range.
     */
    @Query("SELECT COUNT(us) FROM UserSession us WHERE us.createdAt BETWEEN :startDate AND :endDate")
    long countSessionsCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    // =============================================================================
    // Bulk Operations
    // =============================================================================

    /**
     * Revoke all sessions for a user.
     */
    @Modifying
    @Query("UPDATE UserSession us SET us.isActive = false, us.revokedAt = :revokedAt, us.revokedReason = :reason, us.revokedBy = :revokedBy WHERE us.userId = :userId AND us.isActive = true")
    int revokeAllSessionsForUser(@Param("userId") Long userId, @Param("revokedAt") LocalDateTime revokedAt, @Param("reason") String reason, @Param("revokedBy") Long revokedBy);

    /**
     * Revoke expired sessions.
     */
    @Modifying
    @Query("UPDATE UserSession us SET us.isActive = false, us.revokedAt = :revokedAt, us.revokedReason = 'EXPIRED' WHERE us.expiresAt <= :now AND us.isActive = true")
    int revokeExpiredSessions(@Param("now") LocalDateTime now, @Param("revokedAt") LocalDateTime revokedAt);

    /**
     * Revoke sessions by session type.
     */
    @Modifying
    @Query("UPDATE UserSession us SET us.isActive = false, us.revokedAt = :revokedAt, us.revokedReason = :reason, us.revokedBy = :revokedBy WHERE us.sessionType = :sessionType AND us.isActive = true")
    int revokeSessionsByType(@Param("sessionType") String sessionType, @Param("revokedAt") LocalDateTime revokedAt, @Param("reason") String reason, @Param("revokedBy") Long revokedBy);

    /**
     * Delete old revoked sessions (cleanup).
     */
    @Modifying
    @Query("DELETE FROM UserSession us WHERE us.revokedAt <= :threshold")
    int deleteOldRevokedSessions(@Param("threshold") LocalDateTime threshold);

    // =============================================================================
    // Security Queries
    // =============================================================================

    /**
     * Find sessions with high security level.
     */
    @Query("SELECT us FROM UserSession us WHERE us.securityLevel IN ('HIGH', 'CRITICAL') AND us.isActive = true")
    List<UserSession> findHighSecuritySessions();

    /**
     * Find sessions that need two-factor verification.
     */
    @Query("SELECT us FROM UserSession us WHERE us.twoFactorVerified = false AND us.isActive = true")
    List<UserSession> findSessionsNeedingTwoFactorVerification();

    /**
     * Find remember-me sessions.
     */
    @Query("SELECT us FROM UserSession us WHERE us.rememberMe = true AND us.isActive = true")
    List<UserSession> findRememberMeSessions();
}
