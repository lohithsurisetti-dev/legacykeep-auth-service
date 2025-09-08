package com.legacykeep.auth.repository;

import com.legacykeep.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for User entity operations.
 * 
 * Provides data access methods for user authentication and management.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // =============================================================================
    // Basic Find Operations
    // =============================================================================

    /**
     * Find user by email (case-insensitive).
     */
    Optional<User> findByEmailIgnoreCase(String email);

    /**
     * Find user by username (case-insensitive).
     */
    Optional<User> findByUsernameIgnoreCase(String username);

    /**
     * Find user by email verification token.
     */
    Optional<User> findByEmailVerificationToken(String token);

    /**
     * Find user by password reset token.
     */
    Optional<User> findByPasswordResetToken(String token);

    /**
     * Find user by social login ID.
     */
    Optional<User> findByGoogleId(String googleId);
    Optional<User> findByAppleId(String appleId);
    Optional<User> findByFacebookId(String facebookId);

    /**
     * Find user by email hash (for efficient encrypted field searches).
     */
    Optional<User> findByEmailHash(String emailHash);

    /**
     * Find user by username hash (for efficient encrypted field searches).
     */
    Optional<User> findByUsernameHash(String usernameHash);

    /**
     * Find user by phone number hash (for efficient encrypted field searches).
     */
    Optional<User> findByPhoneNumberHash(String phoneNumberHash);

    /**
     * Find user by phone verification token.
     */
    Optional<User> findByPhoneVerificationToken(String token);

    // =============================================================================
    // Status-based Queries
    // =============================================================================

    /**
     * Find all active users.
     */
    @Query("SELECT u FROM User u WHERE u.status = 'ACTIVE' AND u.deletedAt IS NULL")
    List<User> findAllActiveUsers();

    /**
     * Find users by status.
     */
    List<User> findByStatus(com.legacykeep.auth.entity.UserStatus status);

    /**
     * Find users pending email verification.
     */
    @Query("SELECT u FROM User u WHERE u.status = 'PENDING_VERIFICATION' AND u.emailVerificationExpiresAt > :now")
    List<User> findPendingVerificationUsers(@Param("now") LocalDateTime now);

    /**
     * Find users with expired verification tokens.
     */
    @Query("SELECT u FROM User u WHERE u.status = 'PENDING_VERIFICATION' AND u.emailVerificationExpiresAt <= :now")
    List<User> findExpiredVerificationUsers(@Param("now") LocalDateTime now);

    // =============================================================================
    // Security Queries
    // =============================================================================

    /**
     * Find users with failed login attempts above threshold.
     */
    @Query("SELECT u FROM User u WHERE u.failedLoginAttempts >= :threshold")
    List<User> findUsersWithHighFailedAttempts(@Param("threshold") int threshold);

    /**
     * Find locked users.
     */
    @Query("SELECT u FROM User u WHERE u.accountLockedUntil IS NOT NULL AND u.accountLockedUntil > :now")
    List<User> findLockedUsers(@Param("now") LocalDateTime now);

    /**
     * Find suspended users.
     */
    @Query("SELECT u FROM User u WHERE u.status = 'SUSPENDED' AND (u.suspendedUntil IS NULL OR u.suspendedUntil > :now)")
    List<User> findSuspendedUsers(@Param("now") LocalDateTime now);

    // =============================================================================
    // Soft Delete Queries
    // =============================================================================

    /**
     * Find soft-deleted users.
     */
    @Query("SELECT u FROM User u WHERE u.deletedAt IS NOT NULL")
    List<User> findDeletedUsers();

    /**
     * Find users scheduled for deletion.
     */
    @Query("SELECT u FROM User u WHERE u.deletionScheduledAt IS NOT NULL AND u.deletionScheduledAt <= :now")
    List<User> findUsersScheduledForDeletion(@Param("now") LocalDateTime now);

    // =============================================================================
    // Existence Checks
    // =============================================================================

    /**
     * Check if email exists (case-insensitive).
     */
    boolean existsByEmailIgnoreCase(String email);

    /**
     * Check if username exists (case-insensitive).
     */
    boolean existsByUsernameIgnoreCase(String username);

    /**
     * Check if email hash exists.
     */
    boolean existsByEmailHash(String emailHash);

    /**
     * Check if username hash exists.
     */
    boolean existsByUsernameHash(String usernameHash);

    /**
     * Check if phone number hash exists.
     */
    boolean existsByPhoneNumberHash(String phoneNumberHash);

    // =============================================================================
    // Count Queries
    // =============================================================================

    /**
     * Count users by status.
     */
    long countByStatus(com.legacykeep.auth.entity.UserStatus status);

    /**
     * Count active users.
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.status = 'ACTIVE' AND u.deletedAt IS NULL")
    long countActiveUsers();

    /**
     * Count users created in date range.
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt BETWEEN :startDate AND :endDate")
    long countUsersCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find all users (for encrypted field searches).
     * This method is used when we need to search by encrypted fields.
     * The filtering should be done in the service layer.
     */
    @Query("SELECT u FROM User u WHERE u.deletedAt IS NULL")
    List<User> findAllActiveUsersForSearch();
}
