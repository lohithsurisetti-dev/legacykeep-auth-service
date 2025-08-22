package com.legacykeep.auth.repository;

import com.legacykeep.auth.entity.AuditLog;
import com.legacykeep.auth.entity.AuditSeverity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository interface for AuditLog entity operations.
 * 
 * Provides data access methods for audit logging, security monitoring,
 * compliance reporting, and debugging purposes.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    // =============================================================================
    // User-based Queries
    // =============================================================================

    /**
     * Find audit logs by user ID.
     */
    List<AuditLog> findByUserIdOrderByCreatedAtDesc(Long userId);

    /**
     * Find audit logs by user ID with pagination.
     */
    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);

    /**
     * Find audit logs by affected user ID.
     */
    List<AuditLog> findByAffectedUserIdOrderByCreatedAtDesc(Long affectedUserId);

    /**
     * Find audit logs by performed by user ID.
     */
    List<AuditLog> findByPerformedByOrderByCreatedAtDesc(Long performedBy);

    /**
     * Find audit logs by user ID and event category.
     */
    List<AuditLog> findByUserIdAndEventCategoryOrderByCreatedAtDesc(Long userId, String eventCategory);

    /**
     * Find audit logs by user ID and severity.
     */
    List<AuditLog> findByUserIdAndSeverityOrderByCreatedAtDesc(Long userId, AuditSeverity severity);

    // =============================================================================
    // Event-based Queries
    // =============================================================================

    /**
     * Find audit logs by event type.
     */
    List<AuditLog> findByEventTypeOrderByCreatedAtDesc(String eventType);

    /**
     * Find audit logs by event category.
     */
    List<AuditLog> findByEventCategoryOrderByCreatedAtDesc(String eventCategory);

    /**
     * Find audit logs by event type and category.
     */
    List<AuditLog> findByEventTypeAndEventCategoryOrderByCreatedAtDesc(String eventType, String eventCategory);

    /**
     * Find audit logs by severity level.
     */
    List<AuditLog> findBySeverityOrderByCreatedAtDesc(AuditSeverity severity);

    /**
     * Find audit logs by severity level with pagination.
     */
    Page<AuditLog> findBySeverityOrderByCreatedAtDesc(AuditSeverity severity, Pageable pageable);

    /**
     * Find audit logs by success status.
     */
    List<AuditLog> findByIsSuccessfulOrderByCreatedAtDesc(boolean isSuccessful);

    // =============================================================================
    // Session-based Queries
    // =============================================================================

    /**
     * Find audit logs by session ID.
     */
    List<AuditLog> findBySessionIdOrderByCreatedAtDesc(Long sessionId);

    /**
     * Find audit logs by user ID and session ID.
     */
    List<AuditLog> findByUserIdAndSessionIdOrderByCreatedAtDesc(Long userId, Long sessionId);

    // =============================================================================
    // Time-based Queries
    // =============================================================================

    /**
     * Find audit logs created in date range.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.createdAt BETWEEN :startDate AND :endDate ORDER BY al.createdAt DESC")
    List<AuditLog> findAuditLogsCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find audit logs created in date range with pagination.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.createdAt BETWEEN :startDate AND :endDate ORDER BY al.createdAt DESC")
    Page<AuditLog> findAuditLogsCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate, Pageable pageable);

    /**
     * Find audit logs created after a specific date.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.createdAt >= :startDate ORDER BY al.createdAt DESC")
    List<AuditLog> findAuditLogsCreatedAfter(@Param("startDate") LocalDateTime startDate);

    /**
     * Find audit logs created before a specific date.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.createdAt <= :endDate ORDER BY al.createdAt DESC")
    List<AuditLog> findAuditLogsCreatedBefore(@Param("endDate") LocalDateTime endDate);

    /**
     * Find audit logs from the last N days.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.createdAt >= :daysAgo ORDER BY al.createdAt DESC")
    List<AuditLog> findAuditLogsFromLastDays(@Param("daysAgo") LocalDateTime daysAgo);

    // =============================================================================
    // Security and Compliance Queries
    // =============================================================================

    /**
     * Find security-related audit logs.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.eventCategory = 'SECURITY' OR al.severity IN ('HIGH', 'CRITICAL') ORDER BY al.createdAt DESC")
    List<AuditLog> findSecurityAuditLogs();

    /**
     * Find authentication-related audit logs.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.eventCategory = 'AUTHENTICATION' ORDER BY al.createdAt DESC")
    List<AuditLog> findAuthenticationAuditLogs();

    /**
     * Find authorization-related audit logs.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.eventCategory = 'AUTHORIZATION' ORDER BY al.createdAt DESC")
    List<AuditLog> findAuthorizationAuditLogs();

    /**
     * Find user management audit logs.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.eventCategory = 'USER_MANAGEMENT' ORDER BY al.createdAt DESC")
    List<AuditLog> findUserManagementAuditLogs();

    /**
     * Find failed operations audit logs.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.isSuccessful = false ORDER BY al.createdAt DESC")
    List<AuditLog> findFailedOperationsAuditLogs();

    /**
     * Find high and critical severity audit logs.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.severity IN ('HIGH', 'CRITICAL') ORDER BY al.createdAt DESC")
    List<AuditLog> findHighCriticalAuditLogs();

    // =============================================================================
    // IP and Location Queries
    // =============================================================================

    /**
     * Find audit logs by IP address.
     */
    List<AuditLog> findByIpAddressOrderByCreatedAtDesc(String ipAddress);

    /**
     * Find audit logs by location.
     */
    List<AuditLog> findByLocationOrderByCreatedAtDesc(String location);

    /**
     * Find audit logs by IP address and time range.
     */
    @Query("SELECT al FROM AuditLog al WHERE al.ipAddress = :ipAddress AND al.createdAt BETWEEN :startDate AND :endDate ORDER BY al.createdAt DESC")
    List<AuditLog> findByIpAddressAndTimeRange(@Param("ipAddress") String ipAddress, @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    // =============================================================================
    // Resource-based Queries
    // =============================================================================

    /**
     * Find audit logs by resource type.
     */
    List<AuditLog> findByResourceTypeOrderByCreatedAtDesc(String resourceType);

    /**
     * Find audit logs by resource type and ID.
     */
    List<AuditLog> findByResourceTypeAndResourceIdOrderByCreatedAtDesc(String resourceType, String resourceId);

    // =============================================================================
    // Count Queries
    // =============================================================================

    /**
     * Count audit logs by user ID.
     */
    long countByUserId(Long userId);

    /**
     * Count audit logs by event type.
     */
    long countByEventType(String eventType);

    /**
     * Count audit logs by event category.
     */
    long countByEventCategory(String eventCategory);

    /**
     * Count audit logs by severity.
     */
    long countBySeverity(AuditSeverity severity);

    /**
     * Count audit logs by success status.
     */
    long countByIsSuccessful(boolean isSuccessful);

    /**
     * Count audit logs by IP address.
     */
    long countByIpAddress(String ipAddress);

    /**
     * Count audit logs created in date range.
     */
    @Query("SELECT COUNT(al) FROM AuditLog al WHERE al.createdAt BETWEEN :startDate AND :endDate")
    long countAuditLogsCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Count security audit logs.
     */
    @Query("SELECT COUNT(al) FROM AuditLog al WHERE al.eventCategory = 'SECURITY' OR al.severity IN ('HIGH', 'CRITICAL')")
    long countSecurityAuditLogs();

    /**
     * Count failed operations.
     */
    @Query("SELECT COUNT(al) FROM AuditLog al WHERE al.isSuccessful = false")
    long countFailedOperations();

    // =============================================================================
    // Bulk Operations
    // =============================================================================

    /**
     * Delete expired audit logs based on retention policy.
     */
    @Modifying
    @Query("DELETE FROM AuditLog al WHERE al.retentionDays IS NOT NULL AND al.createdAt < :expiryDate")
    int deleteExpiredAuditLogs(@Param("expiryDate") LocalDateTime expiryDate);

    /**
     * Delete audit logs older than specified date.
     */
    @Modifying
    @Query("DELETE FROM AuditLog al WHERE al.createdAt < :cutoffDate")
    int deleteAuditLogsOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Delete audit logs by user ID.
     */
    @Modifying
    @Query("DELETE FROM AuditLog al WHERE al.userId = :userId")
    int deleteAuditLogsByUserId(@Param("userId") Long userId);

    // =============================================================================
    // Advanced Analytics Queries
    // =============================================================================

    /**
     * Find most frequent event types in date range.
     */
    @Query("SELECT al.eventType, COUNT(al) as count FROM AuditLog al WHERE al.createdAt BETWEEN :startDate AND :endDate GROUP BY al.eventType ORDER BY count DESC")
    List<Object[]> findMostFrequentEventTypes(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find most active IP addresses in date range.
     */
    @Query("SELECT al.ipAddress, COUNT(al) as count FROM AuditLog al WHERE al.createdAt BETWEEN :startDate AND :endDate AND al.ipAddress IS NOT NULL GROUP BY al.ipAddress ORDER BY count DESC")
    List<Object[]> findMostActiveIpAddresses(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find users with most failed operations.
     */
    @Query("SELECT al.userId, COUNT(al) as count FROM AuditLog al WHERE al.isSuccessful = false AND al.createdAt BETWEEN :startDate AND :endDate GROUP BY al.userId ORDER BY count DESC")
    List<Object[]> findUsersWithMostFailedOperations(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
}

