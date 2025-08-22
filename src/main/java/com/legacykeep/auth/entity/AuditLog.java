package com.legacykeep.auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * AuditLog entity for comprehensive audit logging.
 * 
 * This entity tracks all authentication events, security actions,
 * and user activities for compliance, security monitoring, and debugging.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_logs_user_id", columnList = "user_id"),
    @Index(name = "idx_audit_logs_event_type", columnList = "event_type"),
    @Index(name = "idx_audit_logs_event_category", columnList = "event_category"),
    @Index(name = "idx_audit_logs_severity", columnList = "severity"),
    @Index(name = "idx_audit_logs_created_at", columnList = "created_at"),
    @Index(name = "idx_audit_logs_ip_address", columnList = "ip_address"),
    @Index(name = "idx_audit_logs_session_id", columnList = "session_id")
})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "session_id")
    private Long sessionId;

    @NotNull(message = "Event type is required")
    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;

    @NotNull(message = "Event category is required")
    @Column(name = "event_category", nullable = false, length = 50)
    private String eventCategory;

    @NotNull(message = "Severity is required")
    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 20)
    private AuditSeverity severity;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "details", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String details;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String userAgent;

    @Column(name = "request_method", length = 10)
    private String requestMethod;

    @Column(name = "request_url", columnDefinition = "TEXT")
    private String requestUrl;

    @Column(name = "request_headers", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String requestHeaders;

    @Column(name = "response_status")
    private Integer responseStatus;

    @Column(name = "response_time_ms")
    private Long responseTimeMs;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "stack_trace", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String stackTrace;

    @Column(name = "affected_user_id")
    private Long affectedUserId;

    @Column(name = "performed_by")
    private Long performedBy;

    @Column(name = "resource_type", length = 50)
    private String resourceType;

    @Column(name = "resource_id")
    private String resourceId;

    @Column(name = "old_values", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String oldValues;

    @Column(name = "new_values", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String newValues;

    @Column(name = "location", length = 255)
    private String location;

    @Column(name = "device_info", columnDefinition = "TEXT")
    @Convert(converter = com.legacykeep.auth.security.EncryptedStringConverter.class)
    private String deviceInfo;

    @Column(name = "browser_info", length = 255)
    private String browserInfo;

    @Column(name = "os_info", length = 255)
    private String osInfo;

    @Column(name = "is_successful", nullable = false)
    private boolean isSuccessful = true;

    @Column(name = "retention_days")
    private Integer retentionDays;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Version
    @Column(nullable = false)
    private Long version = 0L;

    // =============================================================================
    // Constructors
    // =============================================================================

    public AuditLog() {
        // Default constructor for JPA
    }

    public AuditLog(Long userId, String eventType, String eventCategory, AuditSeverity severity, String description) {
        this.userId = userId;
        this.eventType = eventType;
        this.eventCategory = eventCategory;
        this.severity = severity;
        this.description = description;
    }

    // =============================================================================
    // Business Logic Methods
    // =============================================================================

    /**
     * Check if this audit log should be retained based on retention policy.
     */
    @JsonIgnore
    public boolean shouldBeRetained() {
        if (retentionDays == null) {
            return true; // Keep indefinitely if no retention policy
        }
        return LocalDateTime.now().isBefore(createdAt.plusDays(retentionDays));
    }

    /**
     * Check if this audit log is expired based on retention policy.
     */
    @JsonIgnore
    public boolean isExpired() {
        return !shouldBeRetained();
    }

    /**
     * Get the age of this audit log in days.
     */
    @JsonIgnore
    public long getAgeInDays() {
        return java.time.Duration.between(createdAt, LocalDateTime.now()).toDays();
    }

    /**
     * Check if this is a security-related event.
     */
    @JsonIgnore
    public boolean isSecurityEvent() {
        return "SECURITY".equals(eventCategory) || 
               severity == AuditSeverity.HIGH || 
               severity == AuditSeverity.CRITICAL;
    }

    /**
     * Check if this is an authentication event.
     */
    @JsonIgnore
    public boolean isAuthenticationEvent() {
        return "AUTHENTICATION".equals(eventCategory);
    }

    /**
     * Check if this is an authorization event.
     */
    @JsonIgnore
    public boolean isAuthorizationEvent() {
        return "AUTHORIZATION".equals(eventCategory);
    }

    /**
     * Check if this is a user management event.
     */
    @JsonIgnore
    public boolean isUserManagementEvent() {
        return "USER_MANAGEMENT".equals(eventCategory);
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

    public Long getSessionId() {
        return sessionId;
    }

    public void setSessionId(Long sessionId) {
        this.sessionId = sessionId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getEventCategory() {
        return eventCategory;
    }

    public void setEventCategory(String eventCategory) {
        this.eventCategory = eventCategory;
    }

    public AuditSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(AuditSeverity severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
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

    public String getRequestMethod() {
        return requestMethod;
    }

    public void setRequestMethod(String requestMethod) {
        this.requestMethod = requestMethod;
    }

    public String getRequestUrl() {
        return requestUrl;
    }

    public void setRequestUrl(String requestUrl) {
        this.requestUrl = requestUrl;
    }

    public String getRequestHeaders() {
        return requestHeaders;
    }

    public void setRequestHeaders(String requestHeaders) {
        this.requestHeaders = requestHeaders;
    }

    public Integer getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(Integer responseStatus) {
        this.responseStatus = responseStatus;
    }

    public Long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(Long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(String stackTrace) {
        this.stackTrace = stackTrace;
    }

    public Long getAffectedUserId() {
        return affectedUserId;
    }

    public void setAffectedUserId(Long affectedUserId) {
        this.affectedUserId = affectedUserId;
    }

    public Long getPerformedBy() {
        return performedBy;
    }

    public void setPerformedBy(Long performedBy) {
        this.performedBy = performedBy;
    }

    public String getResourceType() {
        return resourceType;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getOldValues() {
        return oldValues;
    }

    public void setOldValues(String oldValues) {
        this.oldValues = oldValues;
    }

    public String getNewValues() {
        return newValues;
    }

    public void setNewValues(String newValues) {
        this.newValues = newValues;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getDeviceInfo() {
        return deviceInfo;
    }

    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    public String getBrowserInfo() {
        return browserInfo;
    }

    public void setBrowserInfo(String browserInfo) {
        this.browserInfo = browserInfo;
    }

    public String getOsInfo() {
        return osInfo;
    }

    public void setOsInfo(String osInfo) {
        this.osInfo = osInfo;
    }

    public boolean isSuccessful() {
        return isSuccessful;
    }

    public void setSuccessful(boolean successful) {
        isSuccessful = successful;
    }

    public Integer getRetentionDays() {
        return retentionDays;
    }

    public void setRetentionDays(Integer retentionDays) {
        this.retentionDays = retentionDays;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
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
        AuditLog auditLog = (AuditLog) o;
        return Objects.equals(id, auditLog.id) && Objects.equals(eventType, auditLog.eventType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, eventType);
    }

    @Override
    public String toString() {
        return "AuditLog{" +
                "id=" + id +
                ", userId=" + userId +
                ", eventType='" + eventType + '\'' +
                ", eventCategory='" + eventCategory + '\'' +
                ", severity=" + severity +
                ", isSuccessful=" + isSuccessful +
                ", createdAt=" + createdAt +
                '}';
    }
}

