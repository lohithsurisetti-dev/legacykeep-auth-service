package com.legacykeep.auth.event.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Base event structure for all events in the LegacyKeep system.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 * @since 2025-08-23
 */
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class BaseEvent {

    /**
     * Unique identifier for the event
     */
    private String eventId;

    /**
     * Type of the event (e.g., "user.registered.v1")
     */
    private String eventType;

    /**
     * Version of the event schema
     */
    private String eventVersion;

    /**
     * Timestamp when the event was created
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private Instant timestamp;

    /**
     * Source service that generated the event
     */
    private String source;

    /**
     * Correlation ID for tracing across services
     */
    private String correlationId;

    /**
     * User ID associated with the event (if applicable)
     */
    private String userId;

    /**
     * Additional metadata for the event
     */
    private Map<String, Object> metadata;

    /**
     * Initialize common event fields
     */
    protected void initializeEvent(String eventType, String userId) {
        this.eventId = UUID.randomUUID().toString();
        this.eventType = eventType;
        this.eventVersion = "1.0";
        this.timestamp = Instant.now();
        this.source = "auth-service";
        this.correlationId = UUID.randomUUID().toString();
        this.userId = userId;
    }

    /**
     * Get the event key for Kafka partitioning
     * Default implementation uses userId for partitioning
     */
    public String getEventKey() {
        return userId != null ? userId : eventId;
    }
}
