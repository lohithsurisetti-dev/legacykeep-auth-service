package com.legacykeep.auth.service;

import com.legacykeep.auth.event.dto.BaseEvent;

/**
 * Service interface for publishing events to Kafka topics.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 * @since 2025-08-23
 */
public interface EventPublisherService {

    /**
     * Publish an event to the specified Kafka topic.
     * 
     * @param topic The Kafka topic to publish to
     * @param event The event to publish
     * @param <T> The type of event extending BaseEvent
     */
    <T extends BaseEvent> void publishEvent(String topic, T event);

    /**
     * Publish an event to the default user events topic.
     * 
     * @param event The event to publish
     * @param <T> The type of event extending BaseEvent
     */
    <T extends BaseEvent> void publishUserEvent(T event);

    /**
     * Publish an event to the default auth events topic.
     * 
     * @param event The event to publish
     * @param <T> The type of event extending BaseEvent
     */
    <T extends BaseEvent> void publishAuthEvent(T event);

    /**
     * Publish an event with a specific key for partitioning.
     * 
     * @param topic The Kafka topic to publish to
     * @param key The key for partitioning
     * @param event The event to publish
     * @param <T> The type of event extending BaseEvent
     */
    <T extends BaseEvent> void publishEvent(String topic, String key, T event);
}
