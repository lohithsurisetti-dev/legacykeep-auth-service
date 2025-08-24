package com.legacykeep.auth.service;

import com.legacykeep.auth.event.dto.UserEmailVerifiedEvent;
import com.legacykeep.auth.event.dto.UserPasswordResetRequestedEvent;
import com.legacykeep.auth.event.dto.UserRegisteredEvent;
import com.legacykeep.auth.event.dto.UserEmailVerificationRequestedEvent;

/**
 * Service for publishing user events to messaging systems (e.g., Kafka).
 * 
 * Handles the publishing of various user-related events to enable
 * event-driven architecture across microservices.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public interface EventPublisherService {

    /**
     * Publish a user registration event.
     * 
     * @param event The user registration event to publish
     */
    void publishUserRegisteredEvent(UserRegisteredEvent event);

    /**
     * Publish a user email verification event.
     * 
     * @param event The user email verification event to publish
     */
    void publishUserEmailVerifiedEvent(UserEmailVerifiedEvent event);

    /**
     * Publish a user email verification requested event.
     * 
     * @param event The user email verification requested event to publish
     */
    void publishUserEmailVerificationRequestedEvent(UserEmailVerificationRequestedEvent event);

    /**
     * Publish a user password reset requested event.
     * 
     * @param event The user password reset requested event to publish
     */
    void publishUserPasswordResetRequestedEvent(UserPasswordResetRequestedEvent event);

    /**
     * Publish a generic user event.
     * 
     * @param topic The topic to publish to
     * @param event The event object to publish
     */
    void publishEvent(String topic, Object event);
}
