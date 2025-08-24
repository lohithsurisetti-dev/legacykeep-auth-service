package com.legacykeep.auth.service.impl;

import com.legacykeep.auth.event.dto.UserEmailVerifiedEvent;
import com.legacykeep.auth.event.dto.UserPasswordResetRequestedEvent;
import com.legacykeep.auth.event.dto.UserRegisteredEvent;
import com.legacykeep.auth.event.dto.UserEmailVerificationRequestedEvent;
import com.legacykeep.auth.service.EventPublisherService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * Implementation of EventPublisherService using Kafka.
 * 
 * Publishes user events to Kafka topics for consumption by other microservices.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EventPublisherServiceImpl implements EventPublisherService {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${kafka.topics.user-registered:user.registered}")
    private String userRegisteredTopic;

    @Value("${kafka.topics.user-email-verified:user.email.verified}")
    private String userEmailVerifiedTopic;

    @Value("${kafka.topics.user-email-verification-requested:user.email.verification.requested}")
    private String userEmailVerificationRequestedTopic;

    @Value("${kafka.topics.user-password-reset-requested:user.password.reset.requested}")
    private String userPasswordResetRequestedTopic;

    @Override
    public void publishUserRegisteredEvent(UserRegisteredEvent event) {
        try {
            log.info("Publishing user registration event: userId={}, eventId={}", 
                    event.getUserId(), event.getEventId());
            
            kafkaTemplate.send(userRegisteredTopic, event.getUserId().toString(), event)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish user registration event: userId={}, error={}", 
                                    event.getUserId(), ex.getMessage(), ex);
                        } else {
                            log.debug("Successfully published user registration event: userId={}, offset={}", 
                                    event.getUserId(), result.getRecordMetadata().offset());
                        }
                    });
        } catch (Exception e) {
            log.error("Error publishing user registration event: userId={}, error={}", 
                    event.getUserId(), e.getMessage(), e);
            throw new RuntimeException("Failed to publish user registration event", e);
        }
    }

    @Override
    public void publishUserEmailVerifiedEvent(UserEmailVerifiedEvent event) {
        try {
            log.info("Publishing user email verification event: userId={}, eventId={}", 
                    event.getUserId(), event.getEventId());
            
            kafkaTemplate.send(userEmailVerifiedTopic, event.getUserId(), event)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish user email verification event: userId={}, error={}", 
                                    event.getUserId(), ex.getMessage(), ex);
                        } else {
                            log.debug("Successfully published user email verification event: userId={}, offset={}", 
                                    event.getUserId(), result.getRecordMetadata().offset());
                        }
                    });
        } catch (Exception e) {
            log.error("Error publishing user email verification event: userId={}, error={}", 
                    event.getUserId(), e.getMessage(), e);
            throw new RuntimeException("Failed to publish user email verification event", e);
        }
    }

    @Override
    public void publishUserEmailVerificationRequestedEvent(UserEmailVerificationRequestedEvent event) {
        try {
            log.info("Publishing user email verification requested event: userId={}, eventId={}", 
                    event.getUserId(), event.getEventId());
            
            kafkaTemplate.send(userEmailVerificationRequestedTopic, event.getUserId().toString(), event)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish user email verification requested event: userId={}, error={}", 
                                    event.getUserId(), ex.getMessage(), ex);
                        } else {
                            log.debug("Successfully published user email verification requested event: userId={}, offset={}", 
                                    event.getUserId(), result.getRecordMetadata().offset());
                        }
                    });
        } catch (Exception e) {
            log.error("Error publishing user email verification requested event: userId={}, error={}", 
                    event.getUserId(), e.getMessage(), e);
            throw new RuntimeException("Failed to publish user email verification requested event", e);
        }
    }

    @Override
    public void publishUserPasswordResetRequestedEvent(UserPasswordResetRequestedEvent event) {
        try {
            log.info("Publishing user password reset requested event: userId={}, eventId={}", 
                    event.getUserId(), event.getEventId());
            
            kafkaTemplate.send(userPasswordResetRequestedTopic, event.getUserId(), event)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish user password reset requested event: userId={}, error={}", 
                                    event.getUserId(), ex.getMessage(), ex);
                        } else {
                            log.debug("Successfully published user password reset requested event: userId={}, offset={}", 
                                    event.getUserId(), result.getRecordMetadata().offset());
                        }
                    });
        } catch (Exception e) {
            log.error("Error publishing user password reset requested event: userId={}, error={}", 
                    event.getUserId(), e.getMessage(), e);
            throw new RuntimeException("Failed to publish user password reset requested event", e);
        }
    }

    @Override
    public void publishEvent(String topic, Object event) {
        try {
            log.info("Publishing generic event to topic: {}", topic);
            
            kafkaTemplate.send(topic, event)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish event to topic {}: error={}", topic, ex.getMessage(), ex);
                        } else {
                            log.debug("Successfully published event to topic {}: offset={}", 
                                    topic, result.getRecordMetadata().offset());
                        }
                    });
        } catch (Exception e) {
            log.error("Error publishing event to topic {}: error={}", topic, e.getMessage(), e);
            throw new RuntimeException("Failed to publish event to topic: " + topic, e);
        }
    }
}
