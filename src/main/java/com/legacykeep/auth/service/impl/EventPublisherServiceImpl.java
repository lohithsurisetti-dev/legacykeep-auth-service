package com.legacykeep.auth.service.impl;

import com.legacykeep.auth.event.dto.BaseEvent;
import com.legacykeep.auth.service.EventPublisherService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;

/**
 * Implementation of EventPublisherService for publishing events to Kafka topics.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 * @since 2025-08-23
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EventPublisherServiceImpl implements EventPublisherService {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${kafka.topics.user-events:user.events}")
    private String userEventsTopic;

    @Value("${kafka.topics.auth-events:auth.events}")
    private String authEventsTopic;

    @Override
    public <T extends BaseEvent> void publishEvent(String topic, T event) {
        publishEvent(topic, event.getEventKey(), event);
    }

    @Override
    public <T extends BaseEvent> void publishUserEvent(T event) {
        publishEvent(userEventsTopic, event);
    }

    @Override
    public <T extends BaseEvent> void publishAuthEvent(T event) {
        publishEvent(authEventsTopic, event);
    }

    @Override
    public <T extends BaseEvent> void publishEvent(String topic, String key, T event) {
        try {
            log.info("Publishing event: topic={}, key={}, eventType={}, eventId={}",
                    topic, key, event.getEventType(), event.getEventId());

            CompletableFuture<SendResult<String, Object>> future = kafkaTemplate.send(topic, key, event);

            future.whenComplete((result, throwable) -> {
                if (throwable == null) {
                    log.debug("Event published successfully: topic={}, partition={}, offset={}, key={}",
                            result.getRecordMetadata().topic(),
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset(),
                            key);
                } else {
                    log.error("Failed to publish event: topic={}, key={}, eventType={}, error={}",
                            topic, key, event.getEventType(), throwable.getMessage(), throwable);
                }
            });

        } catch (Exception e) {
            log.error("Error publishing event: topic={}, key={}, eventType={}, error={}",
                    topic, key, event.getEventType(), e.getMessage(), e);
            throw new RuntimeException("Failed to publish event: " + event.getEventType(), e);
        }
    }
}
