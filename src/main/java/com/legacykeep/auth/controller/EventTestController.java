package com.legacykeep.auth.controller;

import com.legacykeep.auth.event.dto.UserRegisteredEvent;
import com.legacykeep.auth.event.dto.UserEmailVerifiedEvent;
import com.legacykeep.auth.event.dto.UserPasswordResetRequestedEvent;
import com.legacykeep.auth.service.EventPublisherService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Test controller for manually triggering Kafka events.
 * This is for development/testing purposes only.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 * @since 2025-08-23
 */
@Slf4j
@RestController
@RequestMapping("/test/events")
@RequiredArgsConstructor
public class EventTestController {

    private final EventPublisherService eventPublisherService;

    /**
     * Test user registration event
     */
    @PostMapping("/user-registered")
    public ResponseEntity<String> testUserRegisteredEvent() {
        try {
            String userId = UUID.randomUUID().toString();
            String email = "test@example.com";
            String username = "testuser";
            
            UserRegisteredEvent event = UserRegisteredEvent.create(
                    userId,
                    email,
                    username,
                    "Test",
                    "User",
                    "verification-token-123",
                    Instant.now().plus(24, ChronoUnit.HOURS),
                    "en",
                    "UTC",
                    true
            );
            
            eventPublisherService.publishUserEvent(event);
            
            log.info("Test user registration event published: eventId={}", event.getEventId());
            return ResponseEntity.ok("User registration event published successfully. Event ID: " + event.getEventId());
            
        } catch (Exception e) {
            log.error("Failed to publish test user registration event: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Failed to publish event: " + e.getMessage());
        }
    }

    /**
     * Test email verification event
     */
    @PostMapping("/email-verified")
    public ResponseEntity<String> testEmailVerifiedEvent() {
        try {
            String userId = UUID.randomUUID().toString();
            String email = "test@example.com";
            
            UserEmailVerifiedEvent event = UserEmailVerifiedEvent.create(
                    userId,
                    email,
                    Instant.now(),
                    "192.168.1.1",
                    "Mozilla/5.0 (Test Browser)"
            );
            
            eventPublisherService.publishUserEvent(event);
            
            log.info("Test email verification event published: eventId={}", event.getEventId());
            return ResponseEntity.ok("Email verification event published successfully. Event ID: " + event.getEventId());
            
        } catch (Exception e) {
            log.error("Failed to publish test email verification event: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Failed to publish event: " + e.getMessage());
        }
    }

    /**
     * Test password reset requested event
     */
    @PostMapping("/password-reset-requested")
    public ResponseEntity<String> testPasswordResetRequestedEvent() {
        try {
            String userId = UUID.randomUUID().toString();
            String email = "test@example.com";
            
            UserPasswordResetRequestedEvent event = UserPasswordResetRequestedEvent.create(
                    userId,
                    email,
                    "reset-token-456",
                    Instant.now().plus(1, ChronoUnit.HOURS),
                    "192.168.1.1",
                    "Mozilla/5.0 (Test Browser)"
            );
            
            eventPublisherService.publishUserEvent(event);
            
            log.info("Test password reset requested event published: eventId={}", event.getEventId());
            return ResponseEntity.ok("Password reset requested event published successfully. Event ID: " + event.getEventId());
            
        } catch (Exception e) {
            log.error("Failed to publish test password reset requested event: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Failed to publish event: " + e.getMessage());
        }
    }

    /**
     * Test all events
     */
    @PostMapping("/all")
    public ResponseEntity<String> testAllEvents() {
        try {
            String userId = UUID.randomUUID().toString();
            String email = "test@example.com";
            String username = "testuser";
            
            // User registration event
            UserRegisteredEvent registrationEvent = UserRegisteredEvent.create(
                    userId,
                    email,
                    username,
                    "Test",
                    "User",
                    "verification-token-123",
                    Instant.now().plus(24, ChronoUnit.HOURS),
                    "en",
                    "UTC",
                    true
            );
            eventPublisherService.publishUserEvent(registrationEvent);
            
            // Email verification event
            UserEmailVerifiedEvent verificationEvent = UserEmailVerifiedEvent.create(
                    userId,
                    email,
                    Instant.now(),
                    "192.168.1.1",
                    "Mozilla/5.0 (Test Browser)"
            );
            eventPublisherService.publishUserEvent(verificationEvent);
            
            // Password reset event
            UserPasswordResetRequestedEvent resetEvent = UserPasswordResetRequestedEvent.create(
                    userId,
                    email,
                    "reset-token-456",
                    Instant.now().plus(1, ChronoUnit.HOURS),
                    "192.168.1.1",
                    "Mozilla/5.0 (Test Browser)"
            );
            eventPublisherService.publishUserEvent(resetEvent);
            
            log.info("All test events published successfully");
            return ResponseEntity.ok("All test events published successfully. User ID: " + userId);
            
        } catch (Exception e) {
            log.error("Failed to publish test events: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Failed to publish events: " + e.getMessage());
        }
    }
}
