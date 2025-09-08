package com.legacykeep.auth.event.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Event DTO for user email verification events.
 * This event is published when a user verifies their email address.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEmailVerifiedEvent {
    
    /**
     * Unique identifier for the event
     */
    private String eventId;
    
    /**
     * User ID of the user who verified their email
     */
    private String userId;
    
    /**
     * Email address that was verified
     */
    private String email;
    
    /**
     * Timestamp when the email was verified
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private Instant verifiedAt;
    
    /**
     * IP address from which the verification occurred
     */
    private String ipAddress;
    
    /**
     * Device information
     */
    private String deviceInfo;
    
    /**
     * Timestamp when the event was created
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    @Builder.Default
    private LocalDateTime eventTimestamp = LocalDateTime.now();
    
    /**
     * Source service that published this event
     */
    @Builder.Default
    private String sourceService = "auth-service";
    
    /**
     * Event type identifier
     */
    @Builder.Default
    private String eventType = "USER_EMAIL_VERIFIED";
    
    /**
     * Create a UserEmailVerifiedEvent.
     * 
     * @param userId User ID
     * @param email Email address
     * @param verifiedAt Verification timestamp
     * @param ipAddress IP address
     * @param deviceInfo Device information
     * @return UserEmailVerifiedEvent instance
     */
    public static UserEmailVerifiedEvent create(String userId, String email, Instant verifiedAt, 
                                               String ipAddress, String deviceInfo) {
        return UserEmailVerifiedEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .userId(userId)
                .email(email)
                .verifiedAt(verifiedAt)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .build();
    }
}

