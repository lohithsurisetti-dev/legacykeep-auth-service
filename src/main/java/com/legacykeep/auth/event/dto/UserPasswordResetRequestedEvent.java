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
 * Event DTO for user password reset request events.
 * This event is published when a user requests a password reset.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPasswordResetRequestedEvent {
    
    /**
     * Unique identifier for the event
     */
    private String eventId;
    
    /**
     * User ID of the user who requested password reset
     */
    private String userId;
    
    /**
     * Email address for password reset
     */
    private String email;
    
    /**
     * Password reset token
     */
    private String resetToken;
    
    /**
     * Timestamp when the reset token expires
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private Instant resetTokenExpiresAt;
    
    /**
     * IP address from which the reset was requested
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
    private String eventType = "USER_PASSWORD_RESET_REQUESTED";
    
    /**
     * Create a UserPasswordResetRequestedEvent.
     * 
     * @param userId User ID
     * @param email Email address
     * @param resetToken Reset token
     * @param resetTokenExpiresAt Token expiration
     * @param ipAddress IP address
     * @param deviceInfo Device information
     * @return UserPasswordResetRequestedEvent instance
     */
    public static UserPasswordResetRequestedEvent create(String userId, String email, String resetToken,
                                                        Instant resetTokenExpiresAt, String ipAddress, String deviceInfo) {
        return UserPasswordResetRequestedEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .userId(userId)
                .email(email)
                .resetToken(resetToken)
                .resetTokenExpiresAt(resetTokenExpiresAt)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .build();
    }
}
