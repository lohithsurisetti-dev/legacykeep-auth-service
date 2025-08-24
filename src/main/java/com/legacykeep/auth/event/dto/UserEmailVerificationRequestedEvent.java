package com.legacykeep.auth.event.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Event DTO for user email verification request events.
 * This event is published when a user needs to verify their email address.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEmailVerificationRequestedEvent {
    
    /**
     * Unique identifier for the event
     */
    private String eventId;
    
    /**
     * User ID of the user requesting verification
     */
    private Long userId;
    
    /**
     * Email address of the user
     */
    private String email;
    
    /**
     * Username of the user
     */
    private String username;
    
    /**
     * First name of the user
     */
    private String firstName;
    
    /**
     * Last name of the user
     */
    private String lastName;
    
    /**
     * Full name of the user
     */
    private String fullName;
    
    /**
     * Email verification token
     */
    private String verificationToken;
    
    /**
     * Timestamp when the verification was requested
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime requestedAt;
    
    /**
     * Timestamp when the verification token expires
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime expiresAt;
    
    /**
     * Source service that published this event
     */
    private String sourceService;
    
    /**
     * Event type identifier
     */
    @Builder.Default
    private String eventType = "USER_EMAIL_VERIFICATION_REQUESTED";
    
    /**
     * Create a UserEmailVerificationRequestedEvent with default values.
     * 
     * @param userId User ID
     * @param email User email
     * @param username User username
     * @param firstName User first name
     * @param lastName User last name
     * @param verificationToken Email verification token
     * @param expiresAt Token expiration time
     * @return UserEmailVerificationRequestedEvent instance
     */
    public static UserEmailVerificationRequestedEvent create(Long userId, String email, String username, 
                                                           String firstName, String lastName, 
                                                           String verificationToken, LocalDateTime expiresAt) {
        String fullName = (firstName != null && lastName != null) ? 
            firstName + " " + lastName : 
            (firstName != null ? firstName : (lastName != null ? lastName : username));
            
        return UserEmailVerificationRequestedEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .userId(userId)
                .email(email)
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .fullName(fullName)
                .verificationToken(verificationToken)
                .requestedAt(LocalDateTime.now())
                .expiresAt(expiresAt)
                .sourceService("auth-service")
                .eventType("USER_EMAIL_VERIFICATION_REQUESTED")
                .build();
    }
}
