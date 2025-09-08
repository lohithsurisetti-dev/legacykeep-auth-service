package com.legacykeep.auth.event.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Event DTO for user registration events.
 * This event is published when a new user registers in the system.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegisteredEvent {
    
    /**
     * Unique identifier for the event
     */
    private String eventId;
    
    /**
     * User ID of the registered user
     */
    private Long userId;
    
    /**
     * Email address of the registered user
     */
    private String email;
    
    /**
     * Username of the registered user
     */
    private String username;
    
    /**
     * First name of the registered user
     */
    private String firstName;
    
    /**
     * Last name of the registered user
     */
    private String lastName;
    
    /**
     * Full name of the registered user
     */
    private String fullName;
    
    /**
     * Timestamp when the user was registered
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime registeredAt;
    
    /**
     * Source service that published this event
     */
    private String sourceService;
    
    /**
     * Event type identifier
     */
    @Builder.Default
    private String eventType = "USER_REGISTERED";
    
    /**
     * Create a UserRegisteredEvent with default values.
     * 
     * @param userId User ID
     * @param email User email
     * @param username User username
     * @param firstName User first name
     * @param lastName User last name
     * @return UserRegisteredEvent instance
     */
    public static UserRegisteredEvent create(Long userId, String email, String username, 
                                           String firstName, String lastName) {
        String fullName = (firstName != null && lastName != null) ? 
            firstName + " " + lastName : 
            (firstName != null ? firstName : (lastName != null ? lastName : username));
            
        return UserRegisteredEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .userId(userId)
                .email(email)
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .fullName(fullName)
                .registeredAt(LocalDateTime.now())
                .sourceService("auth-service")
                .eventType("USER_REGISTERED")
                .build();
    }
}

