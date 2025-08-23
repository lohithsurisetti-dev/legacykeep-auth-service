package com.legacykeep.auth.event.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.Instant;

/**
 * Event published when a new user registers in the system.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 * @since 2025-08-23
 */
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserRegisteredEvent extends BaseEvent {

    /**
     * User's email address
     */
    private String email;

    /**
     * User's username
     */
    private String username;

    /**
     * User's first name
     */
    private String firstName;

    /**
     * User's last name
     */
    private String lastName;

    /**
     * Email verification token
     */
    private String verificationToken;

    /**
     * Email verification token expiry time
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private Instant verificationExpiry;

    /**
     * User's preferred language
     */
    private String language;

    /**
     * User's timezone
     */
    private String timezone;

    /**
     * Whether the user opted in for marketing emails
     */
    private Boolean marketingEmailsEnabled;

    /**
     * Create a new UserRegisteredEvent with initialized base fields
     */
    public static UserRegisteredEvent create(String userId, String email, String username, 
                                           String firstName, String lastName, String verificationToken,
                                           Instant verificationExpiry, String language, String timezone,
                                           Boolean marketingEmailsEnabled) {
        UserRegisteredEvent event = UserRegisteredEvent.builder()
                .email(email)
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .verificationToken(verificationToken)
                .verificationExpiry(verificationExpiry)
                .language(language)
                .timezone(timezone)
                .marketingEmailsEnabled(marketingEmailsEnabled)
                .build();

        event.initializeEvent("user.registered.v1", userId);
        return event;
    }
}
