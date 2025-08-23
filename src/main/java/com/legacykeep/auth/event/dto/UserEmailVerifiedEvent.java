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
 * Event published when a user's email is verified.
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
public class UserEmailVerifiedEvent extends BaseEvent {

    /**
     * User's email address
     */
    private String email;

    /**
     * Timestamp when the email was verified
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private Instant verifiedAt;

    /**
     * IP address from where verification was performed
     */
    private String verificationIpAddress;

    /**
     * User agent from where verification was performed
     */
    private String verificationUserAgent;

    /**
     * Create a new UserEmailVerifiedEvent with initialized base fields
     */
    public static UserEmailVerifiedEvent create(String userId, String email, Instant verifiedAt,
                                              String verificationIpAddress, String verificationUserAgent) {
        UserEmailVerifiedEvent event = UserEmailVerifiedEvent.builder()
                .email(email)
                .verifiedAt(verifiedAt)
                .verificationIpAddress(verificationIpAddress)
                .verificationUserAgent(verificationUserAgent)
                .build();

        event.initializeEvent("user.email-verified.v1", userId);
        return event;
    }
}
