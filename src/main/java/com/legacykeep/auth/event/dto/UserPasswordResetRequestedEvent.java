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
 * Event published when a user requests a password reset.
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
public class UserPasswordResetRequestedEvent extends BaseEvent {

    /**
     * User's email address
     */
    private String email;

    /**
     * Password reset token
     */
    private String resetToken;

    /**
     * Password reset token expiry time
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private Instant resetExpiry;

    /**
     * IP address from where reset was requested
     */
    private String requestIpAddress;

    /**
     * User agent from where reset was requested
     */
    private String requestUserAgent;

    /**
     * Create a new UserPasswordResetRequestedEvent with initialized base fields
     */
    public static UserPasswordResetRequestedEvent create(String userId, String email, String resetToken,
                                                       Instant resetExpiry, String requestIpAddress, 
                                                       String requestUserAgent) {
        UserPasswordResetRequestedEvent event = UserPasswordResetRequestedEvent.builder()
                .email(email)
                .resetToken(resetToken)
                .resetExpiry(resetExpiry)
                .requestIpAddress(requestIpAddress)
                .requestUserAgent(requestUserAgent)
                .build();

        event.initializeEvent("user.password-reset-requested.v1", userId);
        return event;
    }
}
