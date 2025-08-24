package com.legacykeep.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Health Controller for Auth Service.
 * 
 * Provides health check endpoints for monitoring and load balancers.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@RestController
@RequestMapping("/auth")
public class HealthController {

    /**
     * Health check endpoint.
     * 
     * @return Health status message
     */
    @GetMapping("/health")
    public String health() {
        return "auth-service is running!";
    }
}
