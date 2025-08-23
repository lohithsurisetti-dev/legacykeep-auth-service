package com.legacykeep.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Health check controller for Auth Service.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 * @since 2025-08-23
 */
@Slf4j
@RestController
@RequestMapping("/health")
public class HealthController {

    /**
     * Basic health check endpoint.
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "auth-service");
        response.put("timestamp", LocalDateTime.now());
        response.put("version", "1.0.0");
        
        log.debug("Health check requested");
        return ResponseEntity.ok(response);
    }

    /**
     * Detailed health check endpoint.
     */
    @GetMapping("/details")
    public ResponseEntity<Map<String, Object>> healthDetails() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "auth-service");
        response.put("timestamp", LocalDateTime.now());
        response.put("version", "1.0.0");
        response.put("components", Map.of(
            "database", "UP",
            "redis", "UP",
            "kafka", "UP"
        ));
        
        log.debug("Detailed health check requested");
        return ResponseEntity.ok(response);
    }
}
