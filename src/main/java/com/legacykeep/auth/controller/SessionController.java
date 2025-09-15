package com.legacykeep.auth.controller;

import com.legacykeep.auth.dto.ApiResponse;
import com.legacykeep.auth.entity.AuditLog;
import com.legacykeep.auth.entity.AuditSeverity;
import com.legacykeep.auth.entity.UserSession;
import com.legacykeep.auth.repository.AuditLogRepository;
import com.legacykeep.auth.repository.UserSessionRepository;
import com.legacykeep.auth.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Session Management Controller for user session operations.
 * 
 * Provides endpoints for managing user sessions including:
 * - Getting user sessions
 * - Terminating specific sessions
 * - Terminating all sessions
 * - Session statistics
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/sessions")
@RequiredArgsConstructor
@Tag(name = "Session Management", description = "APIs for managing user sessions")
@SecurityRequirement(name = "bearerAuth")
public class SessionController {

    private final UserSessionRepository userSessionRepository;
    private final JwtService jwtService;
    private final AuditLogRepository auditLogRepository;

    /**
     * Get all active sessions for the current user.
     */
    @Operation(
        summary = "Get User Sessions",
        description = "Retrieve all active sessions for the current authenticated user"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Sessions retrieved successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @GetMapping
    public ResponseEntity<?> getUserSessions(HttpServletRequest request) {
        try {
            // Extract user ID from JWT token
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid authorization header", "Missing or invalid token", 401));
            }

            String token = authHeader.substring(7);
            Optional<Long> userIdOpt = jwtService.extractUserId(token);
            
            if (userIdOpt.isEmpty()) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid token", "Token is invalid or expired", 401));
            }

            Long userId = userIdOpt.get();
            log.info("Retrieving sessions for user: {}", userId);

            // Get all sessions for the user
            List<UserSession> sessions = userSessionRepository.findByUserIdOrderByCreatedAtDesc(userId);
            
            // Filter out sensitive information for response
            List<Map<String, Object>> sessionData = sessions.stream()
                    .map(this::mapSessionToResponse)
                    .toList();

            return ResponseEntity.ok(ApiResponse.success(sessionData, "Sessions retrieved successfully"));

        } catch (Exception e) {
            log.error("Error retrieving user sessions: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to retrieve sessions", e.getMessage(), 500));
        }
    }

    /**
     * Get session by ID.
     */
    @Operation(
        summary = "Get Session by ID",
        description = "Retrieve a specific session by its ID"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Session retrieved successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Session not found"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @GetMapping("/{sessionId}")
    public ResponseEntity<?> getSessionById(
            @Parameter(description = "Session ID", required = true)
            @PathVariable Long sessionId,
            HttpServletRequest request) {
        try {
            // Extract user ID from JWT token
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid authorization header", "Missing or invalid token", 401));
            }

            String token = authHeader.substring(7);
            Optional<Long> userIdOpt = jwtService.extractUserId(token);
            
            if (userIdOpt.isEmpty()) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid token", "Token is invalid or expired", 401));
            }

            Long userId = userIdOpt.get();
            log.info("Retrieving session {} for user: {}", sessionId, userId);

            // Get session by ID
            Optional<UserSession> sessionOpt = userSessionRepository.findById(sessionId);
            
            if (sessionOpt.isEmpty()) {
                return ResponseEntity.status(404)
                        .body(ApiResponse.error("Session not found", "Session with ID " + sessionId + " not found", 404));
            }

            UserSession session = sessionOpt.get();
            
            // Verify the session belongs to the current user
            if (!session.getUserId().equals(userId)) {
                return ResponseEntity.status(403)
                        .body(ApiResponse.error("Access denied", "You can only access your own sessions", 403));
            }

            Map<String, Object> sessionData = mapSessionToResponse(session);
            return ResponseEntity.ok(ApiResponse.success(sessionData, "Session retrieved successfully"));

        } catch (Exception e) {
            log.error("Error retrieving session {}: {}", sessionId, e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to retrieve session", e.getMessage(), 500));
        }
    }

    /**
     * Terminate a specific session.
     */
    @Operation(
        summary = "Terminate Session",
        description = "Terminate a specific session by its ID"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Session terminated successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Session not found"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @DeleteMapping("/{sessionId}")
    public ResponseEntity<?> terminateSession(
            @Parameter(description = "Session ID", required = true)
            @PathVariable Long sessionId,
            HttpServletRequest request) {
        try {
            // Extract user ID from JWT token
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid authorization header", "Missing or invalid token", 401));
            }

            String token = authHeader.substring(7);
            Optional<Long> userIdOpt = jwtService.extractUserId(token);
            
            if (userIdOpt.isEmpty()) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid token", "Token is invalid or expired", 401));
            }

            Long userId = userIdOpt.get();
            String ipAddress = getClientIpAddress(request);
            
            log.info("Terminating session {} for user: {}", sessionId, userId);

            // Get session by ID
            Optional<UserSession> sessionOpt = userSessionRepository.findById(sessionId);
            
            if (sessionOpt.isEmpty()) {
                return ResponseEntity.status(404)
                        .body(ApiResponse.error("Session not found", "Session with ID " + sessionId + " not found", 404));
            }

            UserSession session = sessionOpt.get();
            
            // Verify the session belongs to the current user
            if (!session.getUserId().equals(userId)) {
                return ResponseEntity.status(403)
                        .body(ApiResponse.error("Access denied", "You can only terminate your own sessions", 403));
            }

            // Terminate the session
            session.revoke("User terminated session", userId);
            userSessionRepository.save(session);

            // Log audit event
            logAuditEvent(
                    userId,
                    sessionId,
                    "SESSION_TERMINATED",
                    "SESSION_MANAGEMENT",
                    AuditSeverity.LOW,
                    "User terminated session: " + sessionId,
                    ipAddress,
                    "User terminated session via API",
                    true
            );

            log.info("Session {} terminated successfully for user: {}", sessionId, userId);
            return ResponseEntity.ok(ApiResponse.success(null, "Session terminated successfully"));

        } catch (Exception e) {
            log.error("Error terminating session {}: {}", sessionId, e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to terminate session", e.getMessage(), 500));
        }
    }

    /**
     * Terminate all sessions for the current user.
     */
    @Operation(
        summary = "Terminate All Sessions",
        description = "Terminate all sessions for the current authenticated user"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "All sessions terminated successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @DeleteMapping("/all")
    public ResponseEntity<?> terminateAllSessions(HttpServletRequest request) {
        try {
            // Extract user ID from JWT token
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid authorization header", "Missing or invalid token", 401));
            }

            String token = authHeader.substring(7);
            Optional<Long> userIdOpt = jwtService.extractUserId(token);
            
            if (userIdOpt.isEmpty()) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid token", "Token is invalid or expired", 401));
            }

            Long userId = userIdOpt.get();
            String ipAddress = getClientIpAddress(request);
            
            log.info("Terminating all sessions for user: {}", userId);

            // Get all active sessions for the user
            List<UserSession> activeSessions = userSessionRepository.findActiveSessionsByUserId(userId);
            
            // Terminate all sessions
            int terminatedCount = 0;
            for (UserSession session : activeSessions) {
                session.revoke("User terminated all sessions", userId);
                userSessionRepository.save(session);
                terminatedCount++;
            }

            // Log audit event
            logAuditEvent(
                    userId,
                    null,
                    "ALL_SESSIONS_TERMINATED",
                    "SESSION_MANAGEMENT",
                    AuditSeverity.LOW,
                    "User terminated all sessions. Count: " + terminatedCount,
                    ipAddress,
                    "User terminated all sessions via API",
                    true
            );

            log.info("All sessions terminated successfully for user: {}. Count: {}", userId, terminatedCount);
            return ResponseEntity.ok(ApiResponse.success(
                    Map.of("terminatedCount", terminatedCount), 
                    "All sessions terminated successfully"
            ));

        } catch (Exception e) {
            log.error("Error terminating all sessions: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to terminate all sessions", e.getMessage(), 500));
        }
    }

    /**
     * Get session statistics for the current user.
     */
    @Operation(
        summary = "Get Session Statistics",
        description = "Get session statistics for the current authenticated user"
    )
    @ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Session statistics retrieved successfully"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @GetMapping("/stats")
    public ResponseEntity<?> getSessionStats(HttpServletRequest request) {
        try {
            // Extract user ID from JWT token
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid authorization header", "Missing or invalid token", 401));
            }

            String token = authHeader.substring(7);
            Optional<Long> userIdOpt = jwtService.extractUserId(token);
            
            if (userIdOpt.isEmpty()) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.error("Invalid token", "Token is invalid or expired", 401));
            }

            Long userId = userIdOpt.get();
            log.info("Retrieving session statistics for user: {}", userId);

            // Get session statistics
            List<UserSession> allSessions = userSessionRepository.findByUserIdOrderByCreatedAtDesc(userId);
            List<UserSession> activeSessions = userSessionRepository.findActiveSessionsByUserId(userId);
            
            long totalSessions = allSessions.size();
            long activeCount = activeSessions.size();
            long expiredCount = allSessions.stream().mapToLong(s -> s.isExpired() ? 1 : 0).sum();
            long revokedCount = allSessions.stream().mapToLong(s -> s.isRevoked() ? 1 : 0).sum();

            Map<String, Object> stats = Map.of(
                    "totalSessions", totalSessions,
                    "activeSessions", activeCount,
                    "expiredSessions", expiredCount,
                    "revokedSessions", revokedCount,
                    "currentSessionId", extractCurrentSessionId(token)
            );

            return ResponseEntity.ok(ApiResponse.success(stats, "Session statistics retrieved successfully"));

        } catch (Exception e) {
            log.error("Error retrieving session statistics: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                    .body(ApiResponse.error("Failed to retrieve session statistics", e.getMessage(), 500));
        }
    }

    // =============================================================================
    // Private Helper Methods
    // =============================================================================

    /**
     * Map UserSession entity to response DTO.
     */
    private Map<String, Object> mapSessionToResponse(UserSession session) {
        Map<String, Object> response = new HashMap<>();
        response.put("id", session.getId());
        response.put("sessionType", session.getSessionType());
        response.put("loginMethod", session.getLoginMethod());
        response.put("securityLevel", session.getSecurityLevel());
        response.put("deviceInfo", session.getDeviceInfo());
        response.put("ipAddress", session.getIpAddress());
        response.put("loginLocation", session.getLoginLocation());
        response.put("isActive", session.isActive());
        response.put("isValid", session.isValid());
        response.put("isExpired", session.isExpired());
        response.put("isRevoked", session.isRevoked());
        response.put("createdAt", session.getCreatedAt());
        response.put("expiresAt", session.getExpiresAt());
        response.put("lastUsedAt", session.getLastUsedAt());
        response.put("sessionDurationMinutes", session.getSessionDurationMinutes());
        response.put("remainingTimeMinutes", session.getRemainingTimeMinutes());
        return response;
    }

    /**
     * Extract current session ID from JWT token.
     */
    private Long extractCurrentSessionId(String token) {
        try {
            Optional<String> sessionIdOpt = jwtService.extractSessionId(token);
            return sessionIdOpt.map(Long::valueOf).orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Log audit event to the database.
     */
    private void logAuditEvent(Long userId, Long sessionId, String eventType, String eventCategory,
                              AuditSeverity severity, String description, String ipAddress, String deviceInfo, boolean isSuccessful) {
        try {
            AuditLog auditLog = new AuditLog();
            auditLog.setUserId(userId);
            auditLog.setSessionId(sessionId);
            auditLog.setEventType(eventType);
            auditLog.setEventCategory(eventCategory);
            auditLog.setSeverity(severity);
            auditLog.setDescription(description);
            auditLog.setIpAddress(ipAddress);
            auditLog.setDeviceInfo(deviceInfo);
            auditLog.setSuccessful(isSuccessful);
            auditLog.setCreatedAt(LocalDateTime.now());

            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to log audit event: {}", e.getMessage(), e);
        }
    }
}
