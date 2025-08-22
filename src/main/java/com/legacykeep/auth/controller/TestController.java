package com.legacykeep.auth.controller;

import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserRole;
import com.legacykeep.auth.entity.UserStatus;
import com.legacykeep.auth.entity.UserSession;
import com.legacykeep.auth.entity.AuditLog;
import com.legacykeep.auth.entity.AuditSeverity;
import com.legacykeep.auth.repository.UserRepository;
import com.legacykeep.auth.repository.UserSessionRepository;
import com.legacykeep.auth.repository.AuditLogRepository;
import com.legacykeep.auth.service.JwtService;
import io.jsonwebtoken.Claims;
import java.util.Optional;
import com.legacykeep.auth.dto.JwtTokenDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Test controller for verifying database connection and entity mapping.
 * 
 * This is a temporary controller for testing purposes only.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/test")
public class TestController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserSessionRepository userSessionRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtService jwtService;

    /**
     * Test database connection and basic operations.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> testHealth() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Test basic repository operations
            long userCount = userRepository.count();
            
            response.put("status", "SUCCESS");
            response.put("message", "Database connection successful");
            response.put("timestamp", LocalDateTime.now());
            response.put("userCount", userCount);
            response.put("database", "PostgreSQL");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Database connection failed: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test creating a test user.
     */
    @PostMapping("/create-test-user")
    public ResponseEntity<Map<String, Object>> createTestUser() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Check if test user already exists
            if (userRepository.existsByEmailIgnoreCase("test@legacykeep.com")) {
                response.put("status", "EXISTS");
                response.put("message", "Test user already exists");
                response.put("timestamp", LocalDateTime.now());
                return ResponseEntity.ok(response);
            }

            // Create a test user
            User testUser = new User();
            testUser.setEmail("test@legacykeep.com");
            testUser.setUsername("testuser");
            testUser.setPasswordHash("$2a$10$test.hash.for.testing.purposes.only");
            testUser.setStatus(UserStatus.ACTIVE);
            testUser.setEmailVerified(true);
            
            User savedUser = userRepository.save(testUser);
            
            response.put("status", "SUCCESS");
            response.put("message", "Test user created successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("userId", savedUser.getId());
            response.put("email", savedUser.getEmail());
            response.put("status", savedUser.getStatus());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to create test user: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test retrieving all users.
     */
    @GetMapping("/users")
    public ResponseEntity<Map<String, Object>> getAllUsers() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            var users = userRepository.findAll();
            
            response.put("status", "SUCCESS");
            response.put("message", "Users retrieved successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("userCount", users.size());
            response.put("users", users.stream()
                .map(user -> {
                    Map<String, Object> userMap = new HashMap<>();
                    userMap.put("id", user.getId());
                    userMap.put("email", user.getEmail());
                    userMap.put("username", user.getUsername());
                    userMap.put("status", user.getStatus());
                    userMap.put("emailVerified", user.isEmailVerified());
                    userMap.put("createdAt", user.getCreatedAt());
                    return userMap;
                })
                .toList());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to retrieve users: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test database schema information.
     */
    @GetMapping("/schema")
    public ResponseEntity<Map<String, Object>> getSchemaInfo() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Test various repository methods
            long totalUsers = userRepository.count();
            long activeUsers = userRepository.countActiveUsers();
            long pendingUsers = userRepository.countByStatus(UserStatus.PENDING_VERIFICATION);
            
            response.put("status", "SUCCESS");
            response.put("message", "Schema information retrieved successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("totalUsers", totalUsers);
            response.put("activeUsers", activeUsers);
            response.put("pendingVerificationUsers", pendingUsers);
            response.put("database", "PostgreSQL");
            response.put("schema", "auth_db");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to retrieve schema info: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test creating a user session.
     */
    @PostMapping("/create-test-session")
    public ResponseEntity<Map<String, Object>> createTestSession() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // First, ensure we have a test user
            User testUser = userRepository.findByEmailIgnoreCase("test@legacykeep.com")
                .orElseGet(() -> {
                    User user = new User();
                    user.setEmail("test@legacykeep.com");
                    user.setUsername("testuser");
                    user.setPasswordHash("$2a$10$test.hash.for.testing.purposes.only");
                    user.setStatus(UserStatus.ACTIVE);
                    user.setEmailVerified(true);
                    return userRepository.save(user);
                });

            // Create a test session
            UserSession testSession = new UserSession();
            testSession.setUserId(testUser.getId());
            testSession.setSessionToken("test-session-token-" + System.currentTimeMillis());
            testSession.setRefreshToken("test-refresh-token-" + System.currentTimeMillis());
            testSession.setExpiresAt(LocalDateTime.now().plusHours(1));
            testSession.setDeviceInfo("Test Device - MacBook Pro");
            testSession.setIpAddress("127.0.0.1");
            testSession.setUserAgent("Mozilla/5.0 (Test Browser)");
            testSession.setLoginMethod("PASSWORD");
            testSession.setSessionType("WEB");
            testSession.setSecurityLevel("MEDIUM");
            testSession.setLoginLocation("San Francisco, CA");
            
            UserSession savedSession = userSessionRepository.save(testSession);
            
            response.put("status", "SUCCESS");
            response.put("message", "Test session created successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("sessionId", savedSession.getId());
            response.put("userId", savedSession.getUserId());
            response.put("sessionType", savedSession.getSessionType());
            response.put("loginMethod", savedSession.getLoginMethod());
            response.put("expiresAt", savedSession.getExpiresAt());
            response.put("isValid", savedSession.isValid());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to create test session: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test retrieving all sessions.
     */
    @GetMapping("/sessions")
    public ResponseEntity<Map<String, Object>> getAllSessions() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            var sessions = userSessionRepository.findAll();
            
            response.put("status", "SUCCESS");
            response.put("message", "Sessions retrieved successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("sessionCount", sessions.size());
            response.put("sessions", sessions.stream()
                .map(session -> {
                    Map<String, Object> sessionMap = new HashMap<>();
                    sessionMap.put("id", session.getId());
                    sessionMap.put("userId", session.getUserId());
                    sessionMap.put("sessionType", session.getSessionType());
                    sessionMap.put("loginMethod", session.getLoginMethod());
                    sessionMap.put("securityLevel", session.getSecurityLevel());
                    sessionMap.put("isActive", session.isActive());
                    sessionMap.put("isValid", session.isValid());
                    sessionMap.put("isExpired", session.isExpired());
                    sessionMap.put("createdAt", session.getCreatedAt());
                    sessionMap.put("expiresAt", session.getExpiresAt());
                    sessionMap.put("lastUsedAt", session.getLastUsedAt());
                    return sessionMap;
                })
                .toList());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to retrieve sessions: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test session statistics and repository methods.
     */
    @GetMapping("/session-stats")
    public ResponseEntity<Map<String, Object>> getSessionStats() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Get various session statistics
            long totalSessions = userSessionRepository.count();
            long activeSessions = userSessionRepository.countActiveSessions();
            long webSessions = userSessionRepository.countActiveSessionsByType("WEB");
            long passwordLogins = userSessionRepository.countActiveSessionsByLoginMethod("PASSWORD");
            
            // Get sessions by user (if any exist)
            var sessions = userSessionRepository.findAll();
            Long testUserId = sessions.isEmpty() ? null : sessions.get(0).getUserId();
            long userActiveSessions = testUserId != null ? 
                userSessionRepository.countActiveSessionsByUserId(testUserId) : 0;
            
            response.put("status", "SUCCESS");
            response.put("message", "Session statistics retrieved successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("totalSessions", totalSessions);
            response.put("activeSessions", activeSessions);
            response.put("webSessions", webSessions);
            response.put("passwordLogins", passwordLogins);
            response.put("userActiveSessions", userActiveSessions);
            response.put("testUserId", testUserId);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to retrieve session stats: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test session validation and business logic.
     */
    @GetMapping("/session-validation")
    public ResponseEntity<Map<String, Object>> testSessionValidation() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            var sessions = userSessionRepository.findAll();
            
            if (sessions.isEmpty()) {
                response.put("status", "NO_SESSIONS");
                response.put("message", "No sessions found for validation testing");
                response.put("timestamp", LocalDateTime.now());
                return ResponseEntity.ok(response);
            }
            
            UserSession testSession = sessions.get(0);
            
            response.put("status", "SUCCESS");
            response.put("message", "Session validation test completed");
            response.put("timestamp", LocalDateTime.now());
            response.put("sessionId", testSession.getId());
            response.put("isValid", testSession.isValid());
            response.put("isExpired", testSession.isExpired());
            response.put("isActive", testSession.isActive());
            response.put("isRevoked", testSession.isRevoked());
            response.put("sessionDurationMinutes", testSession.getSessionDurationMinutes());
            response.put("remainingTimeMinutes", testSession.getRemainingTimeMinutes());
            response.put("createdAt", testSession.getCreatedAt());
            response.put("expiresAt", testSession.getExpiresAt());
            response.put("lastUsedAt", testSession.getLastUsedAt());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to test session validation: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test creating an audit log entry.
     */
    @GetMapping("/create-test-audit-log")
    public ResponseEntity<Map<String, Object>> createTestAuditLog() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Create a test audit log entry
            AuditLog testAuditLog = new AuditLog();
            testAuditLog.setUserId(1L); // Test user ID
            testAuditLog.setEventType("LOGIN_ATTEMPT");
            testAuditLog.setEventCategory("AUTHENTICATION");
            testAuditLog.setSeverity(AuditSeverity.MEDIUM);
            testAuditLog.setDescription("Test login attempt from test endpoint");
            testAuditLog.setIpAddress("127.0.0.1");
            testAuditLog.setUserAgent("Test User Agent - Audit Log Test");
            testAuditLog.setRequestMethod("GET");
            testAuditLog.setRequestUrl("/api/v1/test/create-test-audit-log");
            testAuditLog.setResponseStatus(200);
            testAuditLog.setResponseTimeMs(150L);
            testAuditLog.setLocation("San Francisco, CA");
            testAuditLog.setDeviceInfo("Test Device - MacBook Pro");
            testAuditLog.setBrowserInfo("Chrome 120.0");
            testAuditLog.setOsInfo("macOS 14.0");
            testAuditLog.setSuccessful(true);
            
            AuditLog savedAuditLog = auditLogRepository.save(testAuditLog);
            
            response.put("status", "SUCCESS");
            response.put("message", "Test audit log created successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("auditLogId", savedAuditLog.getId());
            response.put("eventType", savedAuditLog.getEventType());
            response.put("eventCategory", savedAuditLog.getEventCategory());
            response.put("severity", savedAuditLog.getSeverity());
            response.put("isSuccessful", savedAuditLog.isSuccessful());
            response.put("createdAt", savedAuditLog.getCreatedAt());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to create test audit log: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test retrieving all audit logs.
     */
    @GetMapping("/audit-logs")
    public ResponseEntity<Map<String, Object>> getAllAuditLogs() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            var auditLogs = auditLogRepository.findAll();
            
            response.put("status", "SUCCESS");
            response.put("message", "Audit logs retrieved successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("auditLogCount", auditLogs.size());
            response.put("auditLogs", auditLogs.stream()
                .map(auditLog -> {
                    Map<String, Object> auditLogMap = new HashMap<>();
                    auditLogMap.put("id", auditLog.getId());
                    auditLogMap.put("userId", auditLog.getUserId());
                    auditLogMap.put("eventType", auditLog.getEventType());
                    auditLogMap.put("eventCategory", auditLog.getEventCategory());
                    auditLogMap.put("severity", auditLog.getSeverity());
                    auditLogMap.put("description", auditLog.getDescription());
                    auditLogMap.put("isSuccessful", auditLog.isSuccessful());
                    auditLogMap.put("ipAddress", auditLog.getIpAddress());
                    auditLogMap.put("createdAt", auditLog.getCreatedAt());
                    auditLogMap.put("isSecurityEvent", auditLog.isSecurityEvent());
                    auditLogMap.put("isAuthenticationEvent", auditLog.isAuthenticationEvent());
                    auditLogMap.put("ageInDays", auditLog.getAgeInDays());
                    return auditLogMap;
                })
                .toList());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to retrieve audit logs: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test audit log statistics and repository methods.
     */
    @GetMapping("/audit-log-stats")
    public ResponseEntity<Map<String, Object>> getAuditLogStats() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Get various audit log statistics
            long totalAuditLogs = auditLogRepository.count();
            long authenticationLogs = auditLogRepository.countByEventCategory("AUTHENTICATION");
            long securityLogs = auditLogRepository.countSecurityAuditLogs();
            long failedOperations = auditLogRepository.countFailedOperations();
            long mediumSeverityLogs = auditLogRepository.countBySeverity(AuditSeverity.MEDIUM);
            
            // Get logs from last 7 days
            LocalDateTime sevenDaysAgo = LocalDateTime.now().minusDays(7);
            long recentLogs = auditLogRepository.countAuditLogsCreatedBetween(sevenDaysAgo, LocalDateTime.now());
            
            response.put("status", "SUCCESS");
            response.put("message", "Audit log statistics retrieved successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("totalAuditLogs", totalAuditLogs);
            response.put("authenticationLogs", authenticationLogs);
            response.put("securityLogs", securityLogs);
            response.put("failedOperations", failedOperations);
            response.put("mediumSeverityLogs", mediumSeverityLogs);
            response.put("recentLogsLast7Days", recentLogs);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to retrieve audit log stats: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test audit log validation and business logic.
     */
    @GetMapping("/audit-log-validation")
    public ResponseEntity<Map<String, Object>> testAuditLogValidation() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            var auditLogs = auditLogRepository.findAll();
            
            if (auditLogs.isEmpty()) {
                response.put("status", "NO_AUDIT_LOGS");
                response.put("message", "No audit logs found for validation testing");
                response.put("timestamp", LocalDateTime.now());
                return ResponseEntity.ok(response);
            }
            
            AuditLog testAuditLog = auditLogs.get(0);
            
            response.put("status", "SUCCESS");
            response.put("message", "Audit log validation test completed");
            response.put("timestamp", LocalDateTime.now());
            response.put("auditLogId", testAuditLog.getId());
            response.put("eventType", testAuditLog.getEventType());
            response.put("eventCategory", testAuditLog.getEventCategory());
            response.put("severity", testAuditLog.getSeverity());
            response.put("isSuccessful", testAuditLog.isSuccessful());
            response.put("isSecurityEvent", testAuditLog.isSecurityEvent());
            response.put("isAuthenticationEvent", testAuditLog.isAuthenticationEvent());
            response.put("isAuthorizationEvent", testAuditLog.isAuthorizationEvent());
            response.put("isUserManagementEvent", testAuditLog.isUserManagementEvent());
            response.put("shouldBeRetained", testAuditLog.shouldBeRetained());
            response.put("isExpired", testAuditLog.isExpired());
            response.put("ageInDays", testAuditLog.getAgeInDays());
            response.put("createdAt", testAuditLog.getCreatedAt());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to test audit log validation: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test JWT token generation and validation.
     */
    @GetMapping("/test-jwt")
    public ResponseEntity<Map<String, Object>> testJwt() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // First, ensure we have a test user
            User testUser = userRepository.findByEmailIgnoreCase("test@legacykeep.com")
                .orElseGet(() -> {
                    User user = new User();
                    user.setEmail("test@legacykeep.com");
                    user.setUsername("testuser");
                    user.setPasswordHash("$2a$10$test.hash.for.testing.purposes.only");
                    user.setStatus(UserStatus.ACTIVE);
                    user.setEmailVerified(true);
                    return userRepository.save(user);
                });

            // Generate JWT tokens
            JwtTokenDto tokens = jwtService.generateTokens(
                testUser, 
                "Test Device - MacBook Pro", 
                "127.0.0.1", 
                "San Francisco, CA", 
                false
            );

            // Validate the access token
            var claimsOpt = jwtService.validateAndExtractClaims(tokens.getAccessToken());
            boolean isValid = claimsOpt.isPresent();
            
            // Extract information from token
            var userIdOpt = jwtService.extractUserId(tokens.getAccessToken());
            var emailOpt = jwtService.extractEmail(tokens.getAccessToken());
            var rolesOpt = jwtService.extractRoles(tokens.getAccessToken());
            var sessionIdOpt = jwtService.extractSessionId(tokens.getAccessToken());

            response.put("status", "SUCCESS");
            response.put("message", "JWT token generation and validation test completed");
            response.put("timestamp", LocalDateTime.now());
            response.put("tokens", tokens);
            response.put("tokenValidation", Map.of(
                "isValid", isValid,
                "userId", userIdOpt.orElse(null),
                "email", emailOpt.orElse(null),
                "roles", rolesOpt.orElse(new String[0]),
                "sessionId", sessionIdOpt.orElse(null)
            ));
            response.put("testUser", Map.of(
                "id", testUser.getId(),
                "email", testUser.getEmail(),
                "username", testUser.getUsername(),
                "role", testUser.getRole().name()
            ));
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Failed to test JWT functionality: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Test refresh token functionality.
     */
    @GetMapping("/test-refresh-token")
    public ResponseEntity<Map<String, Object>> testRefreshToken() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Create a test user
            User testUser = userRepository.findByEmailIgnoreCase("test@example.com")
                .orElseGet(() -> {
                    User user = new User();
                    user.setEmail("test@example.com");
                    user.setUsername("testuser");
                    user.setPasswordHash("$2a$10$test.hash.for.testing.purposes.only");
                    user.setRole(UserRole.USER);
                    user.setStatus(UserStatus.ACTIVE);
                    user.setEmailVerified(true);
                    return userRepository.save(user);
                });

            // Generate initial tokens
            JwtTokenDto initialTokens = jwtService.generateTokens(
                testUser, 
                "Test Device", 
                "127.0.0.1", 
                "Test Location", 
                false
            );

            // Test refresh token flow
            Optional<JwtTokenDto> refreshedTokens = jwtService.refreshAccessToken(
                initialTokens.getRefreshToken(),
                "Test Device",
                "127.0.0.1"
            );

            response.put("status", "SUCCESS");
            response.put("message", "Refresh token test completed successfully");
            response.put("initialTokens", initialTokens);
            response.put("refreshSuccessful", refreshedTokens.isPresent());
            
            if (refreshedTokens.isPresent()) {
                response.put("refreshedTokens", refreshedTokens.get());
                
                // Validate new tokens
                Optional<Claims> newAccessClaims = jwtService.validateAndExtractClaims(refreshedTokens.get().getAccessToken());
                Optional<Claims> newRefreshClaims = jwtService.validateAndExtractClaims(refreshedTokens.get().getRefreshToken());
                
                response.put("newAccessTokenValid", newAccessClaims.isPresent());
                response.put("newRefreshTokenValid", newRefreshClaims.isPresent());
                response.put("tokenRotated", !initialTokens.getRefreshToken().equals(refreshedTokens.get().getRefreshToken()));
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Refresh token test failed: {}", e.getMessage(), e);
            response.put("status", "ERROR");
            response.put("message", "Refresh token test failed: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.status(500).body(response);
        }
    }
}
