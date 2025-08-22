package com.legacykeep.auth.controller;

import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserStatus;
import com.legacykeep.auth.entity.UserSession;
import com.legacykeep.auth.repository.UserRepository;
import com.legacykeep.auth.repository.UserSessionRepository;
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
@RestController
@RequestMapping("/api/v1/test")
public class TestController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserSessionRepository userSessionRepository;

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
}
