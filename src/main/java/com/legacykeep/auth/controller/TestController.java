package com.legacykeep.auth.controller;

import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserStatus;
import com.legacykeep.auth.repository.UserRepository;
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
}
