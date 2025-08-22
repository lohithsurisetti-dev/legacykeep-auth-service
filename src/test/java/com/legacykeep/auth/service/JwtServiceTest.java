package com.legacykeep.auth.service;

import com.legacykeep.auth.config.JwtConfig;
import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.entity.User;
import com.legacykeep.auth.entity.UserRole;
import com.legacykeep.auth.entity.UserStatus;
import com.legacykeep.auth.entity.UserSession;
import com.legacykeep.auth.repository.UserSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for JWT Service.
 * 
 * Tests JWT token generation, validation, and extraction functionality.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private UserSessionRepository userSessionRepository;

    private JwtService jwtService;
    private JwtConfig jwtConfig;
    private User testUser;

    @BeforeEach
    void setUp() {
        jwtConfig = new JwtConfig();
        jwtService = new JwtService(jwtConfig, userSessionRepository);
        
        // Create test user
        testUser = new User();
        testUser.setId(1L);
        testUser.setEmail("test@legacykeep.com");
        testUser.setUsername("testuser");
        testUser.setRole(UserRole.USER);
        testUser.setStatus(UserStatus.ACTIVE);
        testUser.setEmailVerified(true);
    }

    @Test
    void testGenerateTokens() {
        // Given
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> {
            UserSession session = invocation.getArgument(0);
            session.setId(1L);
            return session;
        });

        // When
        JwtTokenDto tokens = jwtService.generateTokens(
            testUser, 
            "Test Device", 
            "127.0.0.1", 
            "Test Location", 
            false
        );

        // Then
        assertNotNull(tokens);
        assertNotNull(tokens.getAccessToken());
        assertNotNull(tokens.getRefreshToken());
        assertEquals("Bearer", tokens.getTokenType());
        assertEquals(testUser.getId(), tokens.getUserId());
        assertEquals(testUser.getEmail(), tokens.getEmail());
        assertEquals(testUser.getUsername(), tokens.getUsername());
        assertArrayEquals(new String[]{testUser.getRole().name()}, tokens.getRoles());
        assertFalse(tokens.getRememberMe());
    }

    @Test
    void testValidateAndExtractClaims() {
        // Given
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> {
            UserSession session = invocation.getArgument(0);
            session.setId(1L);
            return session;
        });

        JwtTokenDto tokens = jwtService.generateTokens(
            testUser, 
            "Test Device", 
            "127.0.0.1", 
            "Test Location", 
            false
        );

        // When
        var claimsOpt = jwtService.validateAndExtractClaims(tokens.getAccessToken());

        // Then
        assertTrue(claimsOpt.isPresent());
        var claims = claimsOpt.get();
        assertEquals(testUser.getEmail(), claims.getSubject());
        assertEquals(testUser.getId().intValue(), claims.get("userId"));
        assertEquals(testUser.getUsername(), claims.get("username"));
        assertEquals(testUser.getRole().name(), claims.get("role"));
        assertEquals("ACCESS", claims.get("type"));
    }

    @Test
    void testExtractUserId() {
        // Given
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> {
            UserSession session = invocation.getArgument(0);
            session.setId(1L);
            return session;
        });

        JwtTokenDto tokens = jwtService.generateTokens(
            testUser, 
            "Test Device", 
            "127.0.0.1", 
            "Test Location", 
            false
        );

        // When
        var userIdOpt = jwtService.extractUserId(tokens.getAccessToken());

        // Then
        assertTrue(userIdOpt.isPresent());
        assertEquals(testUser.getId(), userIdOpt.get());
    }

    @Test
    void testExtractEmail() {
        // Given
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> {
            UserSession session = invocation.getArgument(0);
            session.setId(1L);
            return session;
        });

        JwtTokenDto tokens = jwtService.generateTokens(
            testUser, 
            "Test Device", 
            "127.0.0.1", 
            "Test Location", 
            false
        );

        // When
        var emailOpt = jwtService.extractEmail(tokens.getAccessToken());

        // Then
        assertTrue(emailOpt.isPresent());
        assertEquals(testUser.getEmail(), emailOpt.get());
    }

    @Test
    void testExtractRoles() {
        // Given
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> {
            UserSession session = invocation.getArgument(0);
            session.setId(1L);
            return session;
        });

        JwtTokenDto tokens = jwtService.generateTokens(
            testUser, 
            "Test Device", 
            "127.0.0.1", 
            "Test Location", 
            false
        );

        // When
        var rolesOpt = jwtService.extractRoles(tokens.getAccessToken());

        // Then
        assertTrue(rolesOpt.isPresent());
        assertArrayEquals(new String[]{testUser.getRole().name()}, rolesOpt.get());
    }

    @Test
    void testInvalidToken() {
        // When
        var claimsOpt = jwtService.validateAndExtractClaims("invalid.token.here");

        // Then
        assertFalse(claimsOpt.isPresent());
    }

    @Test
    void testEmptyToken() {
        // When
        var claimsOpt = jwtService.validateAndExtractClaims("");

        // Then
        assertFalse(claimsOpt.isPresent());
    }

    @Test
    void testNullToken() {
        // When
        var claimsOpt = jwtService.validateAndExtractClaims(null);

        // Then
        assertFalse(claimsOpt.isPresent());
    }
}
