package com.legacykeep.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT Authentication Entry Point for handling authentication failures.
 * 
 * Provides custom responses when JWT authentication fails,
 * returning proper JSON error responses instead of default 401 pages.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, 
                        HttpServletResponse response,
                        AuthenticationException authException) throws IOException, ServletException {

        log.warn("Unauthorized request to {} from IP: {} - {}", 
                request.getRequestURI(), 
                getClientIpAddress(request), 
                authException.getMessage());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", "Authentication required to access this resource");
        errorResponse.put("path", request.getRequestURI());
        errorResponse.put("timestamp", LocalDateTime.now().toString());
        errorResponse.put("status", 401);

        // Add specific error details based on exception type
        if (authException.getMessage().contains("expired")) {
            errorResponse.put("details", "JWT token has expired");
            errorResponse.put("code", "TOKEN_EXPIRED");
        } else if (authException.getMessage().contains("invalid")) {
            errorResponse.put("details", "JWT token is invalid");
            errorResponse.put("code", "TOKEN_INVALID");
        } else if (authException.getMessage().contains("missing")) {
            errorResponse.put("details", "Authorization header is missing");
            errorResponse.put("code", "TOKEN_MISSING");
        } else {
            errorResponse.put("details", "Please provide a valid JWT token");
            errorResponse.put("code", "AUTHENTICATION_REQUIRED");
        }

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    /**
     * Get client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader != null && !xForwardedForHeader.isEmpty()) {
            return xForwardedForHeader.split(",")[0].trim();
        }
        
        String xRealIpHeader = request.getHeader("X-Real-IP");
        if (xRealIpHeader != null && !xRealIpHeader.isEmpty()) {
            return xRealIpHeader;
        }
        
        return request.getRemoteAddr();
    }
}

