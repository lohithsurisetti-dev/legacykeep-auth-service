package com.legacykeep.auth.security;

import com.legacykeep.auth.service.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * JWT Authentication Filter for request interception and token validation.
 * 
 * Intercepts incoming requests, extracts JWT tokens from headers,
 * validates them, and sets up Spring Security context.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String authHeader = request.getHeader("Authorization");
            
            // Skip JWT processing for excluded paths
            if (shouldSkipJwtProcessing(request, authHeader)) {
                filterChain.doFilter(request, response);
                return;
            }

            String jwt = extractJwtFromHeader(authHeader);
            if (jwt == null) {
                filterChain.doFilter(request, response);
                return;
            }

            // Validate token and extract claims
            Optional<Claims> claimsOpt = jwtService.validateAndExtractClaims(jwt);
            if (claimsOpt.isEmpty()) {
                log.warn("Invalid JWT token from IP: {}", getClientIpAddress(request));
                filterChain.doFilter(request, response);
                return;
            }

            Claims claims = claimsOpt.get();
            
            // Extract user information
            String email = claims.getSubject();
            Long userId = claims.get("userId", Long.class);
            String role = claims.get("role", String.class);
            String sessionId = claims.get("sessionId", String.class);

            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                
                // Create authorities from roles
                List<SimpleGrantedAuthority> authorities = Stream.of(role)
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                        .toList();

                // Create authentication token
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        email, null, authorities);

                // Add additional details
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                // Set custom attributes for later use
                request.setAttribute("userId", userId);
                request.setAttribute("userEmail", email);
                request.setAttribute("userRole", role);
                request.setAttribute("sessionId", sessionId);

                // Set authentication in security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
                
                log.debug("JWT authentication successful for user: {} from IP: {}", 
                         email, getClientIpAddress(request));
            }

        } catch (Exception e) {
            log.error("JWT authentication failed: {}", e.getMessage(), e);
            // Clear security context on error
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from Authorization header.
     */
    private String extractJwtFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Check if JWT processing should be skipped for this request.
     */
    private boolean shouldSkipJwtProcessing(HttpServletRequest request, String authHeader) {
        String path = request.getRequestURI();
        
        // Skip for public endpoints
        if (path.startsWith("/api/v1/test/") ||
            path.startsWith("/api/v1/auth/login") ||
            path.startsWith("/api/v1/auth/register") ||
            path.startsWith("/api/v1/auth/forgot-password") ||
            path.startsWith("/api/v1/health") ||
            path.startsWith("/api/v1/actuator/")) {
            return true;
        }

        // Skip if no authorization header
        return authHeader == null;
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
