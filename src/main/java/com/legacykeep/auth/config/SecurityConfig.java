package com.legacykeep.auth.config;

import com.legacykeep.auth.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Security Configuration for Auth Service.
 * 
 * Configures Spring Security with JWT authentication, CORS, and security policies.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Configure security filter chain.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF for API endpoints
            .csrf(AbstractHttpConfigurer::disable)
            
            // Configure CORS
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Configure session management
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Configure authorization
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/auth/register", "/auth/login", "/auth/forgot-password", "/auth/verify-email", "/auth/reset-password").permitAll()
                .requestMatchers("/api/v1/social/**").permitAll()
                .requestMatchers("/auth/health").permitAll()
                .requestMatchers("/test/**").permitAll()
                .requestMatchers("/health/**", "/actuator/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                // Protected endpoints - exclude test endpoints
                .requestMatchers("/auth/me", "/auth/logout", "/auth/refresh", "/auth/deactivate", "/auth/activate", "/auth/account").authenticated()
                .requestMatchers("/api/v1/sessions/**").authenticated()
                .requestMatchers("/api/v1/2fa/**").authenticated()
                .anyRequest().authenticated()
            )
            
            // Enable JWT filter
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            
            // Configure logout
            .logout(logout -> logout
                .logoutUrl("/auth/logout")
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "refresh_token", "remember_me")
            );

        return http.build();
    }

    /**
     * Configure CORS for cross-origin requests.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow specific origins for UI development
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",  // React development server
                "http://localhost:3001",  // Alternative React port
                "http://localhost:4200",  // Angular development server
                "http://localhost:8080",  // Vue.js development server
                "http://localhost:5173",  // Vite development server
                "http://127.0.0.1:3000",
                "http://127.0.0.1:3001",
                "http://127.0.0.1:4200",
                "http://127.0.0.1:8080",
                "http://127.0.0.1:5173"
        ));
        
        // Allow common HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        
        // Allow common headers including Authorization
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "X-Forwarded-For",
                "X-Real-IP",
                "User-Agent"
        ));
        
        // Allow credentials for JWT tokens
        configuration.setAllowCredentials(true);
        
        // Expose headers that the client might need
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Total-Count",
                "X-Page-Count"
        ));
        
        // Set max age for preflight requests
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }

    /**
     * Configure password encoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
