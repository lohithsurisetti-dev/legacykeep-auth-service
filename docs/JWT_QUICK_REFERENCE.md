# 🔐 JWT Quick Reference Guide

## 🚀 Quick Start

### Generate Tokens
```java
// Create tokens for user
JwtTokenDto tokens = jwtService.generateTokens(
    user, 
    "Mozilla/5.0...", 
    "127.0.0.1", 
    "San Francisco, CA", 
    false
);

// Access token (15 minutes)
String accessToken = tokens.getAccessToken();

// Refresh token (7 days)
String refreshToken = tokens.getRefreshToken();
```

### Validate Token
```java
// Validate and extract claims
Optional<Claims> claims = jwtService.validateAndExtractClaims(token);
if (claims.isPresent()) {
    Long userId = claims.get().get("userId", Long.class);
    String email = claims.get().getSubject();
    String[] roles = jwtService.extractRoles(token).orElse(new String[0]);
}
```

### Refresh Token
```java
// Refresh access token
Optional<JwtTokenDto> newTokens = jwtService.refreshAccessToken(
    refreshToken,
    "Mozilla/5.0...",
    "127.0.0.1"
);
```

---

## 📋 API Endpoints

### Authentication
| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/v1/auth/refresh` | Refresh access token |
| `DELETE` | `/api/v1/auth/refresh` | Revoke refresh token |

### Testing
| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/api/v1/test/test-jwt` | Test JWT generation |
| `GET` | `/api/v1/test/test-refresh-token` | Test refresh flow |

---

## ⚙️ Configuration

### Key Properties
```properties
# Token Lifetimes
auth.jwt.access-token-expiration-minutes=15
auth.jwt.refresh-token-expiration-days=7
auth.jwt.remember-me-expiration-days=30

# Security
auth.jwt.token-rotation-enabled=true
auth.jwt.blacklist-expired-tokens=true
auth.jwt.max-concurrent-sessions=5

# Algorithm
auth.jwt.algorithm=HS256
```

---

## 🔧 Common Operations

### 1. Extract User Info from Request
```java
@GetMapping("/profile")
public ResponseEntity<?> getProfile(HttpServletRequest request) {
    Long userId = (Long) request.getAttribute("userId");
    String email = (String) request.getAttribute("userEmail");
    String role = (String) request.getAttribute("userRole");
    
    // Use user info...
}
```

### 2. Check Token Expiration
```java
boolean isExpired = jwtService.isTokenExpired(token);
```

### 3. Blacklist Token
```java
tokenBlacklistService.blacklistToken(token);
```

### 4. Get Session Info
```java
Optional<UserSession> session = userSessionRepository.findByRefreshToken(refreshToken);
if (session.isPresent() && session.get().isValid()) {
    // Session is active
}
```

---

## 🛡️ Security Checklist

### ✅ Token Storage
- [ ] Access tokens in memory only
- [ ] Refresh tokens in secure cookies
- [ ] Never in localStorage/sessionStorage

### ✅ Token Transmission
- [ ] Access tokens in Authorization header
- [ ] Refresh tokens in secure cookies
- [ ] Always use HTTPS

### ✅ Error Handling
- [ ] Generic error messages
- [ ] Log security events
- [ ] Rate limiting on auth endpoints

### ✅ Monitoring
- [ ] Track failed authentication attempts
- [ ] Monitor token refresh patterns
- [ ] Alert on suspicious activity

---

## 🐛 Troubleshooting

### Common Issues

#### 401 Unauthorized
```bash
# Check token validity
curl -X GET "http://localhost:8081/api/v1/test/test-jwt"

# Check if token is blacklisted
# Check if session exists in database
```

#### Refresh Token Fails
```bash
# Check session status
curl -X GET "http://localhost:8081/api/v1/test/sessions"

# Verify refresh token in database
# Check if session is active and not expired
```

#### Token Expired
```bash
# Use refresh token to get new access token
curl -X POST "http://localhost:8081/api/v1/auth/refresh" \
  -H "Authorization: Bearer <refresh_token>"
```

---

## 📊 Monitoring

### Key Metrics
- Token generation rate
- Token refresh rate
- Failed authentication attempts
- Token blacklist size
- Session count per user

### Log Patterns
```bash
# JWT events
grep "JWT" app.log

# Authentication events
grep "authentication" app.log

# Security events
grep "security" app.log
```

---

## 🔗 Related Files

### Core Components
- `JwtService.java` - Main JWT operations
- `JwtAuthenticationFilter.java` - Request filtering
- `TokenBlacklistService.java` - Token blacklisting
- `RefreshTokenController.java` - Refresh endpoints

### Entities
- `UserSession.java` - Session management
- `AuditLog.java` - Security logging
- `User.java` - User entity

### Configuration
- `SecurityConfig.java` - Spring Security config
- `RedisConfig.java` - Redis configuration
- `application.properties` - JWT settings

---

## 📚 Additional Resources

- [Full JWT Documentation](./JWT_AUTHENTICATION_SYSTEM.md)
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/)
- [JWT.io Debugger](https://jwt.io/)

---

**Last Updated**: August 21, 2025  
**Version**: 1.2.0

