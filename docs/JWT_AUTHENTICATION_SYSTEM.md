# 🔐 JWT Authentication System Documentation

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Token Types & Lifecycle](#token-types--lifecycle)
4. [Security Features](#security-features)
5. [API Endpoints](#api-endpoints)
6. [Configuration](#configuration)
7. [Implementation Details](#implementation-details)
8. [Testing](#testing)
9. [Security Best Practices](#security-best-practices)
10. [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

The LegacyKeep JWT Authentication System provides enterprise-grade authentication with **short-lived access tokens** and **long-lived refresh tokens**. This system ensures both security and user convenience while following industry best practices.

### Key Features
- ✅ **Short-lived access tokens** (15 minutes) for API security
- ✅ **Long-lived refresh tokens** (7 days) for user convenience
- ✅ **Automatic token rotation** for enhanced security
- ✅ **Redis-based token blacklisting** with TTL
- ✅ **Session management** with database persistence
- ✅ **Comprehensive audit logging** for security monitoring
- ✅ **IP tracking and device management**
- ✅ **Role-based authorization** with Spring Security

---

## 🏗️ Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │    │   Auth Service  │    │   Redis Cache   │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Access Token│◄┼────┼►│ JWT Service │ │    │ │ Blacklist   │ │
│ │ (15 min)    │ │    │ │             │ │    │ │ Service     │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │Refresh Token│◄┼────┼►│User Session │ │    │ │ PostgreSQL  │ │
│ │ (7 days)    │ │    │ │ Repository  │ │    │ │ Database    │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Data Flow

1. **Authentication Flow**
   ```
   User Login → Generate Tokens → Store Session → Return Tokens
   ```

2. **API Request Flow**
   ```
   Request → JWT Filter → Validate Token → Set Security Context → Process Request
   ```

3. **Token Refresh Flow**
   ```
   Refresh Request → Validate Refresh Token → Generate New Access Token → Rotate Refresh Token → Update Session
   ```

---

## 🔑 Token Types & Lifecycle

### Access Token
- **Purpose**: API authentication and authorization
- **Lifetime**: 15 minutes (configurable)
- **Storage**: Client-side (memory/secure storage)
- **Claims**: User ID, email, roles, session ID, token type
- **Security**: Short-lived to minimize exposure

### Refresh Token
- **Purpose**: Obtain new access tokens without re-authentication
- **Lifetime**: 7 days (configurable)
- **Storage**: Client-side (secure storage)
- **Claims**: User ID, session ID, token type
- **Security**: Long-lived but with rotation and blacklisting

### Remember Me Token
- **Purpose**: Extended sessions for trusted devices
- **Lifetime**: 30 days (configurable)
- **Storage**: Client-side (secure storage)
- **Security**: Same as refresh token with extended lifetime

### Token Lifecycle Diagram

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Login     │───►│ Generate    │───►│ Store       │
│             │    │ Tokens      │    │ Session     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Use Access  │    │ Access      │    │ Session     │
│ Token       │    │ Expires     │    │ Valid       │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Refresh     │    │ Generate    │    │ Rotate      │
│ Request     │───►│ New Access  │───►│ Refresh     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Blacklist   │    │ Continue    │    │ Update      │
│ Old Token   │    │ Using New   │    │ Session     │
└─────────────┘    └─────────────┘    └─────────────┘
```

---

## 🛡️ Security Features

### 1. Token Rotation
- **Trigger**: 24 hours after session creation or 7 days of inactivity
- **Process**: Generate new refresh token, blacklist old one
- **Benefit**: Prevents refresh token reuse attacks

### 2. Token Blacklisting
- **Storage**: Redis with automatic TTL
- **Scope**: Revoked tokens and rotated refresh tokens
- **TTL**: Matches original token expiration

### 3. Session Management
- **Storage**: PostgreSQL database
- **Tracking**: Device info, IP address, login location
- **Validation**: Active status, expiration, revocation

### 4. Audit Logging
- **Events**: Login, logout, token refresh, security events
- **Data**: IP address, device info, user actions
- **Retention**: Configurable retention policies

### 5. IP Tracking
- **Purpose**: Security monitoring and fraud detection
- **Headers**: X-Forwarded-For, X-Real-IP
- **Storage**: Session and audit log records

---

## 🌐 API Endpoints

### Authentication Endpoints

#### POST `/api/v1/auth/refresh`
**Purpose**: Refresh access token using refresh token

**Request Headers**:
```
Authorization: Bearer <refresh_token>
User-Agent: <device_info>
```

**Response**:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "refreshExpiresIn": 604800,
  "userId": 1,
  "email": "user@example.com",
  "username": "username",
  "roles": ["USER"],
  "sessionId": "uuid",
  "rememberMe": false,
  "issuedAt": "2025-08-21T21:30:00",
  "expiresAt": "2025-08-21T21:45:00",
  "refreshExpiresAt": "2025-08-28T21:30:00",
  "deviceInfo": "Mozilla/5.0...",
  "ipAddress": "127.0.0.1",
  "location": "San Francisco, CA"
}
```

#### DELETE `/api/v1/auth/refresh`
**Purpose**: Revoke refresh token (logout)

**Request Headers**:
```
Authorization: Bearer <refresh_token>
```

**Response**:
```json
{
  "message": "Refresh token revoked successfully"
}
```

### Test Endpoints

#### GET `/api/v1/test/test-jwt`
**Purpose**: Test JWT token generation and validation

#### GET `/api/v1/test/test-refresh-token`
**Purpose**: Test refresh token functionality

---

## ⚙️ Configuration

### Application Properties

```properties
# JWT Configuration
auth.jwt.secret-key=legacykeep-jwt-secret-key-change-in-production-512-bits-minimum-required-for-hs512-algorithm
auth.jwt.issuer=legacykeep-auth-service
auth.jwt.audience=legacykeep-client
auth.jwt.access-token-expiration-minutes=15
auth.jwt.refresh-token-expiration-days=7
auth.jwt.remember-me-expiration-days=30
auth.jwt.max-concurrent-sessions=5
auth.jwt.token-rotation-enabled=true
auth.jwt.blacklist-expired-tokens=true
auth.jwt.include-roles-in-claims=true
auth.jwt.include-permissions-in-claims=false
auth.jwt.include-device-info-in-claims=true
auth.jwt.algorithm=HS256
auth.jwt.token-prefix=Bearer
auth.jwt.header-name=Authorization
auth.jwt.refresh-token-cookie-name=refresh_token
auth.jwt.remember-me-cookie-name=remember_me
auth.jwt.secure-cookies=true
auth.jwt.http-only-cookies=true
auth.jwt.same-site-policy=Strict
```

### Security Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/v1/test/**").permitAll()
                .requestMatchers("/api/v1/actuator/**").permitAll()
                .requestMatchers("/api/v1/health/**").permitAll()
                .requestMatchers("/api/v1/auth/login").permitAll()
                .requestMatchers("/api/v1/auth/register").permitAll()
                .requestMatchers("/api/v1/auth/forgot-password").permitAll()
                .requestMatchers("/api/v1/auth/refresh").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

---

## 🔧 Implementation Details

### Core Components

#### 1. JwtService
**Location**: `com.legacykeep.auth.service.JwtService`

**Key Methods**:
- `generateTokens()`: Create access and refresh tokens
- `refreshAccessToken()`: Refresh tokens with rotation
- `validateAndExtractClaims()`: Validate and extract JWT claims
- `shouldRotateRefreshToken()`: Determine if rotation is needed

#### 2. JwtAuthenticationFilter
**Location**: `com.legacykeep.auth.security.JwtAuthenticationFilter`

**Purpose**: Intercept requests and validate JWT tokens

**Process**:
1. Extract token from Authorization header
2. Validate token signature and expiration
3. Check token blacklist
4. Set Spring Security context
5. Add user information to request attributes

#### 3. TokenBlacklistService
**Location**: `com.legacykeep.auth.service.TokenBlacklistService`

**Purpose**: Manage revoked and rotated tokens

**Features**:
- Redis-based storage with TTL
- Automatic expiration
- Bulk operations for user logout

#### 4. UserSession Entity
**Location**: `com.legacykeep.auth.entity.UserSession`

**Purpose**: Track user sessions and tokens

**Key Fields**:
- `sessionToken`: Current access token
- `refreshToken`: Current refresh token
- `expiresAt`: Session expiration
- `deviceInfo`: Client device information
- `ipAddress`: Client IP address
- `isActive`: Session status

### Token Generation Process

```java
public JwtTokenDto generateTokens(User user, String deviceInfo, String ipAddress, String location, boolean rememberMe) {
    // 1. Generate session ID
    String sessionId = UUID.randomUUID().toString();
    
    // 2. Calculate expiration times
    LocalDateTime accessTokenExpiresAt = now.plusMinutes(jwtConfig.getAccessTokenExpirationMinutes());
    LocalDateTime refreshTokenExpiresAt = rememberMe ? 
        now.plusDays(jwtConfig.getRememberMeExpirationDays()) : 
        now.plusDays(jwtConfig.getRefreshTokenExpirationDays());

    // 3. Generate tokens
    String accessToken = generateAccessToken(user, sessionId, accessTokenExpiresAt);
    String refreshToken = generateRefreshToken(user, sessionId, refreshTokenExpiresAt);

    // 4. Save session
    UserSession userSession = createUserSession(user, sessionId, accessToken, refreshToken, ...);
    userSessionRepository.save(userSession);

    // 5. Return token DTO
    return buildTokenDto(accessToken, refreshToken, user, userSession, ...);
}
```

### Token Validation Process

```java
public Optional<Claims> validateAndExtractClaims(String token) {
    try {
        // 1. Check if token is blacklisted
        if (isTokenBlacklisted(token)) {
            return Optional.empty();
        }

        // 2. Parse and verify token
        Claims claims = Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();

        // 3. Check expiration
        if (claims.getExpiration().before(new Date())) {
            return Optional.empty();
        }

        return Optional.of(claims);
    } catch (Exception e) {
        log.warn("Token validation failed: {}", e.getMessage());
        return Optional.empty();
    }
}
```

---

## 🧪 Testing

### Unit Tests
**Location**: `src/test/java/com/legacykeep/auth/service/JwtServiceTest.java`

**Coverage**:
- Token generation
- Token validation
- Claims extraction
- Error handling

### Integration Tests
**Location**: `src/main/java/com/legacykeep/auth/controller/TestController.java`

**Endpoints**:
- `/api/v1/test/test-jwt`: Test JWT functionality
- `/api/v1/test/test-refresh-token`: Test refresh token flow

### Manual Testing

#### Test Token Generation
```bash
curl -X GET "http://localhost:8081/api/v1/test/test-jwt" \
  -H "Content-Type: application/json"
```

#### Test Refresh Token Flow
```bash
curl -X GET "http://localhost:8081/api/v1/test/test-refresh-token" \
  -H "Content-Type: application/json"
```

#### Test Token Refresh
```bash
curl -X POST "http://localhost:8081/api/v1/auth/refresh" \
  -H "Authorization: Bearer <refresh_token>" \
  -H "User-Agent: Test Client"
```

---

## 🔒 Security Best Practices

### 1. Token Storage
- **Access Tokens**: Store in memory only
- **Refresh Tokens**: Store in secure, httpOnly cookies
- **Never**: Store tokens in localStorage or sessionStorage

### 2. Token Transmission
- **Access Tokens**: Include in Authorization header
- **Refresh Tokens**: Send via secure cookies
- **HTTPS**: Always use HTTPS in production

### 3. Token Rotation
- **Automatic**: Rotate refresh tokens periodically
- **Manual**: Rotate on suspicious activity
- **Blacklist**: Always blacklist old tokens

### 4. Session Management
- **Limit Sessions**: Maximum concurrent sessions per user
- **Track Devices**: Monitor device and location changes
- **Audit Logs**: Log all authentication events

### 5. Error Handling
- **Generic Messages**: Don't reveal sensitive information
- **Rate Limiting**: Prevent brute force attacks
- **Logging**: Log security events for monitoring

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Token Expired
**Symptoms**: 401 Unauthorized responses
**Solution**: Use refresh token to get new access token

#### 2. Invalid Token
**Symptoms**: 401 Unauthorized responses
**Solution**: Re-authenticate user

#### 3. Token Blacklisted
**Symptoms**: 401 Unauthorized responses
**Solution**: User must log in again

#### 4. Session Not Found
**Symptoms**: Refresh token fails
**Solution**: Check database for session records

### Debug Endpoints

#### Check Token Validity
```bash
curl -X GET "http://localhost:8081/api/v1/test/test-jwt" \
  -H "Content-Type: application/json"
```

#### Check Session Status
```bash
curl -X GET "http://localhost:8081/api/v1/test/sessions" \
  -H "Content-Type: application/json"
```

#### Check Audit Logs
```bash
curl -X GET "http://localhost:8081/api/v1/test/audit-logs" \
  -H "Content-Type: application/json"
```

### Log Analysis

#### JWT Service Logs
```bash
grep "JWT" app.log | tail -20
```

#### Authentication Events
```bash
grep "authentication" app.log | tail -20
```

#### Security Events
```bash
grep "security" app.log | tail -20
```

---

## 📚 Additional Resources

### Documentation
- [Spring Security JWT Guide](https://spring.io/guides/tutorials/spring-security-and-angular-js/)
- [JWT.io](https://jwt.io/) - JWT Debugger and Documentation
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)

### Security Standards
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

### Monitoring
- [Prometheus Metrics](https://prometheus.io/docs/concepts/data_model/)
- [Grafana Dashboards](https://grafana.com/docs/grafana/latest/dashboards/)

---

## 📝 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-08-21 | Initial JWT implementation |
| 1.1.0 | 2025-08-21 | Added refresh token system |
| 1.2.0 | 2025-08-21 | Added token rotation and blacklisting |

---

**Last Updated**: August 21, 2025  
**Maintainer**: LegacyKeep Team  
**Contact**: [team@legacykeep.com](mailto:team@legacykeep.com)
