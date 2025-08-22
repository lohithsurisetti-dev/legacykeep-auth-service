# LegacyKeep Auth Service

## Overview

The Auth Service is the core authentication and authorization microservice for LegacyKeep. It provides enterprise-grade security features including user registration, login, session management, and comprehensive audit logging.

## Features

### 🔐 Authentication Features
- **Multi-method Registration**: Email, phone number, or username
- **Multi-method Login**: Email, phone number, or username + password
- **Email Verification**: Secure email verification with resend capability
- **Password Management**: Reset, change, and history tracking
- **Account Management**: Deactivation, reactivation, and deletion

### 🛡️ Security Features
- **JWT Token Management**: Access tokens (15min) + Refresh tokens (7 days)
- **Session Management**: Concurrent session limits and tracking
- **Rate Limiting**: Configurable rate limiting per endpoint
- **Account Lockout**: Progressive lockout for failed login attempts
- **Audit Logging**: Comprehensive security event tracking
- **Password Policy**: Configurable strength requirements

### 🔄 Service Integration
- **User Service Integration**: Profile creation and management
- **Event Publishing**: User lifecycle events
- **Circuit Breaker**: Fault tolerance with Resilience4j
- **Health Checks**: Comprehensive monitoring endpoints

## Technology Stack

- **Framework**: Spring Boot 3.x (Java 17)
- **Security**: Spring Security 6.x + JWT
- **Database**: PostgreSQL 15+ with Flyway migrations
- **Caching**: Redis for rate limiting and session caching
- **Service Communication**: OpenFeign + Circuit Breaker
- **Monitoring**: Micrometer + Prometheus
- **Testing**: JUnit 5 + Testcontainers

## Quick Start

### Prerequisites
- Java 17+
- Maven 3.8+
- PostgreSQL 15+
- Redis 7+

### Local Development Setup

1. **Clone and Navigate**
   ```bash
   cd legacykeep-backend/auth-service
   ```

2. **Database Setup**
   ```bash
   # Create database
   createdb auth_db_dev
   
   # Or using Docker
   docker run --name postgres-auth -e POSTGRES_DB=auth_db_dev -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres:15
   ```

3. **Redis Setup**
   ```bash
   # Using Docker
   docker run --name redis-auth -p 6379:6379 -d redis:7
   ```

4. **Environment Variables**
   ```bash
   export DB_USERNAME=postgres
   export DB_PASSWORD=password
   export JWT_SECRET_KEY=your-256-bit-secret-key-change-in-production
   ```

5. **Run Application**
   ```bash
   mvn spring-boot:run -Dspring.profiles.active=dev
   ```

### Docker Setup

```bash
# Build the application
mvn clean package

# Run with Docker Compose
docker-compose up auth-service
```

## 📚 Documentation

This project includes comprehensive documentation for the authentication system:

- **[JWT Authentication System](docs/JWT_AUTHENTICATION_SYSTEM.md)** - Complete guide to JWT implementation
- **[JWT Quick Reference](docs/JWT_QUICK_REFERENCE.md)** - Developer quick reference
- **[Documentation Index](docs/README.md)** - Complete documentation overview

### 🚀 Quick Start for Developers

1. **Read the [JWT Quick Reference](docs/JWT_QUICK_REFERENCE.md)** for common operations
2. **Review the [JWT Authentication System](docs/JWT_AUTHENTICATION_SYSTEM.md)** for complete understanding
3. **Check the [Documentation Index](docs/README.md)** for all available guides

## API Endpoints

### Authentication Endpoints
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Token refresh
- `POST /api/v1/auth/verify-email` - Email verification
- `POST /api/v1/auth/forgot-password` - Password reset request
- `POST /api/v1/auth/reset-password` - Password reset
- `POST /api/v1/auth/change-password` - Password change

### User Management Endpoints
- `GET /api/v1/users/profile` - Get user profile
- `PUT /api/v1/users/profile` - Update user profile
- `DELETE /api/v1/users/account` - Delete account
- `POST /api/v1/users/deactivate` - Deactivate account
- `POST /api/v1/users/reactivate` - Reactivate account
- `GET /api/v1/users/sessions` - Get user sessions
- `DELETE /api/v1/users/sessions/{sessionId}` - Terminate session
- `DELETE /api/v1/users/sessions/all` - Terminate all sessions

### Admin Endpoints
- `GET /api/v1/admin/users` - Get all users
- `GET /api/v1/admin/users/{userId}` - Get user by ID
- `PUT /api/v1/admin/users/{userId}/status` - Update user status
- `POST /api/v1/admin/users/{userId}/suspend` - Suspend user
- `POST /api/v1/admin/users/{userId}/ban` - Ban user
- `POST /api/v1/admin/users/{userId}/unlock` - Unlock user
- `GET /api/v1/admin/audit-logs` - Get audit logs

### Health & Monitoring
- `GET /actuator/health` - Health check
- `GET /actuator/metrics` - Application metrics
- `GET /actuator/prometheus` - Prometheus metrics

## Configuration

### Environment Profiles
- **dev**: Development configuration with debug logging
- **test**: Test configuration with H2 in-memory database
- **staging**: Staging configuration with external services
- **prod**: Production configuration with security hardening

### Key Configuration Properties
```properties
# JWT Configuration
auth.jwt.secret-key=${JWT_SECRET_KEY}
auth.jwt.access-token.expiration-minutes=15
auth.jwt.refresh-token.expiration-days=7

# Rate Limiting
auth.rate-limit.login.max-attempts=5
auth.rate-limit.login.window-minutes=15

# Session Management
auth.session.max-concurrent-sessions=5
auth.session.inactivity-timeout-minutes=30

# Password Policy
auth.password.min-length=8
auth.password.require-uppercase=true
auth.password.require-numbers=true
```

## Database Schema

### Core Tables
- **users**: User authentication and security data
- **user_sessions**: Session management and JWT tokens
- **audit_logs**: Security audit trail
- **rate_limits**: Rate limiting data
- **password_history**: Password history for reuse prevention
- **blacklisted_tokens**: Blacklisted JWT tokens

### Migrations
Database schema is managed using Flyway migrations located in `src/main/resources/db/migration/`.

## Testing

### Running Tests
```bash
# Unit tests
mvn test

# Integration tests
mvn verify

# Test with coverage
mvn jacoco:report
```

### Test Categories
- **Unit Tests**: Service layer and business logic
- **Integration Tests**: Repository and database operations
- **Security Tests**: Authentication and authorization
- **Performance Tests**: Load and stress testing

## Monitoring & Observability

### Metrics
- Authentication success/failure rates
- Session management metrics
- Rate limiting statistics
- Database performance metrics
- API response times

### Health Checks
- Database connectivity
- Redis connectivity
- External service health
- Application status

### Logging
- Structured logging with JSON format
- Security event logging
- Performance monitoring
- Error tracking

## Security Considerations

### JWT Security
- Short-lived access tokens (15 minutes)
- Refresh token rotation
- Token blacklisting on logout
- Secure token storage

### Password Security
- BCrypt hashing with configurable cost
- Password history tracking
- Configurable strength requirements
- Secure password reset flow

### Rate Limiting
- Per-endpoint rate limiting
- Progressive account lockout
- IP-based rate limiting
- Configurable thresholds

### Audit Logging
- All authentication events
- Security policy violations
- Administrative actions
- Data access tracking

## Development Guidelines

### Code Style
- Follow Java coding conventions
- Use meaningful variable and method names
- Add comprehensive JavaDoc comments
- Maintain consistent formatting

### Testing Requirements
- Minimum 80% code coverage
- Unit tests for all business logic
- Integration tests for database operations
- Security tests for authentication flows

### Security Best Practices
- Input validation and sanitization
- Secure error handling
- Principle of least privilege
- Regular security audits

## Deployment

### Production Deployment
1. Set secure environment variables
2. Configure production database
3. Set up monitoring and alerting
4. Configure load balancing
5. Enable security hardening

### Docker Deployment
```bash
# Build production image
docker build -t legacykeep/auth-service:latest .

# Run with production config
docker run -e SPRING_PROFILES_ACTIVE=prod legacykeep/auth-service:latest
```

## Troubleshooting

### Common Issues
- **Database Connection**: Check PostgreSQL connectivity and credentials
- **Redis Connection**: Verify Redis server is running
- **JWT Issues**: Ensure JWT secret key is properly configured
- **Rate Limiting**: Check Redis connectivity for rate limiting

### Debug Mode
Enable debug logging by setting:
```properties
logging.level.com.legacykeep.auth=DEBUG
logging.level.org.springframework.security=DEBUG
```

## Contributing

1. Follow the coding standards
2. Write comprehensive tests
3. Update documentation
4. Create feature branches
5. Submit pull requests

## License

This project is part of LegacyKeep and follows the same licensing terms.

---

**For more information, see the main project documentation.**
