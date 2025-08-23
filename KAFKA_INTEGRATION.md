# Kafka Integration - Auth Service

## Overview

The Auth Service now includes comprehensive Kafka integration for event-driven communication with other microservices. This implementation follows best practices for scalability, reliability, and observability.

## Architecture

### Event Flow
```
Auth Service → Kafka Topics → Notification Service
     ↓              ↓              ↓
User Registration → user.events → Email Delivery
Email Verification → user.events → Welcome Email
Password Reset → user.events → Reset Email
```

### Event Types

#### 1. User Registration Event (`user.registered.v1`)
- **Triggered**: When a new user registers
- **Payload**: User details, verification token, preferences
- **Consumer**: Notification Service (sends verification email)

#### 2. Email Verification Event (`user.email-verified.v1`)
- **Triggered**: When user verifies their email
- **Payload**: User details, verification timestamp, IP address
- **Consumer**: Notification Service (sends welcome email)

#### 3. Password Reset Requested Event (`user.password-reset-requested.v1`)
- **Triggered**: When user requests password reset
- **Payload**: User details, reset token, expiry time
- **Consumer**: Notification Service (sends reset email)

## Implementation Details

### Event Structure
All events extend `BaseEvent` with the following structure:
```json
{
  "eventId": "uuid-v4",
  "eventType": "user.registered.v1",
  "eventVersion": "1.0",
  "timestamp": "2025-08-23T06:00:00Z",
  "source": "auth-service",
  "correlationId": "uuid-v4",
  "userId": "user-uuid",
  "metadata": {},
  "payload": {
    // Event-specific data
  }
}
```

### Kafka Configuration
- **Producer**: Idempotent with `acks=all`
- **Compression**: LZ4 for high throughput
- **Batching**: 16KB batch size with 10ms linger
- **Retries**: 3 attempts with exponential backoff
- **Partitioning**: By `userId` for consistent ordering

### Topics
- `user.events`: All user-related events
- `auth.events`: Auth-specific events (future use)

## Setup Instructions

### 1. Prerequisites
- Kafka running on `localhost:9092`
- Docker Compose (for local development)

### 2. Start Kafka
```bash
# Start Kafka using Docker Compose
docker-compose up -d kafka

# Or start the full development environment
docker-compose up -d
```

### 3. Start Auth Service
```bash
mvn spring-boot:run
```

### 4. Test Event Publishing
```bash
# Run the test script
./test-kafka-events.sh

# Or test manually
curl -X POST http://localhost:8081/api/v1/test/events/user-registered
```

## Testing

### Manual Testing
Use the test endpoints to verify event publishing:

```bash
# Test user registration event
curl -X POST http://localhost:8081/api/v1/test/events/user-registered

# Test email verification event
curl -X POST http://localhost:8081/api/v1/test/events/email-verified

# Test password reset event
curl -X POST http://localhost:8081/api/v1/test/events/password-reset-requested

# Test all events
curl -X POST http://localhost:8081/api/v1/test/events/all
```

### Kafka Consumer Testing
```bash
# List topics
kafka-topics --list --bootstrap-server localhost:9092

# View messages in user.events topic
kafka-console-consumer --bootstrap-server localhost:9092 \
    --topic user.events --from-beginning

# View messages with key and value
kafka-console-consumer --bootstrap-server localhost:9092 \
    --topic user.events --from-beginning \
    --property print.key=true \
    --property key.separator=": "
```

### Integration Testing
The events are automatically published during:
- User registration (`/api/v1/auth/register`)
- Email verification (`/api/v1/auth/verify-email`)
- Password reset request (`/api/v1/auth/forgot-password`)

## Configuration

### Application Properties
```properties
# Kafka Configuration
spring.kafka.bootstrap-servers=localhost:9092
spring.kafka.producer.client-id=auth-service-producer
spring.kafka.producer.acks=all
spring.kafka.producer.retries=3
spring.kafka.producer.batch-size=16384
spring.kafka.producer.linger-ms=10
spring.kafka.producer.compression-type=lz4

# Topic Names
kafka.topics.user-events=user.events
kafka.topics.auth-events=auth.events
```

### Environment Variables
```bash
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
export KAFKA_TOPICS_USER_EVENTS=user.events
export KAFKA_TOPICS_AUTH_EVENTS=auth.events
```

## Monitoring

### Logs
Event publishing is logged with the following information:
- Event ID and type
- Topic and partition
- Success/failure status
- Error details (if any)

### Metrics
Kafka producer metrics are available via Spring Boot Actuator:
```bash
curl http://localhost:8081/api/v1/actuator/metrics/kafka.producer
```

### Health Checks
Kafka connectivity is monitored via health checks:
```bash
curl http://localhost:8081/api/v1/actuator/health
```

## Error Handling

### Producer Errors
- **Retry Logic**: Automatic retries with exponential backoff
- **Circuit Breaker**: Prevents cascading failures
- **Dead Letter Queue**: Failed events can be sent to DLQ (future enhancement)
- **Graceful Degradation**: Service continues to work even if Kafka is unavailable

### Event Publishing Failures
- Events are published asynchronously
- Failures don't affect the main business logic
- Comprehensive error logging for debugging
- Manual retry mechanisms available

## Best Practices

### 1. Event Design
- **Idempotency**: Events are designed to be processed multiple times safely
- **Schema Evolution**: Events include version information for backward compatibility
- **Correlation**: Events include correlation IDs for tracing

### 2. Performance
- **Batching**: Events are batched for high throughput
- **Compression**: LZ4 compression reduces network usage
- **Partitioning**: Consistent partitioning by userId ensures ordering

### 3. Reliability
- **Idempotent Producers**: Prevents duplicate events
- **Acknowledgment**: `acks=all` ensures data durability
- **Retries**: Automatic retry with exponential backoff

### 4. Observability
- **Structured Logging**: All events are logged with structured data
- **Metrics**: Kafka producer metrics are exposed
- **Tracing**: Correlation IDs enable distributed tracing

## Future Enhancements

### 1. Event Schema Registry
- Implement Avro schema registry for schema evolution
- Ensure backward compatibility across service versions

### 2. Dead Letter Queue
- Implement DLQ for failed event processing
- Add retry mechanisms for failed events

### 3. Event Replay
- Add capability to replay events for recovery
- Implement event sourcing patterns

### 4. Advanced Monitoring
- Add custom metrics for event processing
- Implement alerting for event failures
- Add event processing latency monitoring

## Troubleshooting

### Common Issues

#### 1. Kafka Connection Failed
```
Error: Failed to connect to Kafka bootstrap servers
Solution: Ensure Kafka is running and accessible
```

#### 2. Event Publishing Failed
```
Error: Failed to publish event
Solution: Check Kafka connectivity and topic existence
```

#### 3. Serialization Errors
```
Error: JSON serialization failed
Solution: Check event DTO structure and Jackson configuration
```

### Debug Commands
```bash
# Check Kafka connectivity
telnet localhost 9092

# List Kafka topics
kafka-topics --list --bootstrap-server localhost:9092

# Check topic details
kafka-topics --describe --topic user.events --bootstrap-server localhost:9092

# View consumer groups
kafka-consumer-groups --list --bootstrap-server localhost:9092
```

## Support

For issues related to Kafka integration:
1. Check the application logs for error details
2. Verify Kafka connectivity and configuration
3. Test with the provided test endpoints
4. Review the troubleshooting section above
