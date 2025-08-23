#!/bin/bash

# Test script for Kafka event publishing in Auth Service
# This script tests the event publishing functionality

set -e

echo "🚀 Testing Kafka Event Publishing in Auth Service"
echo "=================================================="

# Configuration
AUTH_SERVICE_URL="http://localhost:8081/api/v1"
TEST_ENDPOINTS=(
    "/test/events/user-registered"
    "/test/events/email-verified"
    "/test/events/password-reset-requested"
    "/test/events/all"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
    esac
}

# Function to test an endpoint
test_endpoint() {
    local endpoint=$1
    local name=$2
    
    print_status "INFO" "Testing $name..."
    
    response=$(curl -s -w "\n%{http_code}" -X POST "$AUTH_SERVICE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d '{}' 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" -eq 200 ]; then
        print_status "SUCCESS" "$name: $body"
        return 0
    else
        print_status "ERROR" "$name failed with HTTP $http_code: $body"
        return 1
    fi
}

# Check if Auth Service is running
print_status "INFO" "Checking if Auth Service is running..."

if curl -s -f "$AUTH_SERVICE_URL/health" > /dev/null 2>&1; then
    print_status "SUCCESS" "Auth Service is running"
else
    print_status "ERROR" "Auth Service is not running. Please start it first."
    print_status "INFO" "Run: mvn spring-boot:run"
    exit 1
fi

echo ""
print_status "INFO" "Starting Kafka event tests..."
echo ""

# Test individual events
test_endpoint "/test/events/user-registered" "User Registration Event"
test_endpoint "/test/events/email-verified" "Email Verification Event"
test_endpoint "/test/events/password-reset-requested" "Password Reset Requested Event"

echo ""
print_status "INFO" "Testing all events together..."
test_endpoint "/test/events/all" "All Events"

echo ""
print_status "INFO" "Kafka event tests completed!"
print_status "INFO" "Check the Auth Service logs for event publishing details."
print_status "INFO" "If Kafka is running, you should see events in the 'user.events' topic."

echo ""
print_status "INFO" "To view Kafka topics and messages:"
echo "  1. Start Kafka: docker-compose up -d kafka"
echo "  2. List topics: kafka-topics --list --bootstrap-server localhost:9092"
echo "  3. View messages: kafka-console-consumer --bootstrap-server localhost:9092 --topic user.events --from-beginning"
