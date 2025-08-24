#!/bin/bash

echo "🔐 Simple Authentication Flow Test"
echo "=================================="

# Test 1: Health Check
echo "1. Testing health check..."
curl -s http://localhost:8081/api/v1/actuator/health | jq '.status'

# Test 2: Register User
echo -e "\n2. Registering user..."
REG_RESPONSE=$(curl -s -X POST http://localhost:8081/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "simple@test.com",
    "username": "simpleuser",
    "password": "TestPassword123!",
    "confirmPassword": "TestPassword123!",
    "firstName": "Simple",
    "lastName": "Test",
    "acceptTerms": true
  }')

echo "$REG_RESPONSE" | jq '.status'

# Test 3: Get Verification Token
echo -e "\n3. Getting verification token..."
TOKEN_RESPONSE=$(curl -s http://localhost:8081/api/v1/auth/test/verification-token/simple@test.com)
echo "$TOKEN_RESPONSE" | jq '.status'

# Test 4: Verify Email
echo -e "\n4. Verifying email..."
TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.data.token')
VERIFY_RESPONSE=$(curl -s -X POST "http://localhost:8081/api/v1/auth/verify-email?token=$TOKEN")
echo "$VERIFY_RESPONSE" | jq '.status'

# Test 5: Login
echo -e "\n5. Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "simple@test.com",
    "password": "TestPassword123!"
  }')

echo "$LOGIN_RESPONSE" | jq '.status'

# Test 6: Get Current User
echo -e "\n6. Getting current user..."
ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.accessToken')
ME_RESPONSE=$(curl -s -X GET http://localhost:8081/api/v1/auth/me \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "$ME_RESPONSE" | jq '.status'

echo -e "\n✅ Test completed!"
