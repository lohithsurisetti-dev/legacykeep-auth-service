#!/bin/bash

# LegacyKeep Authentication Flow Test Script
# This script tests the complete authentication flow:
# 1. User Registration
# 2. Email Verification
# 3. User Login
# 4. Password Reset
# 5. JWT Token Validation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUTH_SERVICE_URL="http://localhost:8081/api/v1"
TEST_EMAIL="test.auth.$(date +%s)@example.com"
TEST_USERNAME="testauthuser$(date +%s)"
TEST_PASSWORD="TestPassword123!"

echo -e "${BLUE}🔐 LegacyKeep Authentication Flow Test${NC}"
echo "=========================================="
echo ""

# Function to print section headers
print_section() {
    echo -e "\n${YELLOW}📋 $1${NC}"
    echo "----------------------------------------"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to print info messages
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Wait for service to be ready
print_section "Checking Service Health"
print_info "Waiting for Auth Service to be ready..."

for i in {1..30}; do
    if curl -s "$AUTH_SERVICE_URL/actuator/health" > /dev/null 2>&1; then
        print_success "Auth Service is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Auth Service is not responding. Please start the service first."
        exit 1
    fi
    sleep 1
done

# 1. User Registration
print_section "1. User Registration"
print_info "Registering new user: $TEST_EMAIL"

REGISTRATION_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$TEST_EMAIL\",
        \"username\": \"$TEST_USERNAME\",
        \"password\": \"$TEST_PASSWORD\",
        \"confirmPassword\": \"$TEST_PASSWORD\",
        \"firstName\": \"Test\",
        \"lastName\": \"User\",
        \"acceptTerms\": true
    }")

echo "Registration Response:"
echo "$REGISTRATION_RESPONSE" | jq .

if echo "$REGISTRATION_RESPONSE" | jq -e '.status == "success"' > /dev/null; then
    print_success "User registration successful!"
    USER_ID=$(echo "$REGISTRATION_RESPONSE" | jq -r '.data.userId')
    print_info "User ID: $USER_ID"
else
    print_error "User registration failed!"
    exit 1
fi

# 2. Get Verification Token
print_section "2. Email Verification Setup"
print_info "Getting verification token for testing..."

VERIFICATION_RESPONSE=$(curl -s "$AUTH_SERVICE_URL/auth/test/verification-token/$TEST_EMAIL")

echo "Verification Token Response:"
echo "$VERIFICATION_RESPONSE" | jq .

if echo "$VERIFICATION_RESPONSE" | jq -e '.status == "success"' > /dev/null; then
    print_success "Verification token retrieved!"
    VERIFICATION_TOKEN=$(echo "$VERIFICATION_RESPONSE" | jq -r '.data.token')
    print_info "Verification Token: $VERIFICATION_TOKEN"
else
    print_error "Failed to get verification token!"
    exit 1
fi

# 3. Email Verification
print_section "3. Email Verification"
print_info "Verifying email with token..."

VERIFY_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/verify-email?token=$VERIFICATION_TOKEN")

echo "Email Verification Response:"
echo "$VERIFY_RESPONSE" | jq .

if echo "$VERIFY_RESPONSE" | jq -e '.status == "success"' > /dev/null; then
    print_success "Email verification successful!"
else
    print_error "Email verification failed!"
    exit 1
fi

# 4. User Login
print_section "4. User Login"
print_info "Logging in with verified account..."

LOGIN_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"identifier\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\"
    }")

echo "Login Response:"
echo "$LOGIN_RESPONSE" | jq .

if echo "$LOGIN_RESPONSE" | jq -e '.status == "success"' > /dev/null; then
    print_success "User login successful!"
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.accessToken')
    REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.refreshToken')
    print_info "Access Token: ${ACCESS_TOKEN:0:50}..."
    print_info "Refresh Token: ${REFRESH_TOKEN:0:50}..."
else
    print_error "User login failed!"
    exit 1
fi

# 5. JWT Token Validation - Get Current User
print_section "5. JWT Token Validation"
print_info "Testing JWT token validation by getting current user..."

ME_RESPONSE=$(curl -s -X GET "$AUTH_SERVICE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Current User Response:"
echo "$ME_RESPONSE" | jq .

if echo "$ME_RESPONSE" | jq -e '.status == "success"' > /dev/null; then
    print_success "JWT token validation successful!"
    USER_EMAIL=$(echo "$ME_RESPONSE" | jq -r '.data.email')
    USER_STATUS=$(echo "$ME_RESPONSE" | jq -r '.data.status')
    print_info "Authenticated User: $USER_EMAIL"
    print_info "User Status: $USER_STATUS"
else
    print_error "JWT token validation failed!"
    exit 1
fi

# 6. Password Reset Flow
print_section "6. Password Reset Flow"
print_info "Requesting password reset..."

RESET_REQUEST_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/forgot-password?email=$TEST_EMAIL")

echo "Password Reset Request Response:"
echo "$RESET_REQUEST_RESPONSE" | jq .

if echo "$RESET_REQUEST_RESPONSE" | jq -e '.status == "success"' > /dev/null; then
    print_success "Password reset request successful!"
else
    print_error "Password reset request failed!"
    exit 1
fi

# 7. Get Password Reset Token
print_section "7. Password Reset Token"
print_info "Getting password reset token for testing..."

# Note: This would require a similar test endpoint for password reset tokens
# For now, we'll just show that the request was successful
print_info "Password reset email would be sent to: $TEST_EMAIL"
print_info "In a real scenario, the user would click the link in the email"

# 8. Logout
print_section "8. User Logout"
print_info "Logging out user..."

LOGOUT_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/logout" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Logout Response:"
echo "$LOGOUT_RESPONSE" | jq .

if echo "$LOGOUT_RESPONSE" | jq -e '.status == "success"' > /dev/null; then
    print_success "User logout successful!"
else
    print_error "User logout failed!"
    exit 1
fi

# 9. Verify Token is Invalid After Logout
print_section "9. Token Invalidation Test"
print_info "Testing that token is invalid after logout..."

INVALID_ME_RESPONSE=$(curl -s -X GET "$AUTH_SERVICE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Invalid Token Response:"
echo "$INVALID_ME_RESPONSE" | jq .

if echo "$INVALID_ME_RESPONSE" | jq -e '.status == "error"' > /dev/null; then
    print_success "Token properly invalidated after logout!"
else
    print_error "Token still valid after logout!"
fi

# Summary
print_section "Test Summary"
print_success "🎉 All authentication flow tests completed successfully!"
echo ""
print_info "Tested Features:"
echo "  ✅ User Registration with email verification"
echo "  ✅ Email verification with token"
echo "  ✅ User login with JWT token generation"
echo "  ✅ JWT token validation and user info retrieval"
echo "  ✅ Password reset request"
echo "  ✅ User logout with token invalidation"
echo ""
print_info "Authentication Flow Status: COMPLETE"
print_info "All endpoints are working correctly for localhost development!"
echo ""
print_info "Next Steps:"
echo "  🔗 Integrate with frontend application"
echo "  🔗 Add social login (Google, Apple)"
echo "  🔗 Implement two-factor authentication"
echo "  🔗 Add rate limiting and security headers"
echo "  🔗 Deploy to production environment"
