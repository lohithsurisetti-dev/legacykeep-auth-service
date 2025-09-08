#!/bin/bash

# =============================================================================
# Phone Number Registration and Multi-Method Login Test Script
# =============================================================================

echo "🚀 Testing Phone Number Registration and Multi-Method Login"
echo "=========================================================="

# Configuration
AUTH_SERVICE_URL="http://localhost:8081"
BASE_URL="${AUTH_SERVICE_URL}/api/v1/auth"

# Test data
EMAIL="testuser@example.com"
PHONE="+1234567890"
USERNAME="testuser123"
PASSWORD="TestPass123!"
FIRST_NAME="Test"
LAST_NAME="User"

echo ""
echo "📋 Test Data:"
echo "  Email: $EMAIL"
echo "  Phone: $PHONE"
echo "  Username: $USERNAME"
echo "  Password: $PASSWORD"
echo ""

# Function to make HTTP requests
make_request() {
    local method=$1
    local url=$2
    local data=$3
    local description=$4
    
    echo "🔍 $description"
    echo "   $method $url"
    
    if [ -n "$data" ]; then
        echo "   Data: $data"
        response=$(curl -s -w "\n%{http_code}" -X $method \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$url")
    else
        response=$(curl -s -w "\n%{http_code}" -X $method \
            -H "Content-Type: application/json" \
            "$url")
    fi
    
    # Split response and status code
    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | head -n -1)
    
    echo "   Status: $http_code"
    echo "   Response: $response_body"
    echo ""
    
    return $http_code
}

# Test 1: Email Registration
echo "🧪 Test 1: Email Registration"
echo "-----------------------------"
EMAIL_REGISTER_DATA='{
    "email": "'$EMAIL'",
    "username": "'$USERNAME'",
    "firstName": "'$FIRST_NAME'",
    "lastName": "'$LAST_NAME'",
    "password": "'$PASSWORD'",
    "confirmPassword": "'$PASSWORD'",
    "acceptTerms": true,
    "acceptMarketing": false
}'

make_request "POST" "$BASE_URL/register" "$EMAIL_REGISTER_DATA" "Register with email"

# Test 2: Phone Registration
echo "🧪 Test 2: Phone Number Registration"
echo "------------------------------------"
PHONE_REGISTER_DATA='{
    "phoneNumber": "'$PHONE'",
    "username": "phoneuser123",
    "firstName": "Phone",
    "lastName": "User",
    "password": "'$PASSWORD'",
    "confirmPassword": "'$PASSWORD'",
    "acceptTerms": true,
    "acceptMarketing": false
}'

make_request "POST" "$BASE_URL/register" "$PHONE_REGISTER_DATA" "Register with phone number"

# Test 3: Multi-Method Login - Email
echo "🧪 Test 3: Multi-Method Login - Email"
echo "-------------------------------------"
EMAIL_LOGIN_DATA='{
    "identifier": "'$EMAIL'",
    "password": "'$PASSWORD'"
}'

make_request "POST" "$BASE_URL/login" "$EMAIL_LOGIN_DATA" "Login with email"

# Test 4: Multi-Method Login - Phone
echo "🧪 Test 4: Multi-Method Login - Phone"
echo "-------------------------------------"
PHONE_LOGIN_DATA='{
    "identifier": "'$PHONE'",
    "password": "'$PASSWORD'"
}'

make_request "POST" "$BASE_URL/login" "$PHONE_LOGIN_DATA" "Login with phone number"

# Test 5: Multi-Method Login - Username
echo "🧪 Test 5: Multi-Method Login - Username"
echo "----------------------------------------"
USERNAME_LOGIN_DATA='{
    "identifier": "'$USERNAME'",
    "password": "'$PASSWORD'"
}'

make_request "POST" "$BASE_URL/login" "$USERNAME_LOGIN_DATA" "Login with username"

# Test 6: Invalid Registration - No Email or Phone
echo "🧪 Test 6: Invalid Registration - No Email or Phone"
echo "---------------------------------------------------"
INVALID_REGISTER_DATA='{
    "username": "invaliduser",
    "firstName": "Invalid",
    "lastName": "User",
    "password": "'$PASSWORD'",
    "confirmPassword": "'$PASSWORD'",
    "acceptTerms": true,
    "acceptMarketing": false
}'

make_request "POST" "$BASE_URL/register" "$INVALID_REGISTER_DATA" "Register without email or phone (should fail)"

# Test 7: Invalid Phone Format
echo "🧪 Test 7: Invalid Phone Format"
echo "-------------------------------"
INVALID_PHONE_DATA='{
    "phoneNumber": "invalid-phone",
    "username": "invalidphone",
    "firstName": "Invalid",
    "lastName": "Phone",
    "password": "'$PASSWORD'",
    "confirmPassword": "'$PASSWORD'",
    "acceptTerms": true,
    "acceptMarketing": false
}'

make_request "POST" "$BASE_URL/register" "$INVALID_PHONE_DATA" "Register with invalid phone format (should fail)"

echo "✅ Phone Number Registration and Multi-Method Login Tests Completed!"
echo ""
echo "📊 Summary:"
echo "  - Email registration: Should work"
echo "  - Phone registration: Should work"
echo "  - Email login: Should work"
echo "  - Phone login: Should work"
echo "  - Username login: Should work"
echo "  - Invalid registration (no email/phone): Should fail"
echo "  - Invalid phone format: Should fail"
echo ""
echo "🔍 Check the responses above for success/failure status codes:"
echo "  - 200/201: Success"
echo "  - 400: Bad Request (validation error)"
echo "  - 500: Internal Server Error"