#!/bin/bash

# Advanced Security Rules Test Script
# This script tests all the advanced security rules across multiple servers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
AUTH_SERVER="http://localhost:8085"
SESSION_SERVER="http://localhost:8086"
SECURITY_SERVER="http://localhost:8087"
TRAFFIC_SERVER="http://localhost:8088"

GUARD_BINARY="./guard"
CONFIG_DIR="./testdata"

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo -e "${BLUE}🛡️  Advanced Security Rules Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Function to print test header
print_test_header() {
    echo -e "${CYAN}📋 Testing: $1${NC}"
    echo -e "${CYAN}$(printf '%.0s-' {1..50})${NC}"
}

# Function to print test result
print_test_result() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ "$2" = "PASS" ]; then
        echo -e "${GREEN}✅ $1: PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ $1: FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

# Function to start server in background
start_server() {
    local config_file=$1
    local server_name=$2
    local port=$3

    echo -e "${YELLOW}🚀 Starting $server_name on port $port...${NC}"

    if [ -f "$GUARD_BINARY" ]; then
        $GUARD_BINARY -config="$config_file" &
        local pid=$!
        echo $pid > "/tmp/guard_${port}.pid"
        sleep 3

        # Check if server is running
        if curl -s "http://localhost:$port" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $server_name started successfully${NC}"
            return 0
        else
            echo -e "${RED}❌ Failed to start $server_name${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Guard binary not found at $GUARD_BINARY${NC}"
        return 1
    fi
}

# Function to stop server
stop_server() {
    local port=$1
    local server_name=$2

    if [ -f "/tmp/guard_${port}.pid" ]; then
        local pid=$(cat "/tmp/guard_${port}.pid")
        if kill -0 $pid 2>/dev/null; then
            kill $pid
            rm "/tmp/guard_${port}.pid"
            echo -e "${YELLOW}🛑 Stopped $server_name${NC}"
        fi
    fi
}

# Function to test server response
test_server_response() {
    local url=$1
    local expected_status=$2
    local test_name=$3

    local response=$(curl -s -w "%{http_code}" -o /dev/null "$url" 2>/dev/null || echo "000")

    if [ "$response" = "$expected_status" ]; then
        print_test_result "$test_name" "PASS"
    else
        print_test_result "$test_name (Expected: $expected_status, Got: $response)" "FAIL"
    fi
}

# Function to test authentication rules
test_auth_rules() {
    print_test_header "Authentication & Login Security Rules"

    # Test basic server response
    test_server_response "$AUTH_SERVER/" "200" "Auth Server Basic Response"

    # Test login failure simulation
    for i in {1..5}; do
        curl -s -X POST "$AUTH_SERVER/login" \
             -H "Content-Type: application/json" \
             -d '{"username":"testuser","password":"wrongpassword"}' > /dev/null 2>&1
    done
    test_server_response "$AUTH_SERVER/login" "429" "Login Failure Rate Limiting"

    # Test after hours access (simulate by setting unusual timestamp)
    curl -s -X GET "$AUTH_SERVER/admin" \
         -H "X-Timestamp: $(date -d '3:00 AM' +%s)" > /dev/null 2>&1
    test_server_response "$AUTH_SERVER/admin" "403" "After Hours Access Block"

    # Test MFA bypass attempt
    curl -s -X POST "$AUTH_SERVER/mfa-bypass" \
         -H "Content-Type: application/json" \
         -d '{"bypass_code":"admin123"}' > /dev/null 2>&1
    test_server_response "$AUTH_SERVER/mfa-bypass" "403" "MFA Bypass Detection"
}

# Function to test session rules
test_session_rules() {
    print_test_header "Session & Behavioral Analysis Rules"

    # Test basic server response
    test_server_response "$SESSION_SERVER/" "200" "Session Server Basic Response"

    # Test high frequency session requests
    for i in {1..20}; do
        curl -s -X GET "$SESSION_SERVER/api/data" \
             -H "Session-ID: test-session-123" > /dev/null 2>&1 &
    done
    wait
    test_server_response "$SESSION_SERVER/api/data" "429" "High Frequency Session Detection"

    # Test geo inconsistency (simulate different locations)
    curl -s -X GET "$SESSION_SERVER/api/profile" \
         -H "X-Real-IP: 1.2.3.4" \
         -H "X-Forwarded-For: 5.6.7.8" > /dev/null 2>&1
    test_server_response "$SESSION_SERVER/api/profile" "403" "Geo Inconsistency Detection"

    # Test concurrent sessions
    for i in {1..5}; do
        curl -s -X POST "$SESSION_SERVER/session/create" \
             -H "Content-Type: application/json" \
             -d '{"user_id":"user123","device":"device'$i'"}' > /dev/null 2>&1 &
    done
    wait
    test_server_response "$SESSION_SERVER/session/create" "403" "Concurrent Sessions Limit"
}

# Function to test security rules
test_security_rules() {
    print_test_header "Security & Data Protection Rules"

    # Test basic server response
    test_server_response "$SECURITY_SERVER/" "200" "Security Server Basic Response"

    # Test SQL injection attempt
    curl -s -X GET "$SECURITY_SERVER/search?q='; DROP TABLE users; --" > /dev/null 2>&1
    test_server_response "$SECURITY_SERVER/search?q=test" "403" "SQL Injection Detection"

    # Test data exfiltration attempt (large data request)
    curl -s -X GET "$SECURITY_SERVER/export?format=json&limit=999999" > /dev/null 2>&1
    test_server_response "$SECURITY_SERVER/export" "403" "Data Exfiltration Prevention"

    # Test permission escalation attempt
    curl -s -X POST "$SECURITY_SERVER/admin/elevate" \
         -H "Content-Type: application/json" \
         -d '{"target_role":"admin","bypass_auth":true}' > /dev/null 2>&1
    test_server_response "$SECURITY_SERVER/admin/elevate" "403" "Permission Escalation Detection"

    # Test sensitive data access
    curl -s -X GET "$SECURITY_SERVER/sensitive/user-data/123" > /dev/null 2>&1
    test_server_response "$SECURITY_SERVER/sensitive/user-data/123" "403" "Sensitive Data Access Control"
}

# Function to test traffic rules
test_traffic_rules() {
    print_test_header "Traffic & Network Analysis Rules"

    # Test basic server response
    test_server_response "$TRAFFIC_SERVER/" "200" "Traffic Server Basic Response"

    # Test IP blacklist (simulate blacklisted IP)
    curl -s -X GET "$TRAFFIC_SERVER/api/test" \
         -H "X-Real-IP: 192.168.1.100" > /dev/null 2>&1
    test_server_response "$TRAFFIC_SERVER/api/test" "403" "IP Blacklist Blocking"

    # Test traffic volume spike (rapid requests)
    for i in {1..50}; do
        curl -s -X GET "$TRAFFIC_SERVER/api/endpoint$((i % 5))" > /dev/null 2>&1 &
    done
    wait
    test_server_response "$TRAFFIC_SERVER/api/test" "429" "Traffic Volume Spike Detection"

    # Test unusual geolocation (simulate high-risk country)
    curl -s -X GET "$TRAFFIC_SERVER/api/secure" \
         -H "X-Country-Code: CN" \
         -H "X-Real-IP: 1.2.3.4" > /dev/null 2>&1
    test_server_response "$TRAFFIC_SERVER/api/secure" "403" "Unusual Geolocation Blocking"

    # Test suspicious payload size
    large_payload=$(printf 'A%.0s' {1..1000000})
    curl -s -X POST "$TRAFFIC_SERVER/api/upload" \
         -H "Content-Type: application/json" \
         -d "{\"data\":\"$large_payload\"}" > /dev/null 2>&1
    test_server_response "$TRAFFIC_SERVER/api/upload" "413" "Suspicious Payload Size Detection"
}

# Function to test CAPTCHA integration
test_captcha_integration() {
    print_test_header "CAPTCHA Integration Tests"

    # Test CAPTCHA trigger on auth server
    curl -s -X GET "$AUTH_SERVER/trigger-captcha" > /dev/null 2>&1
    local captcha_response=$(curl -s "$AUTH_SERVER/captcha/challenge")

    if echo "$captcha_response" | grep -q "challenge"; then
        print_test_result "CAPTCHA Challenge Generation" "PASS"
    else
        print_test_result "CAPTCHA Challenge Generation" "FAIL"
    fi

    # Test CAPTCHA verification
    curl -s -X POST "$AUTH_SERVER/captcha/verify" \
         -H "Content-Type: application/json" \
         -d '{"challenge_id":"test","answer":"wrong"}' > /dev/null 2>&1
    test_server_response "$AUTH_SERVER/captcha/verify" "400" "CAPTCHA Wrong Answer Handling"
}

# Function to cleanup
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    stop_server "8085" "Auth Server"
    stop_server "8086" "Session Server"
    stop_server "8087" "Security Server"
    stop_server "8088" "Traffic Server"

    # Remove any temporary files
    rm -f /tmp/guard_*.pid
}

# Function to print final results
print_final_results() {
    echo -e "${BLUE}📊 Test Results Summary${NC}"
    echo -e "${BLUE}======================${NC}"
    echo -e "Total Tests: ${TOTAL_TESTS}"
    echo -e "${GREEN}Passed: ${PASSED_TESTS}${NC}"
    echo -e "${RED}Failed: ${FAILED_TESTS}${NC}"

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}❌ Some tests failed. Check the output above for details.${NC}"
        exit 1
    fi
}

# Main execution
main() {
    echo -e "${PURPLE}🔧 Setting up test environment...${NC}"

    # Check if guard binary exists
    if [ ! -f "$GUARD_BINARY" ]; then
        echo -e "${RED}❌ Guard binary not found at $GUARD_BINARY${NC}"
        echo -e "${YELLOW}💡 Please build the guard binary first:${NC}"
        echo -e "${YELLOW}   cd .. && go build -o guard${NC}"
        exit 1
    fi

    # Check if config files exist
    for config in "advanced_auth_rules_config.json" "session_behavioral_rules_config.json" "security_data_protection_rules_config.json" "traffic_network_analysis_rules_config.json"; do
        if [ ! -f "$CONFIG_DIR/$config" ]; then
            echo -e "${RED}❌ Config file not found: $CONFIG_DIR/$config${NC}"
            exit 1
        fi
    done

    # Set trap for cleanup
    trap cleanup EXIT

    echo -e "${GREEN}✅ Environment setup complete${NC}"
    echo ""

    # Start all servers
    start_server "$CONFIG_DIR/advanced_auth_rules_config.json" "Auth Server" "8085"
    start_server "$CONFIG_DIR/session_behavioral_rules_config.json" "Session Server" "8086"
    start_server "$CONFIG_DIR/security_data_protection_rules_config.json" "Security Server" "8087"
    start_server "$CONFIG_DIR/traffic_network_analysis_rules_config.json" "Traffic Server" "8088"

    echo ""
    echo -e "${PURPLE}🧪 Starting security tests...${NC}"
    echo ""

    # Run all tests
    test_auth_rules
    test_session_rules
    test_security_rules
    test_traffic_rules
    test_captcha_integration

    # Print final results
    print_final_results
}

# Check if script is being run directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
