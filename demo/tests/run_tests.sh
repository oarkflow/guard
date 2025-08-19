#!/bin/bash

# Guard Security System - Test Runner
echo "🛡️ Guard Security System - Rule Testing Suite"
echo "=============================================="

# Check if server is running
if ! curl -s http://localhost:8080/health > /dev/null; then
    echo "❌ Error: Guard server is not running on localhost:8080"
    echo "Please start the server first with: cd demo && go run server.go"
    exit 1
fi

echo "✅ Server is running"
echo ""

# Run the tests
echo "🧪 Running comprehensive rule tests..."
cd "$(dirname "$0")"
go run rule_tests.go

echo ""
echo "📊 Test execution completed!"
