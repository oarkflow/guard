#!/bin/bash

echo "🚀 Starting Guard Security System Demo..."
echo "========================================"
echo ""
echo "📖 Demo Guide: demo/README.md"
echo "⚙️ Config Guide: config/README.md"
echo ""
echo "🌐 Demo will be available at: http://localhost:8080"
echo "📊 Metrics endpoint: http://localhost:8080/metrics"
echo ""

# Start the demo server
go run demo/server.go
