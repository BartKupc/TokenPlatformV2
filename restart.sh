#!/bin/bash

# Token Platform Restart Script
# This script stops and then starts all Token Platform services

echo "🔄 Restarting Token Platform..."

# Check if we're in the right directory
if [ ! -f "startup.py" ]; then
    echo "❌ Please run this script from the TokenPlatform directory"
    exit 1
fi

# Clean database first for a fresh start
echo "🧹 Cleaning database for fresh start..."
./clean_db.sh

# Clear debug logs for a fresh start
echo "🧹 Clearing debug logs for fresh start..."
rm -f /tmp/tokenplatform_debug.log
touch /tmp/tokenplatform_debug.log
echo "$(date): Token Platform restart - debug log cleared" > /tmp/tokenplatform_debug.log

# Stop all services first
echo "🛑 Stopping existing services..."
./stop.sh

# Wait a moment for cleanup
sleep 3

# Start services
echo "🚀 Starting services..."
./start.sh 