#!/bin/bash

# Token Platform Stop Script
# This script stops all Token Platform services

echo "🛑 Stopping Token Platform..."

# Stop Flask application
echo "   Stopping Flask application..."
pkill -f "python.*app.py" 2>/dev/null
pkill -f "flask" 2>/dev/null

# Stop Hardhat node
echo "   Stopping Hardhat node..."
pkill -f "hardhat node" 2>/dev/null
pkill -f "npm.*hardhat" 2>/dev/null

# Wait a moment for processes to stop
sleep 2

# Check if processes are still running
FLASK_RUNNING=$(pgrep -f "python.*app.py" | wc -l)
HARDHAT_RUNNING=$(pgrep -f "hardhat" | wc -l)

if [ $FLASK_RUNNING -eq 0 ] && [ $HARDHAT_RUNNING -eq 0 ]; then
    echo "✅ Token Platform stopped successfully"
else
    echo "⚠️  Some processes may still be running:"
    if [ $FLASK_RUNNING -gt 0 ]; then
        echo "   - Flask app: $FLASK_RUNNING process(es)"
    fi
    if [ $HARDHAT_RUNNING -gt 0 ]; then
        echo "   - Hardhat: $HARDHAT_RUNNING process(es)"
    fi
    echo "   You can force kill with: pkill -9 -f 'python.*app.py' && pkill -9 -f 'hardhat'"
fi

echo ""
echo "📊 Port Status:"
echo "   Port 5000 (Flask): $(netstat -tlnp 2>/dev/null | grep :5000 | wc -l | tr -d ' ') listener(s)"
echo "   Port 8545 (Hardhat): $(netstat -tlnp 2>/dev/null | grep :8545 | wc -l | tr -d ' ') listener(s)" 