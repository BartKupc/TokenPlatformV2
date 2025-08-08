#!/bin/bash

# Token Platform Status Script
# This script checks the status of all Token Platform services

echo "📊 Token Platform Status"
echo "========================"

# Check if we're in the right directory
if [ ! -f "startup.py" ]; then
    echo "❌ Please run this script from the TokenPlatform directory"
    exit 1
fi

# Check Flask application
echo "🌐 Flask Application:"
FLASK_PID=$(pgrep -f "python.*app.py")
if [ -n "$FLASK_PID" ]; then
    echo "   ✅ Running (PID: $FLASK_PID)"
    echo "   📍 URL: http://localhost:5000"
else
    echo "   ❌ Not running"
fi

# Check Hardhat node
echo ""
echo "🔗 Hardhat Node:"
HARDHAT_PID=$(pgrep -f "hardhat node")
if [ -n "$HARDHAT_PID" ]; then
    echo "   ✅ Running (PID: $HARDHAT_PID)"
    echo "   📍 URL: http://localhost:8545"
else
    echo "   ❌ Not running"
fi

# Check ports
echo ""
echo "🔌 Port Status:"
FLASK_PORT=$(netstat -tlnp 2>/dev/null | grep :5000 | wc -l)
HARDHAT_PORT=$(netstat -tlnp 2>/dev/null | grep :8545 | wc -l)

if [ $FLASK_PORT -gt 0 ]; then
    echo "   ✅ Port 5000: Listening (Flask)"
else
    echo "   ❌ Port 5000: Not listening"
fi

if [ $HARDHAT_PORT -gt 0 ]; then
    echo "   ✅ Port 8545: Listening (Hardhat)"
else
    echo "   ❌ Port 8545: Not listening"
fi

# Check database
echo ""
echo "💾 Database:"
if [ -f "fundraising.db" ]; then
    echo "   ✅ SQLite database exists"
    DB_SIZE=$(du -h fundraising.db 2>/dev/null | cut -f1)
    echo "   📏 Size: $DB_SIZE"
else
    echo "   ❌ SQLite database not found"
fi

# Check contracts
echo ""
echo "📋 Contracts:"
if [ -f "contracts/contracts.json" ]; then
    echo "   ✅ Contract addresses loaded"
else
    echo "   ❌ Contract addresses not found"
fi

# Overall status
echo ""
echo "🎯 Overall Status:"
if [ -n "$FLASK_PID" ] && [ -n "$HARDHAT_PID" ]; then
    echo "   ✅ Token Platform is fully operational"
elif [ -n "$FLASK_PID" ] || [ -n "$HARDHAT_PID" ]; then
    echo "   ⚠️  Token Platform is partially running"
else
    echo "   ❌ Token Platform is not running"
fi

echo ""
echo "💡 Commands:"
echo "   ./start.sh    - Start Token Platform"
echo "   ./stop.sh     - Stop Token Platform"
echo "   ./restart.sh  - Restart Token Platform" 