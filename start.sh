#!/bin/bash

# Token Platform Startup Script
# This script starts the complete Token Platform environment

echo "🚀 Starting Token Platform..."

# Check if we're in the right directory
if [ ! -f "startup.py" ]; then
    echo "❌ Please run this script from the TokenPlatform directory"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first:"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Check if Node.js dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "❌ Node.js dependencies not found. Please run setup first:"
    echo "   npm install"
    exit 1
fi

# Activate virtual environment and run startup
echo "🔧 Activating virtual environment..."
source venv/bin/activate

echo "🚀 Running startup script..."
echo "   This will:"
echo "   1. Start TokenPlatform Hardhat node"
echo "   2. Deploy T-REX factory using Python script"
echo "   3. Start Flask web application"
echo ""

python startup.py 