#!/bin/bash

# Token Platform Setup Script
# This script sets up the Token Platform for first-time use

echo "🔧 Token Platform Setup"
echo "========================"

# Check if we're in the right directory
if [ ! -f "requirements.txt" ]; then
    echo "❌ Please run this script from the TokenPlatform directory"
    exit 1
fi

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "📦 Installing pip3..."
    sudo apt update
    sudo apt install python3-pip -y
fi

echo "✅ pip3 found: $(pip3 --version)"

# Create virtual environment
echo "🔧 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Copy contract files from T-REX project
echo "📋 Setting up contracts..."
python setup_contracts.py

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run './start.sh' to start the Token Platform"
echo "2. Open http://localhost:5000 in your browser"
echo "3. Register as an issuer and deploy your first token!"
echo "" 