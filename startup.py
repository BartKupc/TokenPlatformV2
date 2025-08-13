#!/usr/bin/env python3
"""
Token Platform Startup Script
Handles the complete startup flow:
1. Start Hardhat node
2. Deploy T-REX factory and contracts
3. Copy contract addresses to Token Platform
4. Start Flask application
"""

import subprocess
import time
import json
import os
import signal
import sys
from pathlib import Path
import requests
from threading import Thread

class TokenPlatformStartup:
    def __init__(self):
        self.platform_path = Path(__file__).parent
        self.hardhat_process = None
        self.flask_process = None
        
    def print_banner(self):
        """Print startup banner"""
        print("=" * 60)
        print("🚀 TOKEN PLATFORM STARTUP")
        print("=" * 60)
        print("This script will:")
        print("1. Start TokenPlatform Hardhat blockchain node")
        print("2. Deploy T-REX factory using Python script")
        print("3. Start Flask web application")
        print("=" * 60)
        print()
    
    def check_prerequisites(self):
        """Check if all prerequisites are met"""
        print("🔍 Checking prerequisites...")
        
        # Check if TokenPlatform has required files
        if not (self.platform_path / 'hardhat.config.js').exists():
            print("❌ Hardhat config not found. Please run setup first.")
            return False
        
        # Check if Node.js is installed
        try:
            subprocess.run(['node', '--version'], check=True, capture_output=True)
            print("✅ Node.js found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Node.js not found. Please install Node.js first.")
            return False
        
        # Check if npm is installed
        try:
            subprocess.run(['npm', '--version'], check=True, capture_output=True)
            print("✅ npm found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ npm not found. Please install npm first.")
            return False
        
        # Check if Python virtual environment exists
        venv_path = self.platform_path / 'venv'
        if not venv_path.exists():
            print("❌ Python virtual environment not found. Please run setup first.")
            return False
        
        print("✅ All prerequisites met!")
        return True
    
    def start_hardhat_node(self):
        """Start TokenPlatform Hardhat node in background"""
        print("🔗 Starting TokenPlatform Hardhat node...")
        
        try:
            # Start Hardhat node from TokenPlatform directory
            self.hardhat_process = subprocess.Popen(
                ['npx', 'hardhat', 'node', '--hostname', '0.0.0.0'],
                cwd=self.platform_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for node to start
            print("⏳ Waiting for Hardhat node to start...")
            time.sleep(7)  # Give more time for Hardhat to initialize
            
            # Check if node is running using JSON-RPC with retries
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    response = requests.post(
                        'http://localhost:8545',
                        json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
                        headers={"Content-Type": "application/json"},
                        timeout=10
                    )
                    if response.status_code == 200:
                        result = response.json()
                        if 'result' in result:
                            print(f"✅ Hardhat node is running on http://localhost:8545 (attempt {attempt + 1})")
                            return True
                        else:
                            print(f"❌ Hardhat node response invalid (attempt {attempt + 1})")
                    else:
                        print(f"❌ Hardhat node not responding (status: {response.status_code}, attempt {attempt + 1})")
                        
                except requests.exceptions.RequestException as e:
                    print(f"❌ Failed to connect to Hardhat node (attempt {attempt + 1}): {e}")
                
                if attempt < max_retries - 1:
                    print(f"⏳ Retrying in 3 seconds... ({attempt + 1}/{max_retries})")
                    time.sleep(3)
            
            print("❌ Failed to start Hardhat node after all retries")
            return False
            
        except Exception as e:
            print(f"❌ Error starting Hardhat node: {e}")
            return False
    
    def create_database_schema(self):
        """Create database with proper schema first"""
        print("🗄️  Creating database schema...")
        
        try:
            # Create database schema using Flask app
            result = subprocess.run(
                [f'{self.platform_path}/venv/bin/python', '-c', 'from app import app; app.app_context().push(); print("Database schema created")'],
                cwd=self.platform_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print("✅ Database schema created successfully")
                return True
            else:
                print(f"❌ Database schema creation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Database schema creation timed out")
            return False
        except Exception as e:
            print(f"❌ Error creating database schema: {e}")
            return False

    def deploy_trex_contracts(self):
        """Deploy T-REX factory using Python script"""
        print("🏭 Deploying T-REX factory using Python script...")
        
        try:
            # Deploy factory using our Python script
            result = subprocess.run(
                [f'{self.platform_path}/venv/bin/python', 'scripts/deploy_factory.py'],
                cwd=self.platform_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                print("✅ TREX factory deployed successfully using Python script")
                return True
            else:
                print(f"❌ Factory deployment failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Factory deployment timed out")
            return False
        except Exception as e:
            print(f"❌ Error deploying factory: {e}")
            return False
    
    def copy_contract_addresses(self):
        """Contract addresses are now stored directly in database by Python script"""
        print("📋 Contract addresses stored directly in database by Python script")
        return True
    
    def start_flask_app(self):
        """Start Flask application"""
        print("🌐 Starting Flask application...")
        
        try:
            # Activate virtual environment and start Flask
            self.flask_process = subprocess.Popen(
                [f'{self.platform_path}/venv/bin/python', 'app.py'],
                cwd=self.platform_path,
                # Remove stdout and stderr redirection to see logs
                text=True
            )
            
            # Wait for Flask to start
            print("⏳ Waiting for Flask app to start...")
            time.sleep(3)
            
            # Check if Flask is running
            try:
                response = requests.get('http://localhost:5000', timeout=5)
                if response.status_code == 200:
                    print("✅ Flask application is running on http://localhost:5000")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            # Wait a bit more
            time.sleep(5)
            
            try:
                response = requests.get('http://localhost:5000', timeout=5)
                if response.status_code == 200:
                    print("✅ Flask application is running on http://localhost:5000")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            # Try a different approach - check if port is listening
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('localhost', 5000))
                sock.close()
                if result == 0:
                    print("✅ Flask application is running on http://localhost:5000")
                    return True
            except:
                pass
            
            print("❌ Failed to start Flask application")
            return False
            
        except Exception as e:
            print(f"❌ Error starting Flask app: {e}")
            return False
    
    def print_success_info(self):
        """Print success information and next steps"""
        print()
        print("=" * 60)
        print("🎉 TOKEN PLATFORM STARTED SUCCESSFULLY!")
        print("=" * 60)
        print()
        # Load configuration
        try:
            import json
            config_path = Path(__file__).parent / 'config.json'
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
                flask_url = config.get('FLASK_URL', 'http://localhost:5000')
                hardhat_url = config.get('HARDHAT_URL', 'http://localhost:8545')
            else:
                flask_url = 'http://localhost:5000'
                hardhat_url = 'http://localhost:8545'
        except Exception as e:
            flask_url = 'http://localhost:5000'
            hardhat_url = 'http://localhost:8545'
        
        print("📱 Access your platform:")
        print(f"   🌐 Web Interface: {flask_url}")
        print(f"   🔗 Blockchain Node: {hardhat_url}")
        print()
        print("👥 Next Steps:")
        print(f"   1. Open {flask_url} in your browser")
        print("   2. Register as an issuer (startup)")
        print("   3. Deploy your first security token")
        print("   4. Have investors complete KYC onboarding")
        print("   5. Start fundraising!")
        print()
        print("🧪 For Testing:")
        print("   - Sample token deployment is available for testing")
        print("   - Use the admin dashboard to approve KYC applications")
        print()
        print("🔧 Development Info:")
        print("   - Hardhat Node: Running on port 8545")
        print("   - Flask App: Running on port 5000")
        print("   - Database: SQLite (fundraising.db)")
        print("   - Contracts: T-REX ERC-3643 deployed")
        print()
        print("🛑 To stop the platform: Press Ctrl+C")
        print("=" * 60)
    
    def cleanup(self):
        """Cleanup processes on exit"""
        print("\n🛑 Shutting down Token Platform...")
        
        if self.flask_process:
            print("   Stopping Flask application...")
            self.flask_process.terminate()
            try:
                self.flask_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.flask_process.kill()
        
        if self.hardhat_process:
            print("   Stopping Hardhat node...")
            self.hardhat_process.terminate()
            try:
                self.hardhat_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.hardhat_process.kill()
        
        print("✅ Token Platform stopped")
    
    def run(self):
        """Run the complete startup process"""
        try:
            self.print_banner()
            
            # Check prerequisites
            if not self.check_prerequisites():
                return False
            
            # Start Hardhat node
            if not self.start_hardhat_node():
                return False
            
            # Create database schema first
            if not self.create_database_schema():
                return False
            
            # Deploy T-REX contracts
            if not self.deploy_trex_contracts():
                return False
            
            # Copy contract addresses
            if not self.copy_contract_addresses():
                return False
            
            # Start Flask app
            if not self.start_flask_app():
                return False
            
            # Print success info
            self.print_success_info()
            
            # Keep running until interrupted
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            
            return True
            
        except Exception as e:
            print(f"❌ Startup failed: {e}")
            return False
        finally:
            self.cleanup()

def main():
    """Main function"""
    startup = TokenPlatformStartup()
    
    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        print("\n🛑 Received interrupt signal")
        startup.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run startup
    success = startup.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 