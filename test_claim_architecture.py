#!/usr/bin/env python3
"""
Test Script for T-REX Claim Architecture
Tests the correct setup: investor OnchainID with only Account 0 as management key,
trusted issuer added as management key and claim signer to ClaimIssuer contract.
"""

import os
import sys
import json
import subprocess
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import app, db
from models.user import User
from models.enhanced_models import OnchainIDKey

def get_test_environment():
    """Get the test environment from database using provided wallet addresses"""
    print("🔍 Querying test environment from database...")
    
    # You can change these addresses here
    TRUSTED_ISSUER_WALLET = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
    INVESTOR_WALLET = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
    
    print(f"🎯 Looking for:")
    print(f"   Trusted Issuer: {TRUSTED_ISSUER_WALLET}")
    print(f"   Investor: {INVESTOR_WALLET}")
    
    with app.app_context():
        # Find users by wallet address
        trusted_issuer = User.query.filter_by(wallet_address=TRUSTED_ISSUER_WALLET).first()
        investor = User.query.filter_by(wallet_address=INVESTOR_WALLET).first()
        
        if not trusted_issuer:
            raise Exception(f"No user found with wallet address {TRUSTED_ISSUER_WALLET}")
        
        if not investor:
            raise Exception(f"No user found with wallet address {INVESTOR_WALLET}")
        
        print(f"✅ Found trusted issuer: {trusted_issuer.username} ({trusted_issuer.wallet_address})")
        print(f"✅ Found investor: {investor.username} ({investor.wallet_address})")
        
        # Check if they have OnchainIDs
        if not trusted_issuer.onchain_id:
            raise Exception(f"Trusted issuer {trusted_issuer.username} has no OnchainID")
        
        if not investor.onchain_id:
            raise Exception(f"Investor {investor.username} has no OnchainID")
        
        print(f"✅ Trusted issuer OnchainID: {trusted_issuer.onchain_id}")
        print(f"✅ Investor OnchainID: {investor.onchain_id}")
        
        # Check if trusted issuer has ClaimIssuer contract
        if not trusted_issuer.claim_issuer_address:
            raise Exception(f"Trusted issuer {trusted_issuer.username} has no ClaimIssuer contract")
        
        print(f"✅ ClaimIssuer contract: {trusted_issuer.claim_issuer_address}")
        
        print("🎉 Test environment found!")
        print(f"📋 Test Summary:")
        print(f"   Trusted Issuer: {trusted_issuer.username} ({trusted_issuer.wallet_address})")
        print(f"   Trusted Issuer OnchainID: {trusted_issuer.onchain_id}")
        print(f"   ClaimIssuer Contract: {trusted_issuer.claim_issuer_address}")
        print(f"   Investor: {investor.username} ({investor.wallet_address})")
        print(f"   Investor OnchainID: {investor.onchain_id}")
        
        return {
            'trusted_issuer': trusted_issuer,
            'investor': investor,
            'trusted_issuer_onchainid': trusted_issuer.onchain_id,
            'investor_onchainid': investor.onchain_id,
            'claimissuer_address': trusted_issuer.claim_issuer_address
        }

def test_claim_architecture(test_data):
    """Test the claim architecture by running the JavaScript test"""
    print("🧪 Testing claim architecture...")
    
    # Update the config file with actual addresses
    update_test_config(test_data)
    
    # Run the JavaScript test
    js_test_path = project_root / "test_claim_architecture.js"
    
    if not js_test_path.exists():
        print("❌ JavaScript test file not found")
        return False
    
    try:
        # Run through Hardhat instead of directly with node
        result = subprocess.run(
            ['npx', 'hardhat', 'run', str(js_test_path), '--network', 'localhost'],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode == 0:
            print("✅ JavaScript test completed successfully")
            print("📋 Output:")
            print(result.stdout)
            return True
        else:
            print("❌ JavaScript test failed")
            print("📋 Full output (stdout):")
            print(result.stdout)
            print("📋 Error output (stderr):")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Error running JavaScript test: {e}")
        return False

def update_test_config(test_data):
    """Update the config file with actual addresses from the test setup"""
    print("📝 Updating test config with actual addresses...")
    
    config_path = project_root / "test_config.json"
    
    if not config_path.exists():
        print("❌ Test config file not found")
        return
    
    # Create config data with all addresses and private keys
    config_data = {
        "trusted_issuer_onchainid": test_data["trusted_issuer_onchainid"],
        "investor_onchainid": test_data["investor_onchainid"],
        "claimissuer_address": test_data["claimissuer_address"],
        "test_topic": 1,
        "test_claim_data": "APPROVED",
        # Hardcoded Hardhat accounts for testing
        "deployer_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "deployer_private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "trusted_issuer_address": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        "trusted_issuer_private_key": "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        "investor_address": "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
        "investor_private_key": "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
    }
    
    # Write the config file
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    print("✅ Test config updated with actual addresses")

if __name__ == "__main__":
    try:
        print("🚀 Starting T-REX Claim Architecture Test")
        print("=" * 50)
        
        # Get test environment from database
        test_data = get_test_environment()
        
        print("\n" + "=" * 50)
        print("🧪 Running claim architecture test...")
        
        # Test the architecture
        success = test_claim_architecture(test_data)
        
        if success:
            print("\n🎉 All tests passed! The claim architecture is working correctly.")
        else:
            print("\n❌ Tests failed. Check the output above for details.")
            
    except Exception as e:
        print(f"\n💥 Test failed: {e}")
        import traceback
        traceback.print_exc()