#!/usr/bin/env python3
"""
Test script to verify trusted issuer addition with correct permissions
"""

import os
import sys
import json
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import app, db
from models.token import Token
from models.user import User
from services.trex_service import TREXService
from services.web3_service import Web3Service

def test_trusted_issuer_addition():
    """Test adding a trusted issuer with the correct account permissions"""
    
    with app.app_context():
        try:
            print("🧪 Testing trusted issuer addition with correct permissions...")
            
            # Get a token and trusted issuer from the database
            token = Token.query.first()
            if not token:
                print("❌ No tokens found in database")
                return
            
            trusted_issuer = User.query.filter_by(user_type='trusted_issuer').first()
            if not trusted_issuer:
                print("❌ No trusted issuers found in database")
                return
            
            print(f"📋 Testing with:")
            print(f"   Token: {token.name} ({token.symbol})")
            print(f"   Token Address: {token.token_address}")
            print(f"   Trusted Issuer: {trusted_issuer.username}")
            print(f"   Trusted Issuer Address: {trusted_issuer.wallet_address}")
            
            # IMPORTANT: We need to use the deployer's private key (Account 0)
            # In Hardhat, this is typically the first account
            # Let's check if we have environment variables for this
            
            deployer_private_key = os.environ.get('DEPLOYER_PRIVATE_KEY')
            if not deployer_private_key:
                print("❌ DEPLOYER_PRIVATE_KEY environment variable not set")
                print("💡 This should be the private key of Account 0 (deployer)")
                return
            
            print(f"🔑 Using deployer private key: {deployer_private_key[:10]}...")
            
            # Initialize services with deployer's private key
            web3_service = Web3Service(deployer_private_key)
            trex_service = TREXService(web3_service)
            
            # Test adding trusted issuer
            print(f"🚀 Testing addTrustedIssuer...")
            
            result = trex_service.add_trusted_issuer_to_token(
                token_address=token.token_address,
                trusted_issuer_address=trusted_issuer.wallet_address,
                claim_topics=[1, 2, 3]  # KYC, AML, Accredited
            )
            
            if result['success']:
                print(f"✅ SUCCESS! Trusted issuer added to blockchain")
                print(f"   Transaction hash: {result['transaction_hash']}")
                print(f"   Block number: {result['block_number']}")
                print(f"   Message: {result['message']}")
            else:
                print(f"❌ FAILED: {result['error']}")
                
        except Exception as e:
            print(f"❌ Test failed with error: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_trusted_issuer_addition() 