#!/usr/bin/env python3
"""
Test script to test compliance module deployment flow
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Flask app context
from app import app

from services.web3_service import Web3Service
from services.trex_service import TREXService

def test_compliance_deployment():
    """Test compliance module deployment flow"""
    
    print("🧪 Testing Compliance Module Deployment Flow")
    print("=" * 60)
    
    # Test compliance modules configuration
    compliance_modules = [
        {
            'type': 'CountryRestrictModule',
            'config': {
                'allowed_countries': [840, 250, 826]  # US, EU, UK
            }
        },
        {
            'type': 'SupplyLimitModule',
            'config': {
                'supply_limit': 1000000  # 1M tokens
            }
        },
        {
            'type': 'TimeTransfersLimitsModule',
            'config': {
                'cooldown_period': 300  # 5 minutes
            }
        }
    ]
    
    deployer_address = "0xdD2FD4581271e230360230F9337D5c0430Bf44C0"
    
    try:
        # Create Web3Service
        print("🔗 Creating Web3Service...")
        web3_service = Web3Service()
        
        # Create TREXService
        print("🔗 Creating TREXService...")
        trex_service = TREXService(web3_service)
        
        # Test compliance module deployment
        print("\n🔧 Testing compliance module deployment...")
        result = trex_service.deploy_compliance_modules(compliance_modules, deployer_address)
        
        if result['success']:
            print("✅ Compliance modules deployed successfully!")
            print(f"   Deployed {len(result['modules'])} modules:")
            for i, module in enumerate(result['modules']):
                print(f"     {i+1}. {module['type']}: {module['address']}")
                print(f"        Config: {module['config']}")
        else:
            print(f"❌ Failed to deploy compliance modules: {result.get('error', 'Unknown error')}")
            return
        
        # Test token deployment with compliance modules
        print("\n🔧 Testing token deployment with compliance modules...")
        
        token_deployment_result = trex_service.build_deployment_transaction(
            deployer_address=deployer_address,
            token_name="Test Compliance Token",
            token_symbol="TCT",
            total_supply="1000000",
            claim_topics=["1", "2"],
            claim_issuer_address="0x1234567890123456789012345678901234567890",
            compliance_modules=compliance_modules
        )
        
        if token_deployment_result['success']:
            print("✅ Token deployment transaction built successfully!")
            print(f"   Transaction includes compliance modules: {len(compliance_modules)}")
        else:
            print(f"❌ Failed to build token deployment: {token_deployment_result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    with app.app_context():
        test_compliance_deployment()