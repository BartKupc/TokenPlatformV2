#!/usr/bin/env python3
"""
Test script to check if compliance modules are properly configured
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models.token import Token
from services.web3_service import Web3Service
import json

def test_module_configuration():
    with app.app_context():
        print("🔍 TESTING MODULE CONFIGURATION")
        print("=" * 50)
        
        # Get token bart3 (Token ID 10) that had 3 modules
        token = Token.query.get(10)
        if not token:
            print("❌ No token found with ID 10")
            return
            
        print(f"📋 Token: {token.name} ({token.symbol})")
        print(f"   Compliance: {token.compliance_address}")
        
        # Initialize Web3 service
        web3_service = Web3Service()
        
        # Get compliance contract to find bound modules
        compliance_contract = web3_service.get_contract(token.compliance_address, "ModularCompliance")
        bound_modules = compliance_contract.functions.getModules().call()
        
        print(f"\n📋 Bound modules: {len(bound_modules)}")
        
        # Test each module's configuration
        for i, module_addr in enumerate(bound_modules):
            print(f"\n🔧 MODULE {i+1}: {module_addr}")
            print("-" * 40)
            
            # Test CountryAllowModule
            if i == 0:  # First module should be CountryAllowModule
                try:
                    with open('artifacts/contracts/compliance/modular/modules/CountryAllowModule.sol/CountryAllowModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                    
                    module_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                    
                    # Check if EU (250) is allowed
                    is_eu_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 250).call()
                    print(f"   🌍 EU (250) allowed: {is_eu_allowed}")
                    
                    # Check if US (840) is allowed
                    is_us_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 840).call()
                    print(f"   🇺🇸 US (840) allowed: {is_us_allowed}")
                    
                    # Test moduleCheck with EU investor
                    try:
                        result = module_contract.functions.moduleCheck(
                            "0x0000000000000000000000000000000000000000",  # from
                            "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",  # to (EU investor)
                            1000000000000000000,  # amount
                            token.compliance_address  # compliance address
                        ).call()
                        print(f"   ✅ moduleCheck with EU investor: {result}")
                    except Exception as e:
                        print(f"   ❌ moduleCheck error: {e}")
                        
                except Exception as e:
                    print(f"   ❌ Error testing CountryAllowModule: {e}")
            
            # Test SupplyLimitModule
            elif i == 1:  # Second module should be SupplyLimitModule
                try:
                    with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                    
                    module_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                    
                    # Check supply limit
                    try:
                        supply_limit = module_contract.functions.getSupplyLimit(token.token_address).call()
                        print(f"   📊 Supply limit: {supply_limit}")
                    except Exception as e:
                        print(f"   ❌ Error getting supply limit: {e}")
                    
                    # Check per-user limit
                    try:
                        per_user_limit = module_contract.functions.getPerUserLimit(token.token_address).call()
                        print(f"   👤 Per-user limit: {per_user_limit}")
                    except Exception as e:
                        print(f"   ❌ Error getting per-user limit: {e}")
                    
                    # Test moduleCheck
                    try:
                        result = module_contract.functions.moduleCheck(
                            "0x0000000000000000000000000000000000000000",  # from
                            "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",  # to
                            1000000000000000000,  # amount
                            token.compliance_address  # compliance address
                        ).call()
                        print(f"   ✅ moduleCheck: {result}")
                    except Exception as e:
                        print(f"   ❌ moduleCheck error: {e}")
                        
                except Exception as e:
                    print(f"   ❌ Error testing SupplyLimitModule: {e}")
            
            # Test TimeTransfersLimitsModule
            elif i == 2:  # Third module should be TimeTransfersLimitsModule
                try:
                    with open('artifacts/contracts/compliance/modular/modules/TimeTransfersLimitsModule.sol/TimeTransfersLimitsModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                    
                    module_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                    
                    # Check time transfer limits
                    try:
                        limits = module_contract.functions.getTimeTransferLimits(token.token_address).call()
                        print(f"   ⏰ Time transfer limits: {limits}")
                    except Exception as e:
                        print(f"   ❌ Error getting time transfer limits: {e}")
                    
                    # Test moduleCheck
                    try:
                        result = module_contract.functions.moduleCheck(
                            "0x0000000000000000000000000000000000000000",  # from
                            "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",  # to
                            1000000000000000000,  # amount
                            token.compliance_address  # compliance address
                        ).call()
                        print(f"   ✅ moduleCheck: {result}")
                    except Exception as e:
                        print(f"   ❌ moduleCheck error: {e}")
                        
                except Exception as e:
                    print(f"   ❌ Error testing TimeTransfersLimitsModule: {e}")

if __name__ == "__main__":
    test_module_configuration()
