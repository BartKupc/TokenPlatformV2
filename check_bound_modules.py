#!/usr/bin/env python3
"""
Simple script to check what modules are bound to the compliance contract
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models.token import Token
from services.web3_service import Web3Service

def check_bound_modules():
    with app.app_context():
        print("🔍 CHECKING BOUND MODULES")
        print("=" * 40)
        
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
        for i, module_addr in enumerate(bound_modules):
            print(f"   Module {i+1}: {module_addr}")
            
            # Check if module is bound and identify type by testing unique functions
            module_type = None
            is_bound = False
            module_contract = None
            
            # Try to identify module type by testing unique functions
            print(f"      🔍 Testing module functions...")
            
            # Test CountryAllowModule by trying isCountryAllowed function
            try:
                with open('artifacts/contracts/compliance/modular/modules/CountryAllowModule.sol/CountryAllowModule.json', 'r') as f:
                    artifact = json.load(f)
                    abi = artifact['abi']
                
                test_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                # Try a function unique to CountryAllowModule
                test_contract.functions.isCountryAllowed(token.compliance_address, 250).call()
                module_type = "CountryAllowModule"
                module_contract = test_contract
                print(f"      ✅ Identified as CountryAllowModule")
            except Exception as e:
                print(f"      ❌ Not CountryAllowModule: {str(e)[:50]}...")
            
            # Test SupplyLimitModule by trying getSupplyLimit function
            if not module_type:
                try:
                    with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                    
                    test_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                    # Try a function unique to SupplyLimitModule
                    test_contract.functions.getSupplyLimit(token.token_address).call()
                    module_type = "SupplyLimitModule"
                    module_contract = test_contract
                    print(f"      ✅ Identified as SupplyLimitModule")
                except Exception as e:
                    print(f"      ❌ Not SupplyLimitModule: {str(e)[:50]}...")
            
            # Test TimeTransfersLimitsModule by trying getTimeTransferLimits function
            if not module_type:
                try:
                    with open('artifacts/contracts/compliance/modular/modules/TimeTransfersLimitsModule.sol/TimeTransfersLimitsModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                    
                    test_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                    # Try a function unique to TimeTransfersLimitsModule
                    test_contract.functions.getTimeTransferLimits(token.token_address).call()
                    module_type = "TimeTransfersLimitsModule"
                    module_contract = test_contract
                    print(f"      ✅ Identified as TimeTransfersLimitsModule")
                except Exception as e:
                    print(f"      ❌ Not TimeTransfersLimitsModule: {str(e)[:50]}...")
            
            if not module_type:
                print(f"      ❌ Could not identify module type")
                continue
                
            print(f"      📋 Module Type: {module_type}")
            
            # Now check if it's bound to compliance
            try:
                is_bound = module_contract.functions.isComplianceBound(token.compliance_address).call()
                print(f"      🔗 Bound to compliance: {is_bound}")
            except Exception as e:
                print(f"      ❌ Error checking if bound: {e}")
                is_bound = False
            
            # Test moduleCheck if bound
            if is_bound:
                try:
                    result = module_contract.functions.moduleCheck(
                        "0x0000000000000000000000000000000000000000",
                        "0x0000000000000000000000000000000000000001", 
                        1000000000000000000,
                        token.token_address
                    ).call()
                    print(f"      ✅ moduleCheck result: {result}")
                except Exception as e:
                    print(f"      ❌ moduleCheck error: {e}")
            else:
                print(f"      ❌ Module not bound to compliance")

if __name__ == "__main__":
    import json
    check_bound_modules()
