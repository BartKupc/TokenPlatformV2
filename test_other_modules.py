#!/usr/bin/env python3
"""
Test script to check why SupplyLimitModule and TimeTransfersLimitsModule are failing.
Focus on checking if they're properly configured and using correct ABIs.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models.token import Token
from services.web3_service import Web3Service
import json

def test_other_modules():
    with app.app_context():
        print("🔍 TESTING SUPPLY LIMIT AND TIME TRANSFER MODULES")
        print("=" * 60)
        
        # Get the latest token (Token ID 11 - ghjghj)
        token = Token.query.get(11)
        if not token:
            print("❌ No token found with ID 11")
            return
            
        print(f"📋 Token: {token.name} ({token.symbol})")
        print(f"   Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Initialize Web3 service
        web3_service = Web3Service()
        
        # Get compliance contract to find bound modules
        compliance_contract = web3_service.get_contract(token.compliance_address, "ModularCompliance")
        bound_modules = compliance_contract.functions.getModules().call()
        print(f"\n📋 Bound modules: {len(bound_modules)}")
        
        # Test each module
        for i, module_addr in enumerate(bound_modules):
            print(f"\n🔧 MODULE {i+1}: {module_addr}")
            print("-" * 40)
            
            # Check if it's bound to compliance
            try:
                # Try to determine module type by testing different ABIs
                module_type = None
                module_contract = None
                
                # Test SupplyLimitModule ABI
                try:
                    with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                    
                    test_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                    # Try to call a function that should exist
                    is_bound = test_contract.functions.isComplianceBound(token.compliance_address).call()
                    if is_bound:
                        module_type = "SupplyLimitModule"
                        module_contract = test_contract
                        print(f"   ✅ Identified as SupplyLimitModule")
                except Exception as e:
                    print(f"   ❌ Not SupplyLimitModule: {e}")
                
                # Test TimeTransfersLimitsModule ABI
                if not module_type:
                    try:
                        with open('artifacts/contracts/compliance/modular/modules/TimeTransfersLimitsModule.sol/TimeTransfersLimitsModule.json', 'r') as f:
                            artifact = json.load(f)
                            abi = artifact['abi']
                        
                        test_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                        # Try to call a function that should exist
                        is_bound = test_contract.functions.isComplianceBound(token.compliance_address).call()
                        if is_bound:
                            module_type = "TimeTransfersLimitsModule"
                            module_contract = test_contract
                            print(f"   ✅ Identified as TimeTransfersLimitsModule")
                    except Exception as e:
                        print(f"   ❌ Not TimeTransfersLimitsModule: {e}")
                
                # Test CountryAllowModule ABI
                if not module_type:
                    try:
                        with open('artifacts/contracts/compliance/modular/modules/CountryAllowModule.sol/CountryAllowModule.json', 'r') as f:
                            artifact = json.load(f)
                            abi = artifact['abi']
                        
                        test_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                        # Try to call a function that should exist
                        is_bound = test_contract.functions.isComplianceBound(token.compliance_address).call()
                        if is_bound:
                            module_type = "CountryAllowModule"
                            module_contract = test_contract
                            print(f"   ✅ Identified as CountryAllowModule")
                    except Exception as e:
                        print(f"   ❌ Not CountryAllowModule: {e}")
                
                if not module_type:
                    print(f"   ❌ Could not identify module type")
                    continue
                
                print(f"   📋 Module Type: {module_type}")
                print(f"   🔗 Bound to compliance: {is_bound}")
                
                # Test moduleCheck function with correct parameters
                try:
                    print(f"   🧪 Testing moduleCheck function:")
                    test_address = "0x0000000000000000000000000000000000000001"
                    module_result = module_contract.functions.moduleCheck(
                        "0x0000000000000000000000000000000000000000",  # from (minting)
                        test_address,  # to
                        1000000000000000000,  # amount (1 token in wei)
                        token.token_address  # token address
                    ).call()
                    print(f"      moduleCheck result: {module_result}")
                    
                    if module_result:
                        print(f"      ✅ Module allows transfer")
                    else:
                        print(f"      ❌ Module blocks transfer")
                        
                except Exception as e:
                    print(f"      ❌ Error testing moduleCheck: {e}")
                
                # Test specific functions based on module type
                if module_type == "SupplyLimitModule":
                    print(f"   📊 Testing SupplyLimitModule specific functions:")
                    try:
                        # Try to get supply limit with token address parameter
                        supply_limit = module_contract.functions.getSupplyLimit(token.token_address).call()
                        print(f"      Supply limit: {supply_limit}")
                    except Exception as e:
                        print(f"      ❌ Error getting supply limit: {e}")
                    
                    try:
                        # Try to get per-user limit with token address parameter
                        per_user_limit = module_contract.functions.getPerUserLimit(token.token_address).call()
                        print(f"      Per-user limit: {per_user_limit}")
                    except Exception as e:
                        print(f"      ❌ Error getting per-user limit: {e}")
                    
                    try:
                        # Try to get current supply
                        current_supply = module_contract.functions.getCurrentSupply(token.token_address).call()
                        print(f"      Current supply: {current_supply}")
                    except Exception as e:
                        print(f"      ❌ Error getting current supply: {e}")
                
                elif module_type == "TimeTransfersLimitsModule":
                    print(f"   ⏰ Testing TimeTransfersLimitsModule specific functions:")
                    try:
                        # Try to get cooldown period with token address parameter
                        cooldown = module_contract.functions.getCooldownPeriod(token.token_address).call()
                        print(f"      Cooldown period: {cooldown} seconds")
                    except Exception as e:
                        print(f"      ❌ Error getting cooldown period: {e}")
                    
                    try:
                        # Try to get transfer limit with token address parameter
                        transfer_limit = module_contract.functions.getTransferLimit(token.token_address).call()
                        print(f"      Transfer limit: {transfer_limit}")
                    except Exception as e:
                        print(f"      ❌ Error getting transfer limit: {e}")
                    
                    try:
                        # Try to get last transfer time
                        test_address = "0x0000000000000000000000000000000000000001"
                        last_transfer = module_contract.functions.getLastTransferTime(token.token_address, test_address).call()
                        print(f"      Last transfer time for test address: {last_transfer}")
                    except Exception as e:
                        print(f"      ❌ Error getting last transfer time: {e}")
                
            except Exception as e:
                print(f"   ❌ Error testing module {module_addr}: {e}")

if __name__ == "__main__":
    test_other_modules()
