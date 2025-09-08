#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def debug_supply_detailed():
    """Detailed debug of SupplyLimitModule"""
    
    # Create Flask app context
    with app.app_context():
        # Initialize services
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        # Get token info
        token_id = 10  # bart3
        token = Token.query.get(token_id)
        
        if not token:
            print(f"❌ Token {token_id} not found")
            return
        
        print(f"🔍 Detailed debugging of SupplyLimitModule for Token {token_id}")
        print(f"   Token: {token.name}")
        print(f"   Token Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Get bound modules
        compliance_contract = web3_service.w3.eth.contract(
            address=token.compliance_address,
            abi=web3_service.get_contract_abi('ModularCompliance')
        )
        
        modules = compliance_contract.functions.getModules().call()
        print(f"📋 Bound modules: {len(modules)}")
        
        # Test Module 2 (SupplyLimitModule)
        if len(modules) >= 2:
            module_address = modules[1]  # Second module
            print(f"\n🔧 DETAILED DEBUG OF MODULE 2 (SupplyLimitModule): {module_address}")
            print("=" * 60)
            
            # Load SupplyLimitModule ABI
            with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Check if module is bound to compliance
            try:
                is_bound = module_contract.functions.isComplianceBound(token.compliance_address).call()
                print(f"   🔗 Is bound to compliance: {is_bound}")
            except Exception as e:
                print(f"   ❌ Error checking if bound: {e}")
            
            # Check supply limit
            try:
                supply_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 Supply limit: {supply_limit}")
            except Exception as e:
                print(f"   ❌ Error getting supply limit: {e}")
            
            # Check if there are any other relevant functions
            try:
                # Try to get the owner
                owner = module_contract.functions.owner().call()
                print(f"   👤 Owner: {owner}")
            except Exception as e:
                print(f"   ❌ Error getting owner: {e}")
            
            # Check if there are any other functions that might give us info
            try:
                # Try to get the name
                name = module_contract.functions.name().call()
                print(f"   📝 Name: {name}")
            except Exception as e:
                print(f"   ❌ Error getting name: {e}")
            
            # Test moduleCheck with detailed logging
            test_address = "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a"  # EU investor
            
            print(f"\n🔍 Testing moduleCheck with detailed parameters:")
            print(f"   Test address: {test_address}")
            print(f"   From: 0x0000000000000000000000000000000000000000 (minting)")
            print(f"   To: {test_address}")
            print(f"   Compliance: {token.compliance_address}")
            
            # Test with 1 token
            try:
                amount_wei = 1 * 10**18  # 1 token in wei
                print(f"\n   🔍 Testing with 1 token ({amount_wei} wei):")
                
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    amount_wei,  # amount
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 Result: {result}")
                
            except Exception as e:
                print(f"   ❌ Error in moduleCheck: {e}")
            
            # Try to call moduleCheck through the compliance contract
            try:
                print(f"\n   🔍 Testing moduleCheck through compliance contract:")
                
                result = compliance_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    amount_wei,  # amount
                    token.token_address  # token address
                ).call()
                print(f"   📊 Compliance moduleCheck result: {result}")
                
            except Exception as e:
                print(f"   ❌ Error in compliance moduleCheck: {e}")
        
        print(f"\n✅ Detailed SupplyLimitModule debug completed!")

if __name__ == "__main__":
    debug_supply_detailed()
