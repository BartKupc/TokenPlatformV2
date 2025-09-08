#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def debug_supply_correct_abi():
    """Debug SupplyLimitModule using correct ABI functions"""
    
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
        
        print(f"🔍 Debugging SupplyLimitModule with correct ABI functions")
        print(f"   Token: {token.name}")
        print(f"   Token Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Get token contract
        token_contract = web3_service.w3.eth.contract(
            address=token.token_address,
            abi=web3_service.get_contract_abi('Token')
        )
        
        # Get current token supply
        try:
            total_supply = token_contract.functions.totalSupply().call()
            print(f"   📊 Token total supply: {total_supply}")
            print(f"   📊 Token total supply (tokens): {total_supply / 10**18}")
        except Exception as e:
            print(f"   ❌ Error getting token total supply: {e}")
        
        # Get bound modules
        compliance_contract = web3_service.w3.eth.contract(
            address=token.compliance_address,
            abi=web3_service.get_contract_abi('ModularCompliance')
        )
        
        modules = compliance_contract.functions.getModules().call()
        
        # Test Module 2 (SupplyLimitModule)
        if len(modules) >= 2:
            module_address = modules[1]  # Second module
            print(f"\n🔧 SUPPLY LIMIT MODULE: {module_address}")
            print("=" * 50)
            
            # Load SupplyLimitModule ABI
            with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Test all available functions from the ABI
            print(f"\n📋 Testing all available functions:")
            
            # 1. getSupplyLimit
            try:
                supply_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   ✅ getSupplyLimit: {supply_limit}")
                print(f"   ✅ getSupplyLimit (tokens): {supply_limit / 10**18}")
            except Exception as e:
                print(f"   ❌ getSupplyLimit error: {e}")
            
            # 2. isComplianceBound
            try:
                is_bound = module_contract.functions.isComplianceBound(token.compliance_address).call()
                print(f"   ✅ isComplianceBound: {is_bound}")
            except Exception as e:
                print(f"   ❌ isComplianceBound error: {e}")
            
            # 3. canComplianceBind
            try:
                can_bind = module_contract.functions.canComplianceBind(token.compliance_address).call()
                print(f"   ✅ canComplianceBind: {can_bind}")
            except Exception as e:
                print(f"   ❌ canComplianceBind error: {e}")
            
            # 4. name
            try:
                name = module_contract.functions.name().call()
                print(f"   ✅ name: {name}")
            except Exception as e:
                print(f"   ❌ name error: {e}")
            
            # 5. owner
            try:
                owner = module_contract.functions.owner().call()
                print(f"   ✅ owner: {owner}")
            except Exception as e:
                print(f"   ❌ owner error: {e}")
            
            # 6. isPlugAndPlay
            try:
                is_plug_and_play = module_contract.functions.isPlugAndPlay().call()
                print(f"   ✅ isPlugAndPlay: {is_plug_and_play}")
            except Exception as e:
                print(f"   ❌ isPlugAndPlay error: {e}")
            
            # 7. proxiableUUID
            try:
                uuid = module_contract.functions.proxiableUUID().call()
                print(f"   ✅ proxiableUUID: {uuid.hex()}")
            except Exception as e:
                print(f"   ❌ proxiableUUID error: {e}")
            
            # Test moduleCheck with different scenarios
            print(f"\n🔍 Testing moduleCheck scenarios:")
            test_address = "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a"  # EU investor
            
            # Test with 0 tokens (should pass)
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    0,  # amount (0 tokens)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 0 tokens: {result}")
            except Exception as e:
                print(f"   ❌ moduleCheck with 0 tokens error: {e}")
            
            # Test with 1 token
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    1 * 10**18,  # amount (1 token)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 1 token: {result}")
            except Exception as e:
                print(f"   ❌ moduleCheck with 1 token error: {e}")
            
            # Test with 50 tokens
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    50 * 10**18,  # amount (50 tokens)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 50 tokens: {result}")
            except Exception as e:
                print(f"   ❌ moduleCheck with 50 tokens error: {e}")
            
            # Test with 100 tokens (should pass if limit is 100)
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    100 * 10**18,  # amount (100 tokens)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 100 tokens: {result}")
            except Exception as e:
                print(f"   ❌ moduleCheck with 100 tokens error: {e}")
            
            # Test with 101 tokens (should fail if limit is 100)
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    101 * 10**18,  # amount (101 tokens)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 101 tokens: {result}")
            except Exception as e:
                print(f"   ❌ moduleCheck with 101 tokens error: {e}")
        
        print(f"\n✅ SupplyLimitModule debug with correct ABI completed!")

if __name__ == "__main__":
    debug_supply_correct_abi()
