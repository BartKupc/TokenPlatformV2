#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def debug_supply_sync():
    """Debug supply synchronization between token and SupplyLimitModule"""
    
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
        
        print(f"🔍 Debugging supply synchronization for Token {token_id}")
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
            
            # Check supply limit
            try:
                supply_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 Supply limit: {supply_limit}")
                print(f"   📊 Supply limit (tokens): {supply_limit / 10**18}")
            except Exception as e:
                print(f"   ❌ Error getting supply limit: {e}")
            
            # Check if there's a function to get current supply from the module
            try:
                # Try to get current supply from module
                current_supply = module_contract.functions.getCurrentSupply(token.compliance_address).call()
                print(f"   📊 Module current supply: {current_supply}")
                print(f"   📊 Module current supply (tokens): {current_supply / 10**18}")
            except Exception as e:
                print(f"   ❌ Error getting module current supply: {e}")
            
            # Check if there's a function to get remaining supply
            try:
                # Try to get remaining supply
                remaining_supply = module_contract.functions.getRemainingSupply(token.compliance_address).call()
                print(f"   📊 Module remaining supply: {remaining_supply}")
                print(f"   📊 Module remaining supply (tokens): {remaining_supply / 10**18}")
            except Exception as e:
                print(f"   ❌ Error getting module remaining supply: {e}")
            
            # Test if the issue is with the moduleCheck logic
            print(f"\n🔍 Testing moduleCheck logic:")
            
            # Test with 0 tokens (should pass if supply is 0 and limit is 100)
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",  # to (EU investor)
                    0,  # amount (0 tokens)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 0 tokens: {result}")
            except Exception as e:
                print(f"   ❌ Error testing 0 tokens: {e}")
            
            # Test with 1 token
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",  # to (EU investor)
                    1 * 10**18,  # amount (1 token)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 1 token: {result}")
            except Exception as e:
                print(f"   ❌ Error testing 1 token: {e}")
            
            # Test with 100 tokens (should pass if limit is 100)
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",  # to (EU investor)
                    100 * 10**18,  # amount (100 tokens)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 100 tokens: {result}")
            except Exception as e:
                print(f"   ❌ Error testing 100 tokens: {e}")
        
        print(f"\n✅ Supply synchronization debug completed!")

if __name__ == "__main__":
    debug_supply_sync()
