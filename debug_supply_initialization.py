#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def debug_supply_initialization():
    """Debug if SupplyLimitModule needs initialization"""
    
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
        
        print(f"🔍 Debugging SupplyLimitModule initialization")
        print(f"   Token: {token.name}")
        print(f"   Token Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        
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
            
            # Check if module needs initialization
            print(f"\n🔍 Checking if module needs initialization:")
            
            # Try to call initialize function
            try:
                print(f"   🔧 Attempting to initialize module...")
                # This should fail if already initialized
                tx_hash = module_contract.functions.initialize().transact({
                    'from': web3_service.w3.eth.accounts[0],
                    'gas': 100000
                })
                receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
                if receipt.status == 1:
                    print(f"   ✅ Module initialized successfully!")
                else:
                    print(f"   ❌ Module initialization failed!")
            except Exception as e:
                print(f"   ℹ️  Module already initialized or error: {e}")
            
            # Check if there's a way to reset or reconfigure the module
            print(f"\n🔍 Checking module state:")
            
            # Try to get the current supply limit again
            try:
                supply_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 Current supply limit: {supply_limit}")
                print(f"   📊 Supply limit (tokens): {supply_limit / 10**18}")
            except Exception as e:
                print(f"   ❌ Error getting supply limit: {e}")
            
            # Try to set the supply limit again (maybe it's not properly set)
            try:
                print(f"   🔧 Attempting to reset supply limit to 100...")
                tx_hash = module_contract.functions.setSupplyLimit(100).transact({
                    'from': web3_service.w3.eth.accounts[0],
                    'gas': 100000
                })
                receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
                if receipt.status == 1:
                    print(f"   ✅ Supply limit reset successfully!")
                    
                    # Check new supply limit
                    new_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                    print(f"   📊 New supply limit: {new_limit}")
                else:
                    print(f"   ❌ Supply limit reset failed!")
            except Exception as e:
                print(f"   ❌ Error resetting supply limit: {e}")
            
            # Test moduleCheck again after potential reset
            print(f"\n🔍 Testing moduleCheck after potential reset:")
            test_address = "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a"  # EU investor
            
            try:
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    1 * 10**18,  # amount (1 token)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   📊 moduleCheck with 1 token: {result}")
            except Exception as e:
                print(f"   ❌ moduleCheck error: {e}")
        
        print(f"\n✅ SupplyLimitModule initialization debug completed!")

if __name__ == "__main__":
    debug_supply_initialization()
