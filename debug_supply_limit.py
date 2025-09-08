#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def debug_supply_limit():
    """Debug why SupplyLimitModule is failing"""
    
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
        
        print(f"🔍 Debugging SupplyLimitModule for Token {token_id}")
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
        
        # Debug Module 2 (SupplyLimitModule)
        if len(modules) >= 2:
            module_address = modules[1]  # Second module
            print(f"\n🔧 DEBUGGING MODULE 2 (SupplyLimitModule): {module_address}")
            print("----------------------------------------")
            
            # Load SupplyLimitModule ABI
            with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Check all supply limit details
            try:
                supply_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 Supply limit: {supply_limit}")
                
                # Check if there are other functions we can call
                print(f"   🔍 Available functions in SupplyLimitModule:")
                for func in abi:
                    if func.get('type') == 'function' and 'get' in func.get('name', '').lower():
                        print(f"      - {func['name']}")
                
                # Try to get current supply from token contract
                token_contract = web3_service.w3.eth.contract(
                    address=token.token_address,
                    abi=web3_service.get_contract_abi('Token')
                )
                
                total_supply = token_contract.functions.totalSupply().call()
                print(f"   📊 Token total supply: {total_supply}")
                
                # Check investor balance
                test_address = "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a"  # EU investor
                investor_balance = token_contract.functions.balanceOf(test_address).call()
                print(f"   👤 Investor balance: {investor_balance}")
                
                # Test with different amounts
                print(f"\n   🧪 Testing moduleCheck with different amounts:")
                for amount in [1000000000000000000, 50000000000000000000, 100000000000000000000]:  # 1, 50, 100 tokens
                    try:
                        result = module_contract.functions.moduleCheck(
                            "0x0000000000000000000000000000000000000000",  # from (minting)
                            test_address,  # to (EU investor)
                            amount,  # amount
                            token.compliance_address  # compliance address
                        ).call()
                        print(f"      Amount {amount // 1000000000000000000} tokens: {result}")
                    except Exception as e:
                        print(f"      Amount {amount // 1000000000000000000} tokens: Error - {e}")
                
            except Exception as e:
                print(f"   ❌ Error debugging supply limit: {e}")

if __name__ == "__main__":
    debug_supply_limit()
