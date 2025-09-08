#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
import json

def test_direct_module_config():
    """Test direct module configuration without callModuleFunction"""
    
    # Initialize services
    web3_service = Web3Service()
    trex_service = TREXService(web3_service)
    
    # Get token info
    token_id = 10  # bart3
    token = trex_service.get_token_by_id(token_id)
    
    if not token:
        print(f"❌ Token {token_id} not found")
        return
    
    print(f"🔍 Testing direct module configuration for Token {token_id}")
    print(f"   Token: {token.name}")
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
        print(f"\n🔧 MODULE 2: {module_address}")
        print("----------------------------------------")
        
        # Load SupplyLimitModule ABI
        with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
            artifact = json.load(f)
            abi = artifact['abi']
        
        module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
        
        # Check current supply limit
        try:
            current_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
            print(f"   📊 Current supply limit: {current_limit}")
        except Exception as e:
            print(f"   ❌ Error getting current supply limit: {e}")
            return
        
        # Try to set supply limit directly
        try:
            print(f"   🔧 Setting supply limit to 50...")
            tx_hash = module_contract.functions.setSupplyLimit(50).transact({
                'from': web3_service.w3.eth.accounts[0],  # Use first account
                'gas': 200000
            })
            
            receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status == 1:
                print(f"   ✅ Successfully set supply limit to 50")
                
                # Check new supply limit
                new_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 New supply limit: {new_limit}")
                
                # Test moduleCheck
                try:
                    result = module_contract.functions.moduleCheck(
                        "0x0000000000000000000000000000000000000000",  # from
                        "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",  # to
                        1000000000000000000,  # amount
                        token.compliance_address  # compliance address
                    ).call()
                    print(f"   ✅ moduleCheck after config: {result}")
                except Exception as e:
                    print(f"   ❌ moduleCheck error: {e}")
                    
            else:
                print(f"   ❌ Transaction failed")
                
        except Exception as e:
            print(f"   ❌ Error setting supply limit: {e}")

if __name__ == "__main__":
    test_direct_module_config()
