#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def fix_module_configuration():
    """Fix module configuration by calling functions directly"""
    
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
        
        print(f"🔧 Fixing module configuration for Token {token_id}")
        print(f"   Token: {token.name}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Get bound modules
        compliance_contract = web3_service.w3.eth.contract(
            address=token.compliance_address,
            abi=web3_service.get_contract_abi('ModularCompliance')
        )
        
        modules = compliance_contract.functions.getModules().call()
        print(f"📋 Bound modules: {len(modules)}")
        
        # Fix Module 2 (SupplyLimitModule)
        if len(modules) >= 2:
            module_address = modules[1]  # Second module
            print(f"\n🔧 FIXING MODULE 2 (SupplyLimitModule): {module_address}")
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
            
            # Set supply limit directly
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
                    
                else:
                    print(f"   ❌ Transaction failed")
                    
            except Exception as e:
                print(f"   ❌ Error setting supply limit: {e}")
        
        # Fix Module 3 (TimeTransfersLimitsModule)
        if len(modules) >= 3:
            module_address = modules[2]  # Third module
            print(f"\n🔧 FIXING MODULE 3 (TimeTransfersLimitsModule): {module_address}")
            print("----------------------------------------")
            
            # Load TimeTransfersLimitsModule ABI
            with open('artifacts/contracts/compliance/modular/modules/TimeTransfersLimitsModule.sol/TimeTransfersLimitsModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Check current time transfer limits
            try:
                current_limits = module_contract.functions.getTimeTransferLimits(token.token_address).call()
                print(f"   ⏰ Current time transfer limits: {current_limits}")
            except Exception as e:
                print(f"   ❌ Error getting current time transfer limits: {e}")
                return
            
            # Set time transfer limit directly
            try:
                print(f"   🔧 Setting time transfer limit to 300 seconds...")
                # setTimeTransferLimit takes a struct: {limitTime: uint32, limitValue: uint256}
                limit_struct = (300, 1000000000000000000)  # 300 seconds, 1 token limit
                tx_hash = module_contract.functions.setTimeTransferLimit(limit_struct).transact({
                    'from': web3_service.w3.eth.accounts[0],  # Use first account
                    'gas': 200000
                })
                
                receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
                if receipt.status == 1:
                    print(f"   ✅ Successfully set time transfer limit to 300 seconds")
                    
                    # Check new time transfer limits
                    new_limits = module_contract.functions.getTimeTransferLimits(token.token_address).call()
                    print(f"   ⏰ New time transfer limits: {new_limits}")
                    
                else:
                    print(f"   ❌ Transaction failed")
                    
            except Exception as e:
                print(f"   ❌ Error setting time transfer limit: {e}")
        
        print(f"\n✅ Module configuration fix completed!")

if __name__ == "__main__":
    fix_module_configuration()
