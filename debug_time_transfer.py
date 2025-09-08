#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def debug_time_transfer():
    """Debug why TimeTransfersLimitsModule configuration is not working"""
    
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
        
        print(f"🔍 Debugging TimeTransfersLimitsModule for Token {token_id}")
        print(f"   Token: {token.name}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Use issuer private key
        issuer_private_key = "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0"
        issuer_address = "0xdD2FD4581271e230360230F9337D5c0430Bf44C0"
        
        # Get bound modules
        compliance_contract = web3_service.w3.eth.contract(
            address=token.compliance_address,
            abi=web3_service.get_contract_abi('ModularCompliance')
        )
        
        modules = compliance_contract.functions.getModules().call()
        print(f"📋 Bound modules: {len(modules)}")
        
        # Test Module 3 (TimeTransfersLimitsModule)
        if len(modules) >= 3:
            module_address = modules[2]  # Third module
            print(f"\n🔧 DEBUGGING MODULE 3 (TimeTransfersLimitsModule): {module_address}")
            print("----------------------------------------")
            
            # Load TimeTransfersLimitsModule ABI
            with open('artifacts/contracts/compliance/modular/modules/TimeTransfersLimitsModule.sol/TimeTransfersLimitsModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Check current configuration
            try:
                current_limits = module_contract.functions.getTimeTransferLimits(token.token_address).call()
                print(f"   ⏰ Current time transfer limits: {current_limits}")
            except Exception as e:
                print(f"   ❌ Error checking time transfer limits: {e}")
                return
            
            # Try different approaches to set the limit
            print(f"\n🔧 Trying different configuration approaches...")
            
            # Approach 1: Try setTimeTransferLimit (single limit)
            try:
                print(f"   🔧 Approach 1: setTimeTransferLimit...")
                
                # Encode setTimeTransferLimit(struct Limit _limit)
                limit_struct = (300, 1000000000000000000)  # 300 seconds, 1 token limit
                module_function_selector = web3_service.w3.keccak(text="setTimeTransferLimit((uint32,uint256))")[:4]
                module_encoded_params = web3_service.w3.codec.encode(['(uint32,uint256)'], [limit_struct])
                module_call_data = module_function_selector + module_encoded_params
                
                print(f"   🔍 Function selector: {module_function_selector.hex()}")
                print(f"   🔍 Encoded params: {module_encoded_params.hex()}")
                print(f"   🔍 Call data: {module_call_data.hex()}")
                
                # Build and execute callModuleFunction transaction
                tx = compliance_contract.functions.callModuleFunction(
                    module_call_data,
                    module_address
                ).build_transaction({
                    'from': issuer_address,
                    'gas': 500000,
                    'gasPrice': web3_service.w3.eth.gas_price,
                    'nonce': web3_service.w3.eth.get_transaction_count(issuer_address)
                })
                
                signed_tx = web3_service.w3.eth.account.sign_transaction(tx, issuer_private_key)
                tx_hash = web3_service.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt.status == 1:
                    print(f"   ✅ setTimeTransferLimit succeeded!")
                    
                    # Check new time transfer limits
                    new_limits = module_contract.functions.getTimeTransferLimits(token.token_address).call()
                    print(f"   ⏰ New time transfer limits: {new_limits}")
                else:
                    print(f"   ❌ setTimeTransferLimit failed")
                    
            except Exception as e:
                print(f"   ❌ Error with setTimeTransferLimit: {e}")
            
            # Approach 2: Try batchSetTimeTransferLimit (array of limits)
            try:
                print(f"\n   🔧 Approach 2: batchSetTimeTransferLimit...")
                
                # Encode batchSetTimeTransferLimit(struct Limit[] _limits)
                limit_struct = (600, 2000000000000000000)  # 600 seconds, 2 token limit
                limits_array = [limit_struct]  # Array with one limit
                module_function_selector = web3_service.w3.keccak(text="batchSetTimeTransferLimit((uint32,uint256)[])")[:4]
                module_encoded_params = web3_service.w3.codec.encode(['(uint32,uint256)[]'], [limits_array])
                module_call_data = module_function_selector + module_encoded_params
                
                print(f"   🔍 Function selector: {module_function_selector.hex()}")
                print(f"   🔍 Encoded params: {module_encoded_params.hex()}")
                print(f"   🔍 Call data: {module_call_data.hex()}")
                
                # Build and execute callModuleFunction transaction
                tx = compliance_contract.functions.callModuleFunction(
                    module_call_data,
                    module_address
                ).build_transaction({
                    'from': issuer_address,
                    'gas': 500000,
                    'gasPrice': web3_service.w3.eth.gas_price,
                    'nonce': web3_service.w3.eth.get_transaction_count(issuer_address)
                })
                
                signed_tx = web3_service.w3.eth.account.sign_transaction(tx, issuer_private_key)
                tx_hash = web3_service.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt.status == 1:
                    print(f"   ✅ batchSetTimeTransferLimit succeeded!")
                    
                    # Check new time transfer limits
                    new_limits = module_contract.functions.getTimeTransferLimits(token.token_address).call()
                    print(f"   ⏰ New time transfer limits: {new_limits}")
                else:
                    print(f"   ❌ batchSetTimeTransferLimit failed")
                    
            except Exception as e:
                print(f"   ❌ Error with batchSetTimeTransferLimit: {e}")
        
        print(f"\n✅ TimeTransfersLimitsModule debug completed!")

if __name__ == "__main__":
    debug_time_transfer()
