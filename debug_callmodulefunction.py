#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def debug_callmodulefunction():
    """Debug why callModuleFunction is not working"""
    
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
        
        print(f"🔍 Debugging callModuleFunction for Token {token_id}")
        print(f"   Token: {token.name}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Get bound modules
        compliance_contract = web3_service.w3.eth.contract(
            address=token.compliance_address,
            abi=web3_service.get_contract_abi('ModularCompliance')
        )
        
        modules = compliance_contract.functions.getModules().call()
        print(f"📋 Bound modules: {len(modules)}")
        
        # Test Module 2 (SupplyLimitModule) with callModuleFunction
        if len(modules) >= 2:
            module_address = modules[1]  # Second module
            print(f"\n🔧 TESTING MODULE 2 (SupplyLimitModule): {module_address}")
            print("----------------------------------------")
            
            # Check current supply limit
            try:
                # Load SupplyLimitModule ABI
                with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                    artifact = json.load(f)
                    abi = artifact['abi']
                
                module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
                current_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 Current supply limit: {current_limit}")
            except Exception as e:
                print(f"   ❌ Error getting current supply limit: {e}")
                return
            
            # Test callModuleFunction approach
            try:
                print(f"   🔧 Testing callModuleFunction approach...")
                
                # Encode setSupplyLimit(uint256 limit)
                module_function_selector = web3_service.w3.keccak(text="setSupplyLimit(uint256)")[:4]
                module_encoded_params = web3_service.w3.codec.encode(['uint256'], [50])
                module_call_data = module_function_selector + module_encoded_params
                
                print(f"   🔍 Function selector: {module_function_selector.hex()}")
                print(f"   🔍 Encoded params: {module_encoded_params.hex()}")
                print(f"   🔍 Call data: {module_call_data.hex()}")
                
                # Use issuer private key
                issuer_private_key = "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0"
                issuer_address = "0xdD2FD4581271e230360230F9337D5c0430Bf44C0"
                
                # Build callModuleFunction transaction
                tx = compliance_contract.functions.callModuleFunction(
                    module_call_data,
                    module_address
                ).build_transaction({
                    'from': issuer_address,
                    'gas': 500000,
                    'gasPrice': web3_service.w3.eth.gas_price,
                    'nonce': web3_service.w3.eth.get_transaction_count(issuer_address)
                })
                
                print(f"   🔍 Transaction to: {tx['to']}")
                print(f"   🔍 Transaction data: {tx['data'][:100]}...")
                
                # Try to execute the transaction
                print(f"   🔧 Executing callModuleFunction transaction...")
                
                # Sign the transaction with the issuer's private key
                signed_tx = web3_service.w3.eth.account.sign_transaction(tx, issuer_private_key)
                tx_hash = web3_service.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt.status == 1:
                    print(f"   ✅ callModuleFunction succeeded!")
                    
                    # Check new supply limit
                    new_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                    print(f"   📊 New supply limit: {new_limit}")
                    
                else:
                    print(f"   ❌ callModuleFunction transaction failed")
                    
            except Exception as e:
                print(f"   ❌ Error with callModuleFunction: {e}")
        
        print(f"\n✅ callModuleFunction debug completed!")

if __name__ == "__main__":
    debug_callmodulefunction()
