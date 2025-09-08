#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def fix_supply_limit():
    """Fix SupplyLimitModule by setting correct supply limit in wei"""
    
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
        
        print(f"🔧 Fixing SupplyLimitModule supply limit")
        print(f"   Token: {token.name}")
        print(f"   Token Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Issuer private key and address
        issuer_private_key = "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0"
        issuer_address = "0xdD2FD4581271e230360230F9337D5c0430Bf44C0"
        
        # Get bound modules
        compliance_contract = web3_service.w3.eth.contract(
            address=token.compliance_address,
            abi=web3_service.get_contract_abi('ModularCompliance')
        )
        
        modules = compliance_contract.functions.getModules().call()
        
        # Fix Module 2 (SupplyLimitModule)
        if len(modules) >= 2:
            module_address = modules[1]  # Second module
            print(f"\n🔧 FIXING SUPPLY LIMIT MODULE: {module_address}")
            print("=" * 50)
            
            # Load SupplyLimitModule ABI
            with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Check current supply limit
            try:
                current_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 Current supply limit: {current_limit} wei")
                print(f"   📊 Current supply limit: {current_limit / 10**18} tokens")
            except Exception as e:
                print(f"   ❌ Error getting current supply limit: {e}")
            
            # Set correct supply limit (100 tokens = 100 * 10^18 wei)
            correct_limit = 100 * 10**18  # 100 tokens in wei
            print(f"\n🔧 Setting supply limit to {correct_limit} wei ({correct_limit / 10**18} tokens)")
            
            try:
                # Build setSupplyLimit transaction
                module_function_selector = web3_service.w3.keccak(text="setSupplyLimit(uint256)")[:4]
                module_encoded_params = web3_service.w3.codec.encode(['uint256'], [correct_limit])
                module_call_data = module_function_selector + module_encoded_params
                
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
                
                # Sign and send transaction
                signed_tx = web3_service.w3.eth.account.sign_transaction(tx, issuer_private_key)
                tx_hash = web3_service.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt.status == 1:
                    print(f"   ✅ Supply limit updated successfully!")
                    print(f"   📋 Transaction hash: {tx_hash.hex()}")
                    
                    # Verify new supply limit
                    new_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                    print(f"   📊 New supply limit: {new_limit} wei")
                    print(f"   📊 New supply limit: {new_limit / 10**18} tokens")
                    
                else:
                    print(f"   ❌ Transaction failed!")
                    print(f"   ❌ Receipt: {receipt}")
                    
            except Exception as e:
                print(f"   ❌ Error updating supply limit: {e}")
            
            # Test moduleCheck after fix
            print(f"\n🔍 Testing moduleCheck after fix:")
            test_address = "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a"  # EU investor
            
            test_amounts = [1, 10, 50, 100, 101]
            for amount in test_amounts:
                try:
                    result = module_contract.functions.moduleCheck(
                        "0x0000000000000000000000000000000000000000",  # from (minting)
                        test_address,  # to (EU investor)
                        amount * 10**18,  # amount in wei
                        token.compliance_address  # compliance address
                    ).call()
                    print(f"   📊 moduleCheck with {amount} tokens: {result}")
                except Exception as e:
                    print(f"   ❌ moduleCheck with {amount} tokens error: {e}")
        
        print(f"\n✅ SupplyLimitModule fix completed!")

if __name__ == "__main__":
    fix_supply_limit()
