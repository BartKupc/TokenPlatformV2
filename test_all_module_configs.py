#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def test_all_module_configs():
    """Test all 3 module configurations using callModuleFunction"""
    
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
        
        print(f"🔧 Testing all module configurations for Token {token_id}")
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
        
        # Test Module 1 (CountryAllowModule)
        if len(modules) >= 1:
            module_address = modules[0]  # First module
            print(f"\n🔧 TESTING MODULE 1 (CountryAllowModule): {module_address}")
            print("----------------------------------------")
            
            # Load CountryAllowModule ABI
            with open('artifacts/contracts/compliance/modular/modules/CountryAllowModule.sol/CountryAllowModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Check current configuration
            try:
                eu_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 250).call()
                us_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 840).call()
                print(f"   🌍 EU (250) allowed: {eu_allowed}")
                print(f"   🇺🇸 US (840) allowed: {us_allowed}")
            except Exception as e:
                print(f"   ❌ Error checking country allowances: {e}")
                return
            
            # Configure CountryAllowModule
            try:
                print(f"   🔧 Configuring CountryAllowModule with EU allowed...")
                
                # Encode batchAllowCountries(uint16[] countries)
                countries = [250]  # EU
                module_function_selector = web3_service.w3.keccak(text="batchAllowCountries(uint16[])")[:4]
                module_encoded_params = web3_service.w3.codec.encode(['uint16[]'], [countries])
                module_call_data = module_function_selector + module_encoded_params
                
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
                    print(f"   ✅ CountryAllowModule configured successfully!")
                else:
                    print(f"   ❌ CountryAllowModule configuration failed")
                    
            except Exception as e:
                print(f"   ❌ Error configuring CountryAllowModule: {e}")
        
        # Test Module 2 (SupplyLimitModule)
        if len(modules) >= 2:
            module_address = modules[1]  # Second module
            print(f"\n🔧 TESTING MODULE 2 (SupplyLimitModule): {module_address}")
            print("----------------------------------------")
            
            # Load SupplyLimitModule ABI
            with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
            
            # Check current configuration
            try:
                current_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                print(f"   📊 Current supply limit: {current_limit}")
            except Exception as e:
                print(f"   ❌ Error checking supply limit: {e}")
                return
            
            # Configure SupplyLimitModule
            try:
                print(f"   🔧 Configuring SupplyLimitModule with limit 100...")
                
                # Encode setSupplyLimit(uint256 limit)
                module_function_selector = web3_service.w3.keccak(text="setSupplyLimit(uint256)")[:4]
                module_encoded_params = web3_service.w3.codec.encode(['uint256'], [100])
                module_call_data = module_function_selector + module_encoded_params
                
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
                    print(f"   ✅ SupplyLimitModule configured successfully!")
                    
                    # Check new supply limit
                    new_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                    print(f"   📊 New supply limit: {new_limit}")
                else:
                    print(f"   ❌ SupplyLimitModule configuration failed")
                    
            except Exception as e:
                print(f"   ❌ Error configuring SupplyLimitModule: {e}")
        
        # Test Module 3 (TimeTransfersLimitsModule)
        if len(modules) >= 3:
            module_address = modules[2]  # Third module
            print(f"\n🔧 TESTING MODULE 3 (TimeTransfersLimitsModule): {module_address}")
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
            
            # Configure TimeTransfersLimitsModule
            try:
                print(f"   🔧 Configuring TimeTransfersLimitsModule with 300 second limit...")
                
                # Encode batchSetTimeTransferLimit(struct Limit[] _limits)
                # The struct has: {limitTime: uint32, limitValue: uint256}
                limit_struct = (300, 1000000000000000000)  # 300 seconds, 1 token limit
                limits_array = [limit_struct]  # Array with one limit
                module_function_selector = web3_service.w3.keccak(text="batchSetTimeTransferLimit((uint32,uint256)[])")[:4]
                module_encoded_params = web3_service.w3.codec.encode(['(uint32,uint256)[]'], [limits_array])
                module_call_data = module_function_selector + module_encoded_params
                
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
                    print(f"   ✅ TimeTransfersLimitsModule configured successfully!")
                    
                    # Check new time transfer limits
                    new_limits = module_contract.functions.getTimeTransferLimits(token.token_address).call()
                    print(f"   ⏰ New time transfer limits: {new_limits}")
                else:
                    print(f"   ❌ TimeTransfersLimitsModule configuration failed")
                    
            except Exception as e:
                print(f"   ❌ Error configuring TimeTransfersLimitsModule: {e}")
        
        print(f"\n✅ All module configuration tests completed!")
        
        # Final verification
        print(f"\n🔍 FINAL VERIFICATION")
        print("=" * 50)
        
        # Test moduleCheck for all modules
        test_address = "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a"  # EU investor
        
        print(f"\n🔍 Testing overall compliance with EU investor: {test_address}")
        print("=" * 50)
        
        try:
            # Test overall compliance check
            result = compliance_contract.functions.moduleCheck(
                "0x0000000000000000000000000000000000000000",  # from (minting)
                test_address,  # to (EU investor)
                1000000000000000000,  # amount (1 token in wei)
                token.token_address  # token address
            ).call()
            print(f"   ✅ Overall compliance check result: {result}")
            
        except Exception as e:
            print(f"   ❌ Overall compliance check error: {e}")
        
        # Test individual module checks
        for i, module_address in enumerate(modules):
            print(f"\n🔧 MODULE {i+1}: {module_address}")
            print("----------------------------------------")
            
            try:
                # Load the correct module ABI
                if i == 0:  # CountryAllowModule
                    with open('artifacts/contracts/compliance/modular/modules/CountryAllowModule.sol/CountryAllowModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                elif i == 1:  # SupplyLimitModule
                    with open('artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                elif i == 2:  # TimeTransfersLimitsModule
                    with open('artifacts/contracts/compliance/modular/modules/TimeTransfersLimitsModule.sol/TimeTransfersLimitsModule.json', 'r') as f:
                        artifact = json.load(f)
                        abi = artifact['abi']
                
                module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
                
                # Test moduleCheck on the individual module
                result = module_contract.functions.moduleCheck(
                    "0x0000000000000000000000000000000000000000",  # from (minting)
                    test_address,  # to (EU investor)
                    1000000000000000000,  # amount (1 token in wei)
                    token.compliance_address  # compliance address
                ).call()
                print(f"   ✅ moduleCheck result: {result}")
                
            except Exception as e:
                print(f"   ❌ moduleCheck error: {e}")

if __name__ == "__main__":
    test_all_module_configs()
