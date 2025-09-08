#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.web3_service import Web3Service
from services.trex_service import TREXService
from app import app
from models import Token
import json

def test_minting_after_fix():
    """Test minting 11 tokens after fixing supply limit"""
    
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
        
        print(f"🧪 Testing minting after supply limit fix")
        print(f"   Token: {token.name}")
        print(f"   Token Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        
        # Test investor address
        test_investor = "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a"  # EU investor
        
        # Get token contract
        token_contract = web3_service.w3.eth.contract(
            address=token.token_address,
            abi=web3_service.get_contract_abi('Token')
        )
        
        # Get compliance contract
        compliance_contract = web3_service.w3.eth.contract(
            address=token.compliance_address,
            abi=web3_service.get_contract_abi('ModularCompliance')
        )
        
        # Check current token supply
        try:
            current_supply = token_contract.functions.totalSupply().call()
            print(f"   📊 Current token supply: {current_supply / 10**18} tokens")
        except Exception as e:
            print(f"   ❌ Error getting current supply: {e}")
        
        # Test compliance check before minting
        print(f"\n🔍 Testing compliance check before minting:")
        try:
            # Test canTransfer (overall compliance)
            can_transfer = compliance_contract.functions.canTransfer(
                "0x0000000000000000000000000000000000000000",  # from (minting)
                test_investor,  # to (EU investor)
                11 * 10**18  # amount (11 tokens in wei)
            ).call()
            print(f"   📊 canTransfer (11 tokens): {can_transfer}")
        except Exception as e:
            print(f"   ❌ Error testing canTransfer: {e}")
        
        # Test individual module checks
        print(f"\n🔍 Testing individual module checks:")
        
        # Get bound modules
        modules = compliance_contract.functions.getModules().call()
        print(f"   📋 Bound modules: {len(modules)}")
        
        for i, module_address in enumerate(modules):
            print(f"\n   🔧 Module {i+1}: {module_address}")
            
            # Load module ABI based on module type
            try:
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
                else:
                    continue
                
                module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
                
                # Test moduleCheck
                try:
                    result = module_contract.functions.moduleCheck(
                        "0x0000000000000000000000000000000000000000",  # from (minting)
                        test_investor,  # to (EU investor)
                        11 * 10**18,  # amount (11 tokens in wei)
                        token.compliance_address  # compliance address
                    ).call()
                    print(f"      📊 moduleCheck (11 tokens): {result}")
                except Exception as e:
                    print(f"      ❌ moduleCheck error: {e}")
                
                # Module-specific checks
                if i == 1:  # SupplyLimitModule
                    try:
                        supply_limit = module_contract.functions.getSupplyLimit(token.compliance_address).call()
                        print(f"      📊 Supply limit: {supply_limit / 10**18} tokens")
                    except Exception as e:
                        print(f"      ❌ Error getting supply limit: {e}")
                
            except Exception as e:
                print(f"      ❌ Error loading module {i+1}: {e}")
        
        print(f"\n✅ Minting test completed!")
        print(f"   💡 If all moduleCheck results are True, minting 11 tokens should work!")

if __name__ == "__main__":
    test_minting_after_fix()
