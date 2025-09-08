#!/usr/bin/env python3
"""
Check what's actually configured in the compliance modules
"""

from app import app
from models.token import Token
from services.web3_service import Web3Service
import json

def check_compliance_config():
    """Check the actual compliance module configuration"""
    with app.app_context():
        # Get the latest token
        token = Token.query.order_by(Token.id.desc()).first()
        print(f'🔍 Token: {token.name} ({token.symbol})')
        print(f'   Compliance: {token.compliance_address}')
        
        web3_service = Web3Service()
        compliance_contract = web3_service.get_contract(token.compliance_address, 'ModularCompliance')
        
        # Get bound modules
        modules = compliance_contract.functions.getModules().call()
        print(f'\\n📋 Bound modules: {len(modules)}')
        
        for i, module_address in enumerate(modules):
            print(f'\\n🔍 Module {i+1}: {module_address}')
            
            # Try to load the module ABI and check its configuration
            try:
                # Try different ABI files
                abi_files = [
                    'artifacts/contracts/compliance/modular/modules/CountryRestrictModule.sol/CountryRestrictModule.json',
                    'artifacts/contracts/compliance/modular/modules/SupplyLimitModule.sol/SupplyLimitModule.json', 
                    'artifacts/contracts/compliance/modular/modules/TimeTransfersLimitsModule.sol/TimeTransfersLimitsModule.json'
                ]
                
                module_contract = None
                for abi_file in abi_files:
                    try:
                        with open(abi_file, 'r') as f:
                            abi = json.load(f)
                        module_contract = web3_service.w3.eth.contract(
                            address=module_address,
                            abi=abi
                        )
                        print(f'   ✅ Loaded ABI from: {abi_file}')
                        break
                    except:
                        continue
                
                if module_contract:
                    # Try to call different functions to see what's configured
                    functions_to_try = [
                        'getRestrictedCountries',
                        'getAllowedCountries',
                        'getCountries', 
                        'restrictedCountries',
                        'allowedCountries',
                        'getSupplyLimit',
                        'getTimeTransferLimit',
                        'getLimit'
                    ]
                    
                    for func_name in functions_to_try:
                        try:
                            func = getattr(module_contract.functions, func_name)
                            result = func().call()
                            print(f'   {func_name}(): {result}')
                        except:
                            pass
                else:
                    print(f'   ❌ Could not load ABI for module')
                    
            except Exception as e:
                print(f'   ❌ Error checking module: {e}')
        
        # Test compliance with different countries
        print(f'\\n🧪 Testing Compliance with Different Countries:')
        test_cases = [
            ('0xdF3e18d64BC6A983f673Ab319CCaE4f1a57C7097', 'EU (250)', 250),
            ('0x1CBd3b2770909D4e10f157cABC84C7264073C9Ec', 'ASIA (156)', 156),
            ('0x0000000000000000000000000000000000000001', 'US (840)', 840),
            ('0x0000000000000000000000000000000000000002', 'UK (826)', 826)
        ]
        
        for addr, name, country_code in test_cases:
            try:
                # Set up a test identity with the country code
                # For now, just test the compliance check
                can_transfer = compliance_contract.functions.canTransfer(addr, addr, 1000).call()
                print(f'   {name}: {can_transfer}')
            except Exception as e:
                print(f'   {name}: Error - {e}')

if __name__ == "__main__":
    check_compliance_config()
