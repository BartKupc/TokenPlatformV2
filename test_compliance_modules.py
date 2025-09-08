#!/usr/bin/env python3
"""
Test compliance modules directly
"""

from app import app
from models.token import Token
from services.web3_service import Web3Service
import json

def test_compliance_modules():
    """Test compliance modules directly"""
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
        
        # Test the first module (should be CountryRestrictModule)
        if modules:
            module_address = modules[0]
            print(f'\\n🔍 Testing Module 1: {module_address}')
            
            try:
                # Load CountryRestrictModule ABI
                with open('artifacts/contracts/compliance/modular/modules/CountryRestrictModule.sol/CountryRestrictModule.json', 'r') as f:
                    abi = json.load(f)
                
                module_contract = web3_service.w3.eth.contract(
                    address=module_address,
                    abi=abi
                )
                
                print(f'   ✅ Loaded CountryRestrictModule ABI')
                
                # Test different countries
                test_countries = [250, 156, 840, 826]  # EU, ASIA, US, UK
                country_names = ['EU', 'ASIA', 'US', 'UK']
                
                print(f'\\n🌍 Testing Country Restrictions:')
                for country, name in zip(test_countries, country_names):
                    try:
                        is_restricted = module_contract.functions.isCountryRestricted(country).call()
                        status = "RESTRICTED" if is_restricted else "ALLOWED"
                        print(f'   {name} ({country}): {status}')
                    except Exception as e:
                        print(f'   {name} ({country}): Error - {e}')
                
                # Try to get all restricted countries (if function exists)
                try:
                    # Check if there's a function to get all restricted countries
                    restricted_countries = module_contract.functions.getRestrictedCountries().call()
                    print(f'\\n📋 All Restricted Countries: {restricted_countries}')
                except:
                    print(f'\\n📋 No getRestrictedCountries function')
                
            except Exception as e:
                print(f'   ❌ Error: {e}')
        
        # Test compliance check
        print(f'\\n🧪 Testing Compliance Check:')
        test_addresses = [
            ('0xdF3e18d64BC6A983f673Ab319CCaE4f1a57C7097', 'EU (250)', 250),
            ('0x1CBd3b2770909D4e10f157cABC84C7264073C9Ec', 'ASIA (156)', 156)
        ]
        
        for addr, name, country_code in test_addresses:
            try:
                can_transfer = compliance_contract.functions.canTransfer(addr, addr, 1000).call()
                status = "PASS" if can_transfer else "FAIL"
                print(f'   {name}: {status}')
            except Exception as e:
                print(f'   {name}: Error - {e}')

if __name__ == "__main__":
    test_compliance_modules()
