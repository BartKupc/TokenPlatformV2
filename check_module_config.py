#!/usr/bin/env python3
"""
Check if compliance modules are properly configured
"""

from app import app
from models.token import Token
from services.web3_service import Web3Service
import json

def check_module_config():
    with app.app_context():
        token = Token.query.order_by(Token.id.desc()).first()
        web3_service = Web3Service()
        
        print('🔍 Checking Compliance Module Configuration:')
        print(f'   Token: {token.name} ({token.symbol})')
        print(f'   Compliance: {token.compliance_address}')
        
        compliance_contract = web3_service.get_contract(token.compliance_address, 'ModularCompliance')
        modules = compliance_contract.functions.getModules().call()
        print(f'   Bound modules: {len(modules)}')
        
        for i, module_address in enumerate(modules):
            print(f'\n   Module {i+1}: {module_address}')
            
            try:
                # Try to load CountryAllowModule ABI
                with open('artifacts/contracts/compliance/modular/modules/CountryAllowModule.sol/CountryAllowModule.json', 'r') as f:
                    artifact = json.load(f)
                    abi = artifact['abi']
                
                module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
                
                # Test country allowances
                print(f'      🌍 Testing Country Allowances:')
                test_countries = [250, 156, 840, 826]  # EU (France), ASIA (China), US, UK
                country_names = ["EU (France)", "ASIA (China)", "US", "UK"]
                
                for country, name in zip(test_countries, country_names):
                    try:
                        is_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, country).call()
                        status = "ALLOWED" if is_allowed else "BLOCKED"
                        print(f'         {name} ({country}): {status}')
                    except Exception as e:
                        print(f'         {name} ({country}): Error - {e}')
                
                # Try to get all allowed countries
                try:
                    allowed_countries = module_contract.functions.getAllowedCountries().call()
                    print(f'      📋 All Allowed Countries: {allowed_countries}')
                except Exception as e:
                    print(f'      ⚠️ Could not get all allowed countries: {e}')
                
                # Test the actual compliance functions
                print(f'      🧪 Testing Compliance Functions:')
                
                try:
                    # We're using CountryAllowModule, so check isCountryAllowed
                    eu_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 250).call()
                    asia_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 156).call()
                    us_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 840).call()
                    uk_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, 826).call()
                    
                    print(f'         isCountryAllowed - EU: {eu_allowed}, ASIA: {asia_allowed}, US: {us_allowed}, UK: {uk_allowed}')
                    
                    # If EU is allowed, it should pass compliance
                    # If ASIA is not allowed, it should be blocked
                    print(f'         Expected: EU should be ALLOWED, ASIA should be BLOCKED')
                    
                except Exception as e:
                    print(f'         ❌ Error testing compliance functions: {e}')
                    
            except Exception as e:
                print(f'      ❌ Error loading module: {e}')

if __name__ == "__main__":
    check_module_config()
