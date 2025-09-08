#!/usr/bin/env python3
"""
Update compliance module to allow US investors
"""

from app import app
from services.web3_service import Web3Service
from models import Token

def update_compliance_countries():
    """Update compliance module to allow US investors"""
    with app.app_context():
        web3_service = Web3Service()
        
        print("🔧 UPDATING COMPLIANCE MODULE COUNTRIES")
        print("=" * 50)
        
        # Get the deployed token
        token = Token.query.filter_by(token_address='0xDaBD6c1d50d3d195881231DA8FF5CA8a52C58c6F').first()
        if not token:
            print("❌ Token not found")
            return
        
        print(f"📋 Token: {token.name} ({token.symbol})")
        print(f"   Compliance: {token.compliance_address}")
        
        try:
            # Get compliance contract
            compliance_contract = web3_service.get_contract(token.compliance_address, 'ModularCompliance')
            
            # Get bound modules
            modules = compliance_contract.functions.getModules().call()
            print(f"📋 Found {len(modules)} compliance modules")
            
            for i, module_address in enumerate(modules):
                print(f"\n🔍 Module {i+1}: {module_address}")
                
                try:
                    # Check if it's CountryRestrictModule
                    module_contract = web3_service.get_contract(module_address, 'CountryRestrictModule')
                    current_restricted = module_contract.functions.getRestrictedCountries().call()
                    print(f"   🌍 Current restricted countries: {current_restricted}")
                    
                    # Update to allow US (840) and restrict others
                    # Remove US (840) from restricted list, add other countries
                    new_restricted = [c for c in current_restricted if c != 840]  # Remove US
                    if 250 not in new_restricted:  # Add France if not already there
                        new_restricted.append(250)
                    
                    print(f"   🔄 New restricted countries: {new_restricted}")
                    
                    # Build transaction to update countries
                    # This would need to be called via callModuleFunction on the compliance contract
                    print(f"   ⚠️  Manual update needed - call batchRestrictCountries with: {new_restricted}")
                    
                except Exception as e:
                    print(f"   ❌ Not CountryRestrictModule or error: {e}")
                    
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    update_compliance_countries()
