#!/usr/bin/env python3
"""
Check if compliance modules are properly bound to the compliance contract
"""

from app import app
from models.token import Token
from services.web3_service import Web3Service
import json

def check_module_binding():
    with app.app_context():
        token = Token.query.order_by(Token.id.desc()).first()
        web3_service = Web3Service()
        
        print('🔍 Checking Compliance Module Binding:')
        print(f'   Token: {token.name} ({token.symbol})')
        print(f'   Compliance: {token.compliance_address}')
        
        compliance_contract = web3_service.get_contract(token.compliance_address, 'ModularCompliance')
        modules = compliance_contract.functions.getModules().call()
        print(f'   Bound modules: {len(modules)}')
        
        for i, module_address in enumerate(modules):
            print(f'\n   Module {i+1}: {module_address}')
            
            try:
                with open('artifacts/contracts/compliance/modular/modules/CountryRestrictModule.sol/CountryRestrictModule.json', 'r') as f:
                    artifact = json.load(f)
                    abi = artifact['abi']  # Extract just the ABI from the artifact
                
                module_contract = web3_service.w3.eth.contract(address=module_address, abi=abi)
                
                # Check if module is bound to compliance
                is_bound = module_contract.functions.isComplianceBound(token.compliance_address).call()
                print(f'      Bound to compliance: {is_bound}')
                
                if not is_bound:
                    print(f'      ❌ MODULE NOT BOUND TO COMPLIANCE!')
                    print(f'      This is why compliance checks fail during mint/transfer')
                else:
                    print(f'      ✅ Module is properly bound')
                    
            except Exception as e:
                print(f'      ❌ Error: {e}')

if __name__ == "__main__":
    check_module_binding()
