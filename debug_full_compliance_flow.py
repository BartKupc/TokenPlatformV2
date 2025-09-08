#!/usr/bin/env python3
"""
Debug the full compliance flow step by step
"""

from app import app
from models.user import User
from models.token import Token
from models.enhanced_models import KYCRequest
from services.web3_service import Web3Service
from services.trex_service import TREXService
import json

def debug_full_compliance_flow():
    """Debug the entire compliance flow step by step"""
    with app.app_context():
        print("🔍 DEBUGGING FULL COMPLIANCE FLOW")
        print("=" * 50)
        
        # Get the latest token
        token = Token.query.order_by(Token.id.desc()).first()
        if not token:
            print("❌ No tokens found")
            return
            
        print(f"📋 Testing Token: {token.name} ({token.symbol})")
        print(f"   Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        print(f"   IR: {token.identity_registry_address}")
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        # Get investors
        investors = User.query.filter_by(user_type='investor').all()
        print(f"\n👥 Found {len(investors)} investors:")
        
        for investor in investors:
            print(f"\n🔍 INVESTOR: {investor.username}")
            print(f"   Wallet: {investor.wallet_address}")
            print(f"   OnchainID: {investor.onchain_id}")
            
            # STEP 1: Check KYC Data
            print(f"\n   📋 STEP 1: KYC Data Check")
            kyc_data = None
            if investor.kyc_data:
                try:
                    kyc_data = json.loads(investor.kyc_data)
                    nationality = kyc_data.get('nationality', '')
                    print(f"   ✅ KYC Data: {kyc_data}")
                    print(f"   🌍 Nationality: {nationality}")
                    
                    # Map to country code
                    country_code = trex_service._get_country_code_from_nationality(nationality)
                    print(f"   🗺️ Mapped Country Code: {country_code}")
                except Exception as e:
                    print(f"   ❌ Error parsing KYC data: {e}")
            else:
                print(f"   ❌ No KYC data in User table")
                
                # Try KYCRequest
                try:
                    kyc_request = KYCRequest.query.filter_by(
                        investor_id=investor.id, 
                        status='approved'
                    ).first()
                    if kyc_request and kyc_request.kyc_data:
                        kyc_data = json.loads(kyc_request.kyc_data)
                        nationality = kyc_data.get('nationality', '')
                        print(f"   📋 Found in KYCRequest: {kyc_data}")
                        print(f"   🌍 Nationality: {nationality}")
                        
                        country_code = trex_service._get_country_code_from_nationality(nationality)
                        print(f"   🗺️ Mapped Country Code: {country_code}")
                    else:
                        print(f"   ❌ No approved KYC request found")
                except Exception as e:
                    print(f"   ❌ Error getting KYCRequest: {e}")
            
            # STEP 2: Check IR Registration
            print(f"\n   📋 STEP 2: Identity Registry Check")
            try:
                ir_contract = web3_service.get_contract(token.identity_registry_address, 'IdentityRegistry')
                
                # Check if registered
                is_verified = ir_contract.functions.isVerified(investor.wallet_address).call()
                print(f"   ✅ IR Verified: {is_verified}")
                
                if is_verified:
                    # Get identity data
                    identity_data = ir_contract.functions.identity(investor.wallet_address).call()
                    print(f"   🆔 Identity: {identity_data}")
                    
                    # Get country code from IR
                    if len(identity_data) > 2:
                        ir_country_code = identity_data[2]
                        print(f"   🌍 IR Country Code: {ir_country_code}")
                        
                        # Compare with expected
                        if kyc_data:
                            expected_country = trex_service._get_country_code_from_nationality(
                                kyc_data.get('nationality', '')
                            )
                            print(f"   🎯 Expected Country Code: {expected_country}")
                            if ir_country_code == expected_country:
                                print(f"   ✅ Country codes match!")
                            else:
                                print(f"   ❌ Country codes don't match!")
                    else:
                        print(f"   ❌ No country code in identity data")
                else:
                    print(f"   ❌ Not registered in IR")
                    
            except Exception as e:
                print(f"   ❌ Error checking IR: {e}")
            
            # STEP 3: Check Compliance Modules
            print(f"\n   📋 STEP 3: Compliance Modules Check")
            try:
                compliance_contract = web3_service.get_contract(token.compliance_address, 'ModularCompliance')
                
                # Get bound modules
                modules = compliance_contract.functions.getModules().call()
                print(f"   📋 Bound modules: {len(modules)}")
                for i, module in enumerate(modules):
                    print(f"      Module {i+1}: {module}")
                
                # Try to check CountryRestrictModule (first module)
                if modules:
                    try:
                        # Load CountryRestrictModule ABI manually
                        with open('artifacts/trex/CountryRestrictModule.json', 'r') as f:
                            country_abi = json.load(f)
                        
                        country_module = web3_service.w3.eth.contract(
                            address=modules[0], 
                            abi=country_abi
                        )
                        
                        # Check restricted countries
                        try:
                            restricted_countries = country_module.functions.getRestrictedCountries().call()
                            print(f"   🚫 Restricted countries: {restricted_countries}")
                        except:
                            print(f"   ℹ️ No getRestrictedCountries function")
                        
                        # Check allowed countries
                        try:
                            allowed_countries = country_module.functions.getAllowedCountries().call()
                            print(f"   ✅ Allowed countries: {allowed_countries}")
                        except:
                            print(f"   ℹ️ No getAllowedCountries function")
                            
                    except Exception as e:
                        print(f"   ⚠️ Could not load CountryRestrictModule: {e}")
                
            except Exception as e:
                print(f"   ❌ Error checking compliance: {e}")
            
            # STEP 4: Test Compliance Check
            print(f"\n   📋 STEP 4: Compliance Check Test")
            try:
                compliance_contract = web3_service.get_contract(token.compliance_address, 'ModularCompliance')
                
                # Test canTransfer
                can_transfer = compliance_contract.functions.canTransfer(
                    investor.wallet_address,  # from
                    investor.wallet_address,  # to
                    1000  # amount
                ).call()
                
                print(f"   🔍 Can Transfer: {can_transfer}")
                
                if can_transfer:
                    print(f"   ✅ Compliance check PASSED")
                else:
                    print(f"   ❌ Compliance check FAILED")
                    
            except Exception as e:
                print(f"   ❌ Error testing compliance: {e}")
            
            # STEP 5: Test Mint (simulation)
            print(f"\n   📋 STEP 5: Mint Test (Simulation)")
            try:
                token_contract = web3_service.get_contract(token.token_address, 'Token')
                
                # Try to estimate gas for mint
                try:
                    gas_estimate = token_contract.functions.mint(
                        investor.wallet_address,
                        1000
                    ).estimate_gas({'from': web3_service.account.address})
                    
                    print(f"   ✅ Mint gas estimate: {gas_estimate}")
                    print(f"   ✅ Mint would succeed")
                    
                except Exception as e:
                    print(f"   ❌ Mint would fail: {e}")
                    
            except Exception as e:
                print(f"   ❌ Error testing mint: {e}")
            
            print(f"\n" + "="*50)

if __name__ == "__main__":
    debug_full_compliance_flow()
