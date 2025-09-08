#!/usr/bin/env python3
"""
Test script to verify compliance flow:
1. Check if compliance modules are properly configured
2. Check what country code investors are registered with in IR
3. Test if investors can actually mint tokens
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models.token import Token
from models.user import User
from services.web3_service import Web3Service
import json

def test_compliance_flow():
    with app.app_context():
        print("🔍 COMPREHENSIVE COMPLIANCE FLOW TEST")
        print("=" * 50)
        
        # Get the latest token (Token ID 10 - bart3)
        token = Token.query.get(10)
        if not token:
            print("❌ No token found with ID 10")
            return
            
        print(f"📋 Token: {token.name} ({token.symbol})")
        print(f"   Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        print(f"   IR: {token.identity_registry_address}")
        
        # Initialize Web3 service
        web3_service = Web3Service()
        
        # 1. Check compliance module configuration (FOCUS ON COUNTRY ALLOW MODULE)
        print(f"\n🔧 1. CHECKING COUNTRY ALLOW MODULE CONFIGURATION")
        print("-" * 50)
        
        # Load CountryAllowModule ABI
        try:
            with open('artifacts/contracts/compliance/modular/modules/CountryAllowModule.sol/CountryAllowModule.json', 'r') as f:
                artifact = json.load(f)
                abi = artifact['abi']
            
            # Get the compliance contract to find bound modules
            compliance_contract = web3_service.get_contract(token.compliance_address, "ModularCompliance")
            
            # Get bound modules
            try:
                bound_modules = compliance_contract.functions.getModules().call()
                print(f"   📋 Bound modules: {len(bound_modules)}")
                
                # Focus only on the first module (CountryAllowModule)
                if len(bound_modules) > 0:
                    module_addr = bound_modules[0]
                    print(f"   🌍 CountryAllowModule: {module_addr}")
                    
                    try:
                        module_contract = web3_service.w3.eth.contract(address=module_addr, abi=abi)
                        
                        # Check if this module is bound to our compliance
                        is_bound = module_contract.functions.isComplianceBound(token.compliance_address).call()
                        print(f"      Bound to compliance: {is_bound}")
                        
                        if is_bound:
                            # Test specific countries using isCountryAllowed
                            try:
                                test_countries = [250, 156, 840, 826]  # EU, ASIA, US, UK
                                country_names = ["EU (250)", "ASIA (156)", "US (840)", "UK (826)"]
                                
                                print(f"      Testing country allowances:")
                                for country, name in zip(test_countries, country_names):
                                    is_allowed = module_contract.functions.isCountryAllowed(token.compliance_address, country).call()
                                    status = "✅ ALLOWED" if is_allowed else "❌ BLOCKED"
                                    print(f"        {name}: {status}")
                                    
                            except Exception as e:
                                print(f"      ❌ Error checking country allowances: {e}")
                                
                            # Test moduleCheck function with CORRECT parameters
                            try:
                                print(f"      Testing moduleCheck function:")
                                # Test with a transfer from 0x0 (minting) to a test address
                                test_address = "0x0000000000000000000000000000000000000001"
                                module_result = module_contract.functions.moduleCheck(
                                    "0x0000000000000000000000000000000000000000",  # from (minting)
                                    test_address,  # to
                                    1000000000000000000,  # amount (1 token in wei)
                                    token.token_address  # token address
                                ).call()
                                print(f"        moduleCheck result: {module_result}")
                                
                            except Exception as e:
                                print(f"      ❌ Error testing moduleCheck: {e}")
                                
                    except Exception as e:
                        print(f"      ❌ Error checking CountryAllowModule: {e}")
                else:
                    print("   ❌ No modules found!")
                        
            except Exception as e:
                print(f"   ❌ Error getting bound modules: {e}")
                
        except Exception as e:
            print(f"   ❌ Error loading CountryAllowModule ABI: {e}")
        
        # 2. Check investors in IR
        print(f"\n👥 2. CHECKING INVESTORS IN IDENTITY REGISTRY")
        print("-" * 50)
        
        try:
            ir_contract = web3_service.get_contract(token.identity_registry_address, "IdentityRegistry")
            
            # Get all investors
            investors = User.query.filter_by(user_type='investor').all()
            print(f"   📋 Found {len(investors)} investors in database")
            
            for investor in investors:
                print(f"\n   👤 Investor: {investor.username}")
                print(f"      Wallet: {investor.wallet_address}")
                print(f"      OnchainID: {investor.onchain_id}")
                
                # Check if investor is in IR
                try:
                    is_in_ir = ir_contract.functions.isVerified(investor.wallet_address).call()
                    print(f"      In IR: {is_in_ir}")
                    
                    if is_in_ir:
                        # Get country code
                        try:
                            country_code = ir_contract.functions.investorCountry(investor.wallet_address).call()
                            print(f"      Country code: {country_code}")
                            
                            # Map country codes to names
                            country_map = {
                                250: "EU",
                                156: "ASIA", 
                                840: "US",
                                826: "UK",
                                7: "EU (old)",
                                6: "ASIA (old)"
                            }
                            country_name = country_map.get(country_code, f"Unknown ({country_code})")
                            print(f"      Country: {country_name}")
                            
                        except Exception as e:
                            print(f"      ❌ Error getting country code: {e}")
                            
                except Exception as e:
                    print(f"      ❌ Error checking IR status: {e}")
                    
        except Exception as e:
            print(f"   ❌ Error checking IR: {e}")
        
        # 3. Test compliance check (FOCUS ON EU INVESTOR)
        print(f"\n🧪 3. TESTING COMPLIANCE CHECK")
        print("-" * 50)
        
        try:
            # Get compliance contract
            compliance_contract = web3_service.get_contract(token.compliance_address, "ModularCompliance")
            
            # Focus on the EU investor (bat111) who should be able to mint
            eu_investor = None
            for investor in investors:
                if investor.username == 'bat111' and investor.onchain_id:
                    eu_investor = investor
                    break
            
            if eu_investor:
                print(f"\n   🧪 Testing compliance for EU investor {eu_investor.username}:")
                print(f"      Wallet: {eu_investor.wallet_address}")
                print(f"      Country: 250 (EU)")
                print(f"      In IR: True")
                
                try:
                    # Check if investor can receive tokens (compliance check)
                    can_receive = compliance_contract.functions.canTransfer(
                        "0x0000000000000000000000000000000000000000",  # from (minting)
                        eu_investor.wallet_address,  # to
                        1000000000000000000  # 1 token in wei
                    ).call()
                    
                    print(f"      Can receive tokens: {can_receive}")
                    
                    if not can_receive:
                        print(f"      ❌ Compliance check FAILED - EU investor cannot receive tokens")
                        print(f"      🔍 This is the problem! EU (250) should be allowed but compliance is blocking it")
                    else:
                        print(f"      ✅ Compliance check PASSED - EU investor can receive tokens")
                        
                except Exception as e:
                    print(f"      ❌ Error testing compliance: {e}")
            else:
                print(f"   ❌ No EU investor found to test with")
                
        except Exception as e:
            print(f"   ❌ Error testing compliance: {e}")
        
        # 4. Check token agents
        print(f"\n🔑 4. CHECKING TOKEN AGENTS")
        print("-" * 50)
        
        try:
            token_contract = web3_service.get_contract(token.token_address, "Token")
            
            # Check if issuer is token agent
            issuer_address = token.issuer_address
            is_agent = token_contract.functions.isAgent(issuer_address).call()
            print(f"   Issuer {issuer_address} is token agent: {is_agent}")
            
            # Check if issuer is IR agent
            ir_contract = web3_service.get_contract(token.identity_registry_address, "IdentityRegistry")
            is_ir_agent = ir_contract.functions.isAgent(issuer_address).call()
            print(f"   Issuer {issuer_address} is IR agent: {is_ir_agent}")
            
        except Exception as e:
            print(f"   ❌ Error checking agents: {e}")

if __name__ == "__main__":
    test_compliance_flow()
