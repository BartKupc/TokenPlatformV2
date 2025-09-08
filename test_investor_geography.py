#!/usr/bin/env python3
"""
Test script to check investor geographical locations and compliance
"""

from app import app
from services.web3_service import Web3Service
from services.trex_service import TREXService
from models import User, Token

def test_investor_geography():
    """Test investor geographical locations and compliance"""
    with app.app_context():
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        print("🔍 INVESTOR GEOGRAPHY & COMPLIANCE TEST")
        print("=" * 50)
        
        # Get the deployed token
        token = Token.query.filter_by(token_address='0xDaBD6c1d50d3d195881231DA8FF5CA8a52C58c6F').first()
        if not token:
            print("❌ Token not found in database")
            return
        
        print(f"📋 Testing Token: {token.name} ({token.symbol})")
        print(f"   Address: {token.token_address}")
        print(f"   Compliance: {token.compliance_address}")
        print()
        
        # Get all investors
        investors = User.query.filter_by(user_type='investor').all()
        print(f"👥 Found {len(investors)} investors:")
        
        for investor in investors:
            print(f"\n🔍 Investor: {investor.username}")
            print(f"   Wallet: {investor.wallet_address}")
            
            # Check KYC data from database
            if hasattr(investor, 'kyc_data') and investor.kyc_data:
                try:
                    import json
                    kyc_data = json.loads(investor.kyc_data) if isinstance(investor.kyc_data, str) else investor.kyc_data
                    nationality = kyc_data.get('nationality', 'Not provided')
                    print(f"   📋 KYC Nationality: {nationality}")
                    
                    # Convert to country code
                    country_code = trex_service._get_country_code_from_nationality(nationality)
                    print(f"   🌍 Mapped Country Code: {country_code}")
                except Exception as e:
                    print(f"   ⚠️ Could not parse KYC data: {e}")
            else:
                print(f"   ❌ No KYC data found")
            
            # Check if investor is in Identity Registry
            try:
                ir_address = token.identity_registry_address
                ir_contract = web3_service.get_contract(ir_address, 'IdentityRegistry')
                
                # Check if investor is registered
                is_registered = ir_contract.functions.isVerified(investor.wallet_address).call()
                print(f"   ✅ IR Registered: {is_registered}")
                
                if is_registered:
                    # Get investor's identity data from IR
                    identity_data = ir_contract.functions.identity(investor.wallet_address).call()
                    print(f"   📋 Identity Data: {identity_data}")
                    
                    # Get investor's country code from identity (usually index 2)
                    country_code = identity_data[2] if len(identity_data) > 2 else None
                    print(f"   🌍 Country Code: {country_code}")
                    
                    # Check if investor has an ONCHAINID
                    try:
                        onchainid_address = ir_contract.functions.identity(investor.wallet_address).call()[0]
                        if onchainid_address != "0x0000000000000000000000000000000000000000":
                            print(f"   🆔 ONCHAINID: {onchainid_address}")
                            
                            # Try to get claims from ONCHAINID
                            try:
                                onchainid_contract = web3_service.get_contract(onchainid_address, 'Identity')
                                # Get all claim topics
                                claim_topics = onchainid_contract.functions.getClaimTopics().call()
                                print(f"   📋 Claim Topics: {claim_topics}")
                                
                                # Try to get specific claims (like nationality)
                                for topic in claim_topics:
                                    try:
                                        claim = onchainid_contract.functions.getClaim(topic, 0).call()
                                        print(f"      Topic {topic}: {claim}")
                                    except:
                                        pass
                            except Exception as e:
                                print(f"   ⚠️ Could not read ONCHAINID claims: {e}")
                        else:
                            print(f"   ❌ No ONCHAINID found")
                    except Exception as e:
                        print(f"   ⚠️ Could not get ONCHAINID: {e}")
                    
                    # Check compliance for this investor
                    try:
                        compliance_address = token.compliance_address
                        compliance_contract = web3_service.get_contract(compliance_address, 'ModularCompliance')
                        
                        # Test if transfer would be allowed (mint 1 token to this address)
                        can_transfer = compliance_contract.functions.canTransfer(
                            investor.wallet_address,  # from
                            investor.wallet_address,  # to
                            1,  # amount
                            b''  # data
                        ).call()
                        
                        print(f"   ✅ Compliance Check: {'PASS' if can_transfer else 'FAIL'}")
                        
                        if not can_transfer:
                            print(f"   ❌ Transfer would be blocked by compliance")
                        
                    except Exception as e:
                        print(f"   ⚠️ Compliance check failed: {e}")
                else:
                    print(f"   ❌ Not registered in Identity Registry")
                
            except Exception as e:
                print(f"   ❌ IR check failed: {e}")
        
        print("\n" + "=" * 50)
        print("🔧 COMPLIANCE MODULE STATUS")
        
        # Check compliance modules
        try:
            compliance_address = token.compliance_address
            compliance_contract = web3_service.get_contract(compliance_address, 'ModularCompliance')
            
            # Get bound modules
            modules = compliance_contract.functions.getModules().call()
            print(f"📋 Bound modules: {len(modules)}")
            
            for i, module_address in enumerate(modules):
                print(f"   Module {i+1}: {module_address}")
                
                # Try to determine module type by checking if it has specific functions
                try:
                    # Check if it's CountryRestrictModule
                    module_contract = web3_service.get_contract(module_address, 'CountryRestrictModule')
                    restricted_countries = module_contract.functions.getRestrictedCountries().call()
                    print(f"      🌍 CountryRestrictModule - Restricted countries: {restricted_countries}")
                    
                    # Check which countries are allowed (opposite of restricted)
                    all_countries = list(range(1, 1000))  # Common country codes
                    allowed_countries = [c for c in all_countries if c not in restricted_countries]
                    print(f"      ✅ Allowed countries: {allowed_countries[:10]}...")  # Show first 10
                    
                except:
                    try:
                        # Check if it's SupplyLimitModule
                        module_contract = web3_service.get_contract(module_address, 'SupplyLimitModule')
                        # Try to get supply limit info
                        print(f"      💰 SupplyLimitModule")
                    except:
                        try:
                            # Check if it's TimeTransfersLimitsModule
                            module_contract = web3_service.get_contract(module_address, 'TimeTransfersLimitsModule')
                            print(f"      ⏰ TimeTransfersLimitsModule")
                        except:
                            print(f"      ❓ Unknown module type")
                            
        except Exception as e:
            print(f"❌ Error checking compliance modules: {e}")

def test_specific_investor_compliance(investor_address, token_address):
    """Test compliance for a specific investor"""
    print(f"\n🔍 TESTING SPECIFIC INVESTOR: {investor_address}")
    print("=" * 50)
    
    with app.app_context():
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        try:
            # Get token
            token = Token.query.filter_by(token_address=token_address).first()
            if not token:
                print("❌ Token not found")
                return
            
            # Check IR registration
            ir_contract = web3_service.get_contract(token.identity_registry_address, 'IdentityRegistry')
            is_registered = ir_contract.functions.isVerified(investor_address).call()
            print(f"✅ IR Registered: {is_registered}")
            
            if is_registered:
                # Get identity data
                identity_data = ir_contract.functions.identity(investor_address).call()
                country_code = identity_data[2] if len(identity_data) > 2 else None
                print(f"🌍 Country Code: {country_code}")
                
                # Test compliance
                compliance_contract = web3_service.get_contract(token.compliance_address, 'ModularCompliance')
                can_transfer = compliance_contract.functions.canTransfer(
                    investor_address, investor_address, 1, b''
                ).call()
                
                print(f"✅ Compliance Check: {'PASS' if can_transfer else 'FAIL'}")
                
                # Check each compliance module individually
                modules = compliance_contract.functions.getModules().call()
                print(f"📋 Testing {len(modules)} compliance modules:")
                
                for i, module_address in enumerate(modules):
                    try:
                        module_contract = web3_service.get_contract(module_address, 'CountryRestrictModule')
                        restricted_countries = module_contract.functions.getRestrictedCountries().call()
                        is_restricted = country_code in restricted_countries if country_code else False
                        print(f"   Module {i+1}: Country {country_code} is {'RESTRICTED' if is_restricted else 'ALLOWED'}")
                    except:
                        print(f"   Module {i+1}: Not CountryRestrictModule or error")
                        
        except Exception as e:
            print(f"❌ Error: {e}")

def test_country_mapping():
    """Test the country code mapping"""
    print("\n🌍 COUNTRY CODE MAPPING TEST")
    print("=" * 30)
    
    with app.app_context():
        trex_service = TREXService(Web3Service())
        
        test_nationalities = [
            'US', 'EU', 'UK', 'CA', 'AU', 'ASIA', 'OTHER'
        ]
        
        for nationality in test_nationalities:
            country_code = trex_service._get_country_code_from_nationality(nationality)
            print(f"   {nationality:20} -> {country_code}")

if __name__ == "__main__":
    test_investor_geography()
    test_country_mapping()
    
    # Test specific investors
    print("\n" + "=" * 60)
    print("🔍 TESTING SPECIFIC INVESTORS")
    print("=" * 60)
    
    # Test the investors from your logs
    test_specific_investor_compliance(
        "0xbDA5747bFD65F08deb54cb465eB87D40e51B197E", 
        "0xDaBD6c1d50d3d195881231DA8FF5CA8a52C58c6F"
    )
    
    test_specific_investor_compliance(
        "0x2546BcD3c84621e976D8185a91A922aE77ECEc30", 
        "0xDaBD6c1d50d3d195881231DA8FF5CA8a52C58c6F"
    )
