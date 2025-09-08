#!/usr/bin/env python3
"""
Check what data is stored in the Identity Registry on-chain
"""

from app import app
from services.web3_service import Web3Service
from models import Token

def check_ir_data():
    """Check Identity Registry data on-chain"""
    with app.app_context():
        web3_service = Web3Service()
        
        print("🔍 CHECKING IDENTITY REGISTRY DATA")
        print("=" * 40)
        
        # Get the deployed token
        token = Token.query.filter_by(token_address='0xDaBD6c1d50d3d195881231DA8FF5CA8a52C58c6F').first()
        if not token:
            print("❌ Token not found")
            return
        
        print(f"📋 Token: {token.name} ({token.symbol})")
        print(f"   IR Address: {token.identity_registry_address}")
        
        # Test addresses from your logs
        test_addresses = [
            "0xbDA5747bFD65F08deb54cb465eB87D40e51B197E",  # bart3
            "0x2546BcD3c84621e976D8185a91A922aE77ECEc30"   # bart4
        ]
        
        try:
            ir_contract = web3_service.get_contract(token.identity_registry_address, 'IdentityRegistry')
            
            for address in test_addresses:
                print(f"\n🔍 Checking: {address}")
                
                # Check if registered
                is_registered = ir_contract.functions.isVerified(address).call()
                print(f"   ✅ IR Registered: {is_registered}")
                
                if is_registered:
                    # Get identity data
                    identity_data = ir_contract.functions.identity(address).call()
                    print(f"   📋 Identity Data: {identity_data}")
                    
                    # Get country code
                    try:
                        country_code = ir_contract.functions.investorCountry(address).call()
                        print(f"   🌍 Country Code: {country_code}")
                    except Exception as e:
                        print(f"   ⚠️ Could not get country code: {e}")
                    
                    # Get ONCHAINID
                    try:
                        onchainid = identity_data[0] if len(identity_data) > 0 else None
                        print(f"   🆔 ONCHAINID: {onchainid}")
                    except Exception as e:
                        print(f"   ⚠️ Could not get ONCHAINID: {e}")
                else:
                    print(f"   ❌ Not registered in Identity Registry")
                    
        except Exception as e:
            print(f"❌ Error checking IR: {e}")

if __name__ == "__main__":
    check_ir_data()
