#!/usr/bin/env python3
"""
Comprehensive isVerified() Debug Script
Debug why isVerified() returns False for a user who should be verified
"""

import sys
import os
from web3 import Web3

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from services.web3_service import Web3Service

def debug_isverified_comprehensive():
    """Comprehensive debugging of isVerified() function"""
    
    with app.app_context():
        web3_service = Web3Service()
        
        # Token and user details from the logs
        token_address = '0xAc086d939a9bE24d915F8f30eBec31716f3843Af'  # bart1 token
        user_address = '0xbDA5747bFD65F08deb54cb465eB87D40e51B197E'  # Investor
        onchain_id_address = '0x279b8AD06Eb7379AE5fa7401eD1d9C0C1FCD981D'  # User's OnchainID
        identity_registry_address = '0xE1Da0759bA107F3D3730FF745b0e4Ab8C85BAcFb'
        trusted_issuers_registry_address = '0x0B0003b9014A98Ae70f0bF6f9e69A6b7d4A212EF'
        claim_topics_registry_address = '0x1A73C10C47b829F6492E35AFFF4eD65846C979B3'
        compliance_address = '0xd5596E4CbdD8ae27e02b3901fB0b893bc1E3d25c'
        trusted_issuer_address = '0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199'
        
        print("🔍 COMPREHENSIVE isVerified() DEBUG")
        print("=" * 60)
        print(f"Token: {token_address}")
        print(f"User: {user_address}")
        print(f"OnchainID: {onchain_id_address}")
        print(f"Identity Registry: {identity_registry_address}")
        print(f"Trusted Issuers Registry: {trusted_issuers_registry_address}")
        print(f"Claim Topics Registry: {claim_topics_registry_address}")
        print(f"Compliance: {compliance_address}")
        print(f"Trusted Issuer: {trusted_issuer_address}")
        print()
        
        # Step 1: Check if user is registered in Identity Registry
        print("📋 STEP 1: Check Identity Registry Registration")
        print("-" * 50)
        try:
            identity_result = web3_service.call_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'identity',
                user_address
            )
            print(f"✅ identity() result: {identity_result}")
            if identity_result == onchain_id_address:
                print("✅ User is registered in Identity Registry")
            else:
                print(f"❌ User OnchainID mismatch! Expected: {onchain_id_address}, Got: {identity_result}")
        except Exception as e:
            print(f"❌ Error calling identity(): {e}")
        
        # Step 2: Check isVerified directly
        print("\n📋 STEP 2: Check isVerified()")
        print("-" * 50)
        try:
            is_verified = web3_service.call_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'isVerified',
                user_address
            )
            print(f"🔍 isVerified() result: {is_verified}")
        except Exception as e:
            print(f"❌ Error calling isVerified(): {e}")
        
        # Step 3: Check what claim topics are required by the token
        print("\n📋 STEP 3: Check Required Claim Topics")
        print("-" * 50)
        try:
            # Try different contract types for getClaimTopics
            for contract_type in ['ClaimTopicsRegistry', 'Compliance', 'ModularCompliance']:
                try:
                    required_topics = web3_service.call_contract_function(
                        contract_type,
                        claim_topics_registry_address if contract_type == 'ClaimTopicsRegistry' else compliance_address,
                        'getClaimTopics'
                    )
                    print(f"✅ Required claim topics ({contract_type}): {required_topics}")
                    break
                except Exception as e:
                    print(f"⚠️ Could not get claim topics from {contract_type}: {e}")
        except Exception as e:
            print(f"❌ Error getting required claim topics: {e}")
        
        # Step 4: Check what claim topics the trusted issuer is approved for
        print("\n📋 STEP 4: Check Trusted Issuer Approved Topics")
        print("-" * 50)
        try:
            # Check if trusted issuer is registered
            is_trusted_issuer = web3_service.call_contract_function(
                'TrustedIssuersRegistry',
                trusted_issuers_registry_address,
                'isTrustedIssuer',
                trusted_issuer_address
            )
            print(f"✅ Is trusted issuer registered: {is_trusted_issuer}")
            
            if is_trusted_issuer:
                # Get approved claim topics for this trusted issuer
                try:
                    approved_topics = web3_service.call_contract_function(
                        'TrustedIssuersRegistry',
                        trusted_issuers_registry_address,
                        'getTrustedIssuerClaimTopics',
                        trusted_issuer_address
                    )
                    print(f"✅ Trusted issuer approved topics: {approved_topics}")
                except Exception as e:
                    print(f"⚠️ Could not get approved topics: {e}")
                    
                # Get all trusted issuers
                try:
                    all_trusted_issuers = web3_service.call_contract_function(
                        'TrustedIssuersRegistry',
                        trusted_issuers_registry_address,
                        'getTrustedIssuers'
                    )
                    print(f"✅ All trusted issuers: {all_trusted_issuers}")
                except Exception as e:
                    print(f"⚠️ Could not get all trusted issuers: {e}")
            else:
                print("❌ Trusted issuer is not registered!")
        except Exception as e:
            print(f"❌ Error checking trusted issuer: {e}")
        
        # Step 5: Check what claims the user has on their OnchainID
        print("\n📋 STEP 5: Check User's OnchainID Claims")
        print("-" * 50)
        print("🔍 The IdentityRegistry's isVerified() function should handle this internally.")
        print("🔍 Since isVerified() returns False, let's check what we can query directly...")
        
        try:
            # Let's try to query the OnchainID using the Identity ABI
            onchain_id_contract = web3_service.w3.eth.contract(
                address=onchain_id_address,
                abi=web3_service.contract_abis.get('Identity', [])
            )
            
            print(f"✅ Created OnchainID contract with Identity ABI")
            print(f"🔍 Available functions in Identity ABI:")
            
            # List available functions
            try:
                functions = [func.name for func in onchain_id_contract.functions]
                print(f"   Available functions: {functions}")
                
                # Try to get claim topics using available functions
                for func_name in functions:
                    if 'claim' in func_name.lower() or 'topic' in func_name.lower():
                        try:
                            if func_name == 'getClaimIdsByTopic':
                                # This is the correct function! Try with topic 1
                                result = onchain_id_contract.functions[func_name](1).call()
                                print(f"✅ {func_name}(1): {result}")
                                
                                # If we get claim IDs, try to get the actual claim data
                                if result and len(result) > 0:
                                    print(f"   Found {len(result)} claim(s) for topic 1")
                                    for i, claim_id in enumerate(result):
                                        try:
                                            claim_data = onchain_id_contract.functions.getClaim(claim_id).call()
                                            print(f"   Claim {i+1} ({claim_id.hex()}): {claim_data}")
                                            if len(claim_data) >= 3:
                                                issuer = claim_data[2]  # issuer is at index 2
                                                print(f"     Issuer: {issuer}")
                                                if issuer.lower() == trusted_issuer_address.lower():
                                                    print(f"     ✅ Claim is from correct trusted issuer!")
                                                else:
                                                    print(f"     ❌ Claim is from wrong issuer! Expected: {trusted_issuer_address}")
                                        except Exception as e:
                                            print(f"   ❌ Could not get claim data for {claim_id.hex()}: {e}")
                                else:
                                    print(f"   ❌ No claims found for topic 1 - this is why isVerified() returns False!")
                            elif func_name in ['getClaimTopics', 'claimTopics']:
                                result = onchain_id_contract.functions[func_name]().call()
                                print(f"✅ {func_name}(): {result}")
                            elif func_name in ['getClaim', 'claims']:
                                # Try with topic 1
                                result = onchain_id_contract.functions[func_name](1).call()
                                print(f"✅ {func_name}(1): {result}")
                        except Exception as e:
                            print(f"⚠️ {func_name}: {e}")
                            
            except Exception as e:
                print(f"❌ Could not list functions: {e}")
                
        except Exception as e:
            print(f"❌ Error creating OnchainID contract: {e}")
        
        # Step 6: Check compliance contract configuration
        print("\n📋 STEP 6: Check Compliance Contract")
        print("-" * 50)
        try:
            # Try different compliance ABI types
            compliance_contract = None
            for abi_type in ['ModularCompliance', 'Compliance', 'ICompliance']:
                try:
                    compliance_contract = web3_service.w3.eth.contract(
                        address=compliance_address,
                        abi=web3_service.contract_abis.get(abi_type, [])
                    )
                    print(f"✅ Using {abi_type} ABI for Compliance")
                    break
                except Exception as e:
                    print(f"⚠️ Could not use {abi_type} ABI: {e}")
            
            if compliance_contract:
                # Check if compliance is bound to the token - try different function names
                bound_token = None
                for func_name in ['token', 'getToken', 'tokenAddress']:
                    try:
                        bound_token = compliance_contract.functions[func_name]().call()
                        print(f"✅ Compliance bound to token ({func_name}): {bound_token}")
                        break
                    except Exception as e:
                        print(f"⚠️ Could not call {func_name}: {e}")
                
                if bound_token:
                    if bound_token.lower() == token_address.lower():
                        print("✅ Compliance is correctly bound to our token")
                    else:
                        print(f"❌ Compliance bound to wrong token! Expected: {token_address}")
                else:
                    print("⚠️ Could not determine bound token")
            else:
                print("❌ Could not create compliance contract with any ABI")
                
        except Exception as e:
            print(f"❌ Error checking compliance contract: {e}")
        
        # Step 7: Manual verification logic (like V1 would do)
        print("\n📋 STEP 7: Manual Verification Logic")
        print("-" * 50)
        print("This is what the isVerified() function should be checking:")
        print("1. User must be registered in Identity Registry ✅")
        print("2. User must have OnchainID ✅") 
        print("3. OnchainID must have claims for ALL required topics")
        print("4. Each claim must be from a trusted issuer")
        print("5. Each trusted issuer must be approved for that topic")
        print("6. Claims must be valid (not expired, correct status)")
        print()
        print("🔍 Let's check each requirement manually...")
        
        # Check if user has claims for required topics
        try:
            # Get required topics (we know it should be [1] from deployment)
            required_topics = [1]  # From deployment logs
            
            print(f"Required topics: {required_topics}")
            
            # Check if user has claims for each required topic
            onchain_id_contract = web3_service.w3.eth.contract(
                address=onchain_id_address,
                abi=web3_service.contract_abis.get('Identity', [])
            )
            
            # Use the correct function: getClaimIdsByTopic
            missing_topics = []
            for topic in required_topics:
                try:
                    claim_ids = onchain_id_contract.functions.getClaimIdsByTopic(topic).call()
                    if claim_ids and len(claim_ids) > 0:
                        print(f"✅ Has {len(claim_ids)} claim(s) for topic {topic}")
                        # Check if any claim is from the correct trusted issuer
                        valid_claim_found = False
                        for claim_id in claim_ids:
                            try:
                                claim_data = onchain_id_contract.functions.getClaim(claim_id).call()
                                if len(claim_data) >= 3:
                                    issuer = claim_data[2]  # issuer is at index 2
                                    if issuer.lower() == trusted_issuer_address.lower():
                                        print(f"   ✅ Valid claim from trusted issuer: {issuer}")
                                        valid_claim_found = True
                                        break
                                    else:
                                        print(f"   ⚠️ Claim from wrong issuer: {issuer}")
                            except Exception as e:
                                print(f"   ❌ Could not get claim data: {e}")
                        
                        if not valid_claim_found:
                            print(f"   ❌ No valid claims from trusted issuer for topic {topic}")
                            missing_topics.append(topic)
                    else:
                        print(f"❌ No claims found for topic {topic}")
                        missing_topics.append(topic)
                except Exception as e:
                    print(f"❌ Error checking topic {topic}: {e}")
                    missing_topics.append(topic)
            
            if missing_topics:
                print(f"❌ User is missing valid claims for topics: {missing_topics}")
                print("This is why isVerified() returns False!")
            else:
                print("✅ User has valid claims for all required topics")
                
        except Exception as e:
            print(f"❌ Error in manual verification: {e}")
        
        print("\n" + "=" * 60)
        print("🎯 SUMMARY")
        print("=" * 60)
        print("Check the output above to identify why isVerified() returns False.")
        print("Common issues:")
        print("1. User missing claims for required topics")
        print("2. Claims from wrong trusted issuer")
        print("3. Trusted issuer not approved for required topics")
        print("4. Claims expired or invalid status")
        print("5. Compliance contract not properly configured")

if __name__ == "__main__":
    debug_isverified_comprehensive()
