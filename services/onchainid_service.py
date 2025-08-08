import json
import secrets
from datetime import datetime
from eth_account import Account
from services.web3_service import Web3Service
from models import db
from models.contract import Contract
from models.user import User

class OnchainIDService:
    """Service for OnchainID operations using IdFactory contract"""
    
    def __init__(self, web3_service=None):
        if web3_service:
            self.web3_service = web3_service
        else:
            self.web3_service = Web3Service()
        
        # Claim topics (Tokeny standard ERC-3643 topics)
        self.CLAIM_TOPICS = {
            'KYC_STATUS': 1,           # KYC approval status
            'NATIONALITY': 2,          # Nationality/country
            'AGE_VERIFICATION': 3,     # Age verification
            'ACCREDITED': 4,           # Accredited investor status
            'RESIDENCY': 5,            # Residency status
            'COMPLIANCE': 6,           # General compliance status
            'RESTRICTED': 7,           # Restricted status
            'WHITELISTED': 8,          # Whitelisted status
            'CUSTOM': 9                # Custom claims
        }

    def get_claimissuer_address_for_user(self, user_id):
        """Get the ClaimIssuer contract address for a trusted issuer user"""
        try:
            user = User.query.get(user_id)
            if user and user.claim_issuer_address:
                return user.claim_issuer_address
            else:
                raise Exception(f"No ClaimIssuer found for user {user_id}")
        except Exception as e:
            raise Exception(f"Failed to get ClaimIssuer address: {str(e)}")
    
    def get_id_factory_address(self):
        """Get the IdFactory contract address from database"""
        try:
            contract = Contract.query.filter_by(contract_type='IdentityFactory').first()
            if contract:
                return contract.contract_address
            else:
                raise Exception("IdentityFactory not deployed. Please deploy T-REX factory first.")
        except Exception as e:
            raise Exception(f"Failed to get IdentityFactory address: {str(e)}")
    
    def create_onchainid(self, wallet_address, kyc_data=None):
        """
        Create OnchainID for a wallet address using IdFactory
        
        Args:
            wallet_address (str): The wallet address
            kyc_data (dict): KYC information (optional)
            
        Returns:
            dict: OnchainID creation result
        """
        try:
            print(f"🎯 Creating OnchainID for wallet: {wallet_address}")
            
            # Get IdFactory address
            id_factory_address = self.get_id_factory_address()
            print(f"📋 Using IdFactory: {id_factory_address}")
            
            # Check if OnchainID already exists for this wallet
            existing_onchainid = self.get_existing_onchainid(wallet_address, id_factory_address)
            if existing_onchainid:
                print(f"✅ OnchainID already exists: {existing_onchainid}")
                return {
                    'success': True,
                    'onchainid_address': existing_onchainid,
                    'is_new': False,
                    'message': 'OnchainID already exists'
                }
            
            # Create new OnchainID using IdFactory
            print("🏭 Creating new OnchainID via IdFactory...")
            
            # Get IdFactory contract using Web3Service (now loaded as 'Factory')
            id_factory_contract = self.web3_service.get_contract('Factory', id_factory_address)
            if not id_factory_contract:
                raise Exception("Failed to get IdFactory contract")
            
            # Call createIdentity function - use the actual IdFactory contract
            tx_hash = self.web3_service.transact_contract_function(
                'Factory',
                id_factory_address,
                'createIdentity',
                wallet_address,
                self.web3_service.default_account  # recovery address (same as wallet for now)
            )
            
            print(f"✅ OnchainID creation transaction: {tx_hash}")
            
            # Get the created OnchainID address
            onchainid_address = self.web3_service.call_contract_function(
                'Factory',
                id_factory_address,
                'identity',
                wallet_address
            )
            
            print(f"✅ Created OnchainID: {onchainid_address}")
            
            return {
                'success': True,
                'onchainid_address': onchainid_address,
                'tx_hash': tx_hash,
                'is_new': True,
                'message': 'OnchainID created successfully'
            }
            
        except Exception as e:
            print(f"❌ Error creating OnchainID: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to create OnchainID: {str(e)}'
            }
    
    def get_existing_onchainid(self, wallet_address, id_factory_address):
        """Check if OnchainID already exists for a wallet"""
        try:
            # Call identity function on IdFactory
            onchainid_address = self.web3_service.call_contract_function(
                'Factory',
                id_factory_address,
                'identity',
                wallet_address
            )
            
            # Check if the address is not zero
            if onchainid_address and onchainid_address != "0x" + "0" * 40:
                return onchainid_address
            else:
                return None
                
        except Exception as e:
            print(f"⚠️  Error checking existing OnchainID: {str(e)}")
            return None
    
    def add_claim(self, onchainid_address, topic, issuer, data, signature=None):
        """
        DEPRECATED: Use HybridClaimService.add_claim() instead.
        This method is kept for backward compatibility but will be removed.
        """
        print("⚠️ DEPRECATED: Use HybridClaimService.add_claim() instead")
        from services.hybrid_claim_service import HybridClaimService
        
        # This is a legacy method - redirect to hybrid service
        # Note: This won't work perfectly since we need user IDs, not addresses
        return {
            'success': False,
            'error': 'This method is deprecated. Use HybridClaimService.add_claim() with user IDs instead.'
        }

    def add_claim_with_claimissuer(self, onchainid_address, topic, trusted_issuer_user_id, data, signature=None):
        """
        DEPRECATED: Use HybridClaimService.add_claim() instead.
        This method is kept for backward compatibility but will be removed.
        """
        print("⚠️ DEPRECATED: Use HybridClaimService.add_claim() instead")
        return {
            'success': False,
            'error': 'This method is deprecated. Use HybridClaimService.add_claim() with user IDs instead.'
        }
    
    def remove_claim(self, onchainid_address, claim_id):
        """
        Remove a claim from an OnchainID
        
        Args:
            onchainid_address (str): The OnchainID address
            claim_id (bytes32): The claim ID to remove
            
        Returns:
            dict: Result of removing claim
        """
        try:
            print(f"🎯 Removing claim from OnchainID: {onchainid_address}")
            print(f"📋 Claim ID: {claim_id}")
            
            # Remove claim
            tx_hash = self.web3_service.transact_contract_function(
                'Identity',
                onchainid_address,
                'removeClaim',
                claim_id
            )
            
            print(f"✅ Claim removed successfully: {tx_hash}")
            
            return {
                'success': True,
                'tx_hash': tx_hash
            }
            
        except Exception as e:
            print(f"❌ Error removing claim: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to remove claim: {str(e)}'
            }
    
    def get_claims(self, onchainid_address):
        """
        Get all claims for an OnchainID
        
        Args:
            onchainid_address (str): The OnchainID address
            
        Returns:
            dict: Claims information
        """
        try:
            print(f"🎯 Getting claims for OnchainID: {onchainid_address}")
            
            # Get OnchainID contract using Web3Service
            onchainid_contract = self.web3_service.get_contract('Identity', onchainid_address)
            if not onchainid_contract:
                raise Exception("Failed to get Identity contract")
            
            # Get claim count
            claim_count = onchainid_contract.functions.getClaimCount().call()
            print(f"📋 Found {claim_count} claims")
            
            claims = []
            for i in range(claim_count):
                try:
                    claim = onchainid_contract.functions.getClaimByIndex(i).call()
                    claims.append({
                        'index': i,
                        'topic': claim[0],
                        'scheme': claim[1],
                        'issuer': claim[2],
                        'signature': claim[3],
                        'data': claim[4],
                        'uri': claim[5]
                    })
                except Exception as e:
                    print(f"⚠️  Error getting claim {i}: {str(e)}")
                    continue
            
            return {
                'success': True,
                'claims': claims,
                'count': claim_count
            }
            
        except Exception as e:
            print(f"❌ Error getting claims: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to get claims: {str(e)}'
            }
    
    def verify_claim(self, onchainid_address, topic, issuer):
        """
        Verify if a claim exists for an OnchainID
        
        Args:
            onchainid_address (str): The OnchainID address
            topic (int): The claim topic
            issuer (str): The issuer address
            
        Returns:
            dict: Claim verification result
        """
        try:
            print(f"🎯 Verifying claim for OnchainID: {onchainid_address}")
            print(f"📋 Topic: {topic}, Issuer: {issuer}")
            
            # Get OnchainID contract using Web3Service
            onchainid_contract = self.web3_service.get_contract('Identity', onchainid_address)
            if not onchainid_contract:
                raise Exception("Failed to get Identity contract")
            
            # Get claim ID
            claim_id = onchainid_contract.functions.getClaimId(onchainid_address, issuer, topic).call()
            
            # Check if claim exists
            if claim_id != "0x" + "0" * 32:
                claim = onchainid_contract.functions.getClaim(claim_id).call()
                return {
                    'success': True,
                    'claim_exists': True,
                    'claim_id': claim_id,
                    'claim_data': {
                        'topic': claim[0],
                        'scheme': claim[1],
                        'issuer': claim[2],
                        'signature': claim[3],
                        'data': claim[4],
                        'uri': claim[5]
                    }
                }
            else:
                return {
                    'success': True,
                    'claim_exists': False,
                    'claim_id': None
                }
            
        except Exception as e:
            print(f"❌ Error verifying claim: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to verify claim: {str(e)}'
            }

    def add_claim_exact_hardhat_match(self, onchainid_address, topic, trusted_issuer_user_id, data):
        """
        DEPRECATED: Use HybridClaimService.add_claim() instead.
        This method is kept for backward compatibility but will be removed.
        """
        print("⚠️ DEPRECATED: Use HybridClaimService.add_claim() instead")
        return {
            'success': False,
            'error': 'This method is deprecated. Use HybridClaimService.add_claim() with user IDs instead.'
        }

    def get_onchainid_details(self, onchainid_address):
        """
        Get comprehensive OnchainID details including keys, claims, and topics
        
        Args:
            onchainid_address (str): The OnchainID address
            
        Returns:
            dict: Comprehensive OnchainID details
        """
        try:
            print(f"🔍 Getting comprehensive OnchainID details for: {onchainid_address}")
            
            # First, check if this address is actually a contract
            code = self.web3_service.w3.eth.get_code(onchainid_address)
            if code == b'':
                print(f"❌ Address {onchainid_address} is not a contract (no code)")
                return {
                    'error': f'Address {onchainid_address} is not a contract',
                    'address': onchainid_address
                }
            
            print(f"✅ Address {onchainid_address} is a contract with code length: {len(code)}")
            
            # Get contract instance using the same ABI as add_claim (IIdentity interface)
            import os
            import json
            
            # Load the IIdentity interface ABI (same as add_claim method)
            identity_interface_path = os.path.join(os.path.dirname(__file__), '..', 'artifacts', '@onchain-id', 'solidity', 'contracts', 'interface', 'IIdentity.sol', 'IIdentity.json')
            
            print(f"🔍 Loading IIdentity interface ABI for details from: {identity_interface_path}")
            
            with open(identity_interface_path, 'r') as f:
                identity_interface_artifact = json.load(f)
                onchainid_abi = identity_interface_artifact['abi']
            
            contract = self.web3_service.w3.eth.contract(
                address=onchainid_address,
                abi=onchainid_abi
            )
            
            details = {
                'address': onchainid_address,
                'keys': {
                    'management_keys': [],
                    'action_keys': [],
                    'claim_signer_keys': []
                },
                'claims': [],
                'claim_topics': {},
                'total_claims': 0,
                'total_keys': 0
            }
            
            # Get all keys by purpose
            try:
                print(f"🔍 Fetching keys for OnchainID: {onchainid_address}")
                
                # Purpose 1: Management Keys
                print(f"🔍 Getting management keys (purpose 1)...")
                try:
                    management_keys = contract.functions.getKeysByPurpose(1).call()
                    print(f"🔍 Found {len(management_keys)} management keys: {[k.hex() for k in management_keys]}")
                except Exception as e:
                    print(f"❌ Error calling getKeysByPurpose(1): {str(e)}")
                    print(f"❌ Error type: {type(e)}")
                    management_keys = []
                
                for key_hash in management_keys:
                    key_info = contract.functions.getKey(key_hash).call()
                    print(f"🔍 Key info for {key_hash.hex()}: {key_info}")
                    # Convert purposes to a list of integers
                    purposes_list = [int(p) for p in key_info[0]] if key_info[0] else []
                    print(f"🔍 Purposes list: {purposes_list}")
                    
                    details['keys']['management_keys'].append({
                        'key_hash': key_hash.hex(),
                        'purposes': purposes_list,
                        'key_type': int(key_info[1]),
                        'key_data': key_info[2].hex()
                    })
                    print(f"🔍 Added management key: {key_hash.hex()}")
                
                # Purpose 2: Action Keys
                print(f"🔍 Getting action keys (purpose 2)...")
                action_keys = contract.functions.getKeysByPurpose(2).call()
                print(f"🔍 Found {len(action_keys)} action keys: {[k.hex() for k in action_keys]}")
                
                for key_hash in action_keys:
                    key_info = contract.functions.getKey(key_hash).call()
                    print(f"🔍 Key info for {key_hash.hex()}: {key_info}")
                    # Convert purposes to a list of integers
                    purposes_list = [int(p) for p in key_info[0]] if key_info[0] else []
                    
                    details['keys']['action_keys'].append({
                        'key_hash': key_hash.hex(),
                        'purposes': purposes_list,
                        'key_type': int(key_info[1]),
                        'key_data': key_info[2].hex()
                    })
                
                # Purpose 3: Claim Signer Keys
                print(f"🔍 Getting claim signer keys (purpose 3)...")
                claim_signer_keys = contract.functions.getKeysByPurpose(3).call()
                print(f"🔍 Found {len(claim_signer_keys)} claim signer keys: {[k.hex() for k in claim_signer_keys]}")
                
                for key_hash in claim_signer_keys:
                    key_info = contract.functions.getKey(key_hash).call()
                    print(f"🔍 Key info for {key_hash.hex()}: {key_info}")
                    # Convert purposes to a list of integers
                    purposes_list = [int(p) for p in key_info[0]] if key_info[0] else []
                    
                    details['keys']['claim_signer_keys'].append({
                        'key_hash': key_hash.hex(),
                        'purposes': purposes_list,
                        'key_type': int(key_info[1]),
                        'key_data': key_info[2].hex()
                    })
                
                # Calculate total keys after all keys have been processed
                management_count = len(details['keys']['management_keys'])
                action_count = len(details['keys']['action_keys'])
                claim_signer_count = len(details['keys']['claim_signer_keys'])
                
                details['total_keys'] = management_count + action_count + claim_signer_count
                
                print(f"🔍 Key counts calculation:")
                print(f"  - Management keys: {management_count}")
                print(f"  - Action keys: {action_count}")
                print(f"  - Claim signer keys: {claim_signer_count}")
                print(f"  - Total keys: {details['total_keys']}")
                print(f"🔍 Final details['keys'] structure:")
                print(f"  - management_keys: {len(details['keys']['management_keys'])} items")
                print(f"  - action_keys: {len(details['keys']['action_keys'])} items")
                print(f"  - claim_signer_keys: {len(details['keys']['claim_signer_keys'])} items")
                
            except Exception as key_error:
                print(f"⚠️ Error getting keys: {key_error}")
                details['key_error'] = str(key_error)
            
            # Get all claims and topics
            try:
                # Common claim topics (1-20)
                common_topics = list(range(1, 21))
                
                for topic in common_topics:
                    try:
                        # Get claim IDs for this topic
                        claim_ids = contract.functions.getClaimIdsByTopic(topic).call()
                        
                        if claim_ids:
                            details['claim_topics'][topic] = []
                            
                            for claim_id in claim_ids:
                                try:
                                    # Get claim details
                                    claim = contract.functions.getClaim(claim_id).call()
                                    
                                    # Decode claim data
                                    claim_data_decoded = ''
                                    try:
                                        claim_data_decoded = self.web3_service.w3.to_text(claim[4])  # claim[4] is data
                                    except:
                                        claim_data_decoded = claim[4].hex()
                                    
                                    claim_info = {
                                        'claim_id': claim_id.hex(),
                                        'topic': claim[0],
                                        'scheme': claim[1],
                                        'issuer': claim[2],
                                        'signature': claim[3].hex(),
                                        'data': claim[4].hex(),
                                        'data_decoded': claim_data_decoded,
                                        'uri': claim[5]
                                    }
                                    
                                    details['claims'].append(claim_info)
                                    details['claim_topics'][topic].append(claim_id.hex())
                                    
                                except Exception as claim_error:
                                    print(f"⚠️ Error getting claim {claim_id}: {claim_error}")
                                    continue
                    
                    except Exception as topic_error:
                        print(f"⚠️ Error getting claims for topic {topic}: {topic_error}")
                        continue
                
                details['total_claims'] = len(details['claims'])
                
            except Exception as claim_error:
                print(f"⚠️ Error getting claims: {claim_error}")
                details['claim_error'] = str(claim_error)
            
            return details
            
        except Exception as e:
            print(f"❌ Error getting OnchainID details: {str(e)}")
            return {
                'error': f'Failed to get OnchainID details: {str(e)}',
                'address': onchainid_address
            } 