import json
import os
from web3 import Web3
from services.web3_service import Web3Service

class OnchainClaimsService:
    """Service for on-chain claim verification using ERC-3643 contracts"""
    
    def __init__(self, private_key=None):
        self.web3_service = Web3Service(private_key)
        self.w3 = self.web3_service.w3
        
        # Load contract ABIs
        self.onchainid_abi = self._load_abi('OnchainID')
        self.identity_registry_abi = self._load_abi('IdentityRegistry')
        self.trusted_issuers_registry_abi = self._load_abi('TrustedIssuersRegistry')
        self.claim_topics_registry_abi = self._load_abi('ClaimTopicsRegistry')
    
    def _load_abi(self, contract_name):
        """Load contract ABI from the contracts directory"""
        try:
            abi_path = f"contracts/{contract_name}.json"
            if os.path.exists(abi_path):
                with open(abi_path, 'r') as f:
                    contract_data = json.load(f)
                    return contract_data.get('abi', [])
            else:
                # Fallback to hardcoded ABIs for key methods
                return self._get_fallback_abi(contract_name)
        except Exception as e:
            print(f"Warning: Could not load ABI for {contract_name}: {e}")
            return self._get_fallback_abi(contract_name)
    
    def _get_fallback_abi(self, contract_name):
        """Fallback ABIs for key methods we need"""
        if contract_name == 'OnchainID':
            return [
                {
                    "inputs": [{"internalType": "uint256", "name": "topic", "type": "uint256"}],
                    "name": "getClaimIdsByTopic",
                    "outputs": [{"internalType": "uint256[]", "name": "", "type": "uint256[]"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [{"internalType": "uint256", "name": "claimId", "type": "uint256"}],
                    "name": "getClaim",
                    "outputs": [
                        {"internalType": "uint256", "name": "topic", "type": "uint256"},
                        {"internalType": "uint256", "name": "scheme", "type": "uint256"},
                        {"internalType": "address", "name": "issuer", "type": "address"},
                        {"internalType": "bytes", "name": "signature", "type": "bytes"},
                        {"internalType": "bytes", "name": "data", "type": "bytes"},
                        {"internalType": "string", "name": "uri", "type": "string"}
                    ],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
        elif contract_name == 'IdentityRegistry':
            return [
                {
                    "inputs": [{"internalType": "address", "name": "user", "type": "address"}],
                    "name": "isVerified",
                    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [{"internalType": "address", "name": "user", "type": "address"}],
                    "name": "identity",
                    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
        elif contract_name == 'TrustedIssuersRegistry':
            return [
                {
                    "inputs": [{"internalType": "uint256", "name": "topic", "type": "uint256"}],
                    "name": "getTrustedIssuersForClaimTopic",
                    "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
        elif contract_name == 'ClaimTopicsRegistry':
            return [
                {
                    "inputs": [],
                    "name": "getClaimTopics",
                    "outputs": [{"internalType": "uint256[]", "name": "", "type": "uint256[]"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
        return []
    
    def get_onchainid_claims(self, onchainid_address):
        """Get all claims from an OnchainID contract on-chain"""
        try:
            if not Web3.is_address(onchainid_address):
                raise ValueError(f"Invalid OnchainID address: {onchainid_address}")
            
            onchainid_contract = self.w3.eth.contract(
                address=onchainid_address,
                abi=self.onchainid_abi
            )
            
            # Common claim topics (1-20)
            common_topics = list(range(1, 21))
            claims = []
            processed_claim_ids = set()
            
            for topic_id in common_topics:
                try:
                    # Get claim IDs for this topic
                    claim_ids = onchainid_contract.functions.getClaimIdsByTopic(topic_id).call()
                    
                    if claim_ids:
                        for claim_id in claim_ids:
                            claim_id_str = str(claim_id)
                            if claim_id_str in processed_claim_ids:
                                continue
                            
                            try:
                                # Get the actual claim data
                                claim = onchainid_contract.functions.getClaim(claim_id).call()
                                
                                # Decode claim data
                                try:
                                    claim_data = self.w3.to_text(claim[4])  # claim.data
                                except:
                                    claim_data = claim[4].hex()  # Fallback to hex
                                
                                claims.append({
                                    'id': claim_id_str,
                                    'topic': claim[0],  # claim.topic
                                    'scheme': claim[1],  # claim.scheme
                                    'issuer': claim[2],  # claim.issuer
                                    'signature': claim[3].hex(),  # claim.signature
                                    'data': claim_data,
                                    'uri': claim[5]  # claim.uri
                                })
                                processed_claim_ids.add(claim_id_str)
                                
                            except Exception as claim_error:
                                print(f"Error getting claim {claim_id}: {claim_error}")
                                
                except Exception as topic_error:
                    print(f"Error checking topic {topic_id}: {topic_error}")
            
            return {
                'success': True,
                'claims': claims,
                'total_claims': len(claims),
                'onchainid_address': onchainid_address
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'claims': [],
                'total_claims': 0,
                'onchainid_address': onchainid_address
            }
    
    def check_user_verification(self, user_address, identity_registry_address):
        """Check if a user is verified in the Identity Registry"""
        try:
            if not Web3.is_address(user_address) or not Web3.is_address(identity_registry_address):
                raise ValueError("Invalid address provided")
            
            ir_contract = self.w3.eth.contract(
                address=identity_registry_address,
                abi=self.identity_registry_abi
            )
            
            # Check if user is verified
            is_verified = ir_contract.functions.isVerified(user_address).call()
            
            # Get user's OnchainID address
            try:
                onchainid_address = ir_contract.functions.identity(user_address).call()
            except:
                onchainid_address = None
            
            return {
                'success': True,
                'is_verified': is_verified,
                'user_address': user_address,
                'onchainid_address': onchainid_address,
                'identity_registry': identity_registry_address
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'is_verified': False,
                'user_address': user_address,
                'identity_registry': identity_registry_address
            }
    
    def get_trusted_issuers_for_topic(self, topic, trusted_issuers_registry_address):
        """Get trusted issuers for a specific claim topic"""
        try:
            if not Web3.is_address(trusted_issuers_registry_address):
                raise ValueError("Invalid TrustedIssuersRegistry address")
            
            tir_contract = self.w3.eth.contract(
                address=trusted_issuers_registry_address,
                abi=self.trusted_issuers_registry_abi
            )
            
            trusted_issuers = tir_contract.functions.getTrustedIssuersForClaimTopic(topic).call()
            
            return {
                'success': True,
                'topic': topic,
                'trusted_issuers': [issuer.lower() for issuer in trusted_issuers],
                'registry_address': trusted_issuers_registry_address
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'topic': topic,
                'trusted_issuers': [],
                'registry_address': trusted_issuers_registry_address
            }
    
    def get_token_claim_requirements(self, claim_topics_registry_address):
        """Get required claim topics for a token"""
        try:
            if not Web3.is_address(claim_topics_registry_address):
                raise ValueError("Invalid ClaimTopicsRegistry address")
            
            ctr_contract = self.w3.eth.contract(
                address=claim_topics_registry_address,
                abi=self.claim_topics_registry_abi
            )
            
            required_topics = ctr_contract.functions.getClaimTopics().call()
            
            return {
                'success': True,
                'required_topics': [topic for topic in required_topics],
                'registry_address': claim_topics_registry_address
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'required_topics': [],
                'registry_address': claim_topics_registry_address
            }
    
    def comprehensive_claims_check(self, user_address, token_address, deployment_details):
        """Comprehensive check of user's claims against token requirements"""
        try:
            # Get token's contract addresses from deployment details
            token_data = deployment_details.get('tokens', {}).get(token_address, {})
            identity_registry = token_data.get('identityRegistry')
            trusted_issuers_registry = token_data.get('trustedIssuersRegistry')
            claim_topics_registry = token_data.get('claimTopicsRegistry')
            
            if not all([identity_registry, trusted_issuers_registry, claim_topics_registry]):
                raise ValueError("Missing required registry addresses in deployment details")
            
            # 1. Check if user is verified
            verification_result = self.check_user_verification(user_address, identity_registry)
            if not verification_result['success']:
                return {
                    'success': False,
                    'error': f"Verification check failed: {verification_result['error']}"
                }
            
            # 2. Get user's OnchainID
            onchainid_address = verification_result['onchainid_address']
            if not onchainid_address:
                return {
                    'success': False,
                    'error': "User has no OnchainID registered",
                    'is_verified': False
                }
            
            # 3. Get token's required claim topics
            topics_result = self.get_token_claim_requirements(claim_topics_registry)
            if not topics_result['success']:
                return {
                    'success': False,
                    'error': f"Failed to get token claim topics: {topics_result['error']}"
                }
            
            required_topics = topics_result['required_topics']
            if not required_topics:
                return {
                    'success': True,
                    'is_verified': verification_result['is_verified'],
                    'compliant': True,
                    'message': "Token has no claim requirements - always compliant"
                }
            
            # 4. Get user's claims from OnchainID
            claims_result = self.get_onchainid_claims(onchainid_address)
            if not claims_result['success']:
                return {
                    'success': False,
                    'error': f"Failed to get user claims: {claims_result['error']}"
                }
            
            user_claims = claims_result['claims']
            
            # 5. Check each required topic
            missing_topics = []
            invalid_claims = []
            valid_claims = []
            
            for topic in required_topics:
                topic_num = topic
                
                # Get trusted issuers for this topic
                trusted_result = self.get_trusted_issuers_for_topic(topic_num, trusted_issuers_registry)
                if not trusted_result['success']:
                    invalid_claims.append({
                        'topic': topic_num,
                        'error': f"Failed to get trusted issuers: {trusted_result['error']}"
                    })
                    continue
                
                trusted_issuers = trusted_result['trusted_issuers']
                
                # Find user's claims for this topic
                topic_claims = [claim for claim in user_claims if claim['topic'] == topic_num]
                
                if not topic_claims:
                    missing_topics.append(topic_num)
                else:
                    # Check if any claim is from a trusted issuer
                    has_valid_claim = False
                    for claim in topic_claims:
                        if claim['issuer'].lower() in trusted_issuers:
                            has_valid_claim = True
                            valid_claims.append(claim)
                            break
                    
                    if not has_valid_claim:
                        invalid_claims.append({
                            'topic': topic_num,
                            'claims': topic_claims,
                            'trusted_issuers': trusted_issuers,
                            'error': "No claims from trusted issuers"
                        })
            
            # 6. Determine compliance
            is_compliant = len(missing_topics) == 0 and len(invalid_claims) == 0
            
            return {
                'success': True,
                'is_verified': verification_result['is_verified'],
                'compliant': is_compliant,
                'user_address': user_address,
                'token_address': token_address,
                'onchainid_address': onchainid_address,
                'required_topics': required_topics,
                'missing_topics': missing_topics,
                'valid_claims': valid_claims,
                'invalid_claims': invalid_claims,
                'total_user_claims': len(user_claims)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'user_address': user_address,
                'token_address': token_address
            } 