from services.web3_service import Web3Service
from eth_account import Account
import json
from pathlib import Path
import os
import time

class TREXService:
    """Service for TREX (ERC-3643) specific operations"""
    
    def __init__(self, web3_service: Web3Service):
        self.web3 = web3_service
        self.w3 = web3_service.w3
        
        # Load contract addresses from database
        self.gateway_address = self._get_contract_address('TREXGateway')
        self.factory_address = self._get_contract_address('TREXFactory')
        self.identity_registry_address = self._get_contract_address('IdentityRegistry')
        self.claim_topics_registry_address = self._get_contract_address('ClaimTopicsRegistry')
        self.trusted_issuers_registry_address = self._get_contract_address('TrustedIssuersRegistry')
        self.implementation_authority_address = self._get_contract_address('TREXImplementationAuthority')
        
        # Initialize contracts (only if addresses are available)
        self.gateway_contract = None
        if self.gateway_address:
            self.gateway_contract = self.web3.get_contract(self.gateway_address, 'TREXGateway')
        
        self.factory_contract = None
        if self.factory_address:
            self.factory_contract = self.web3.get_contract(self.factory_address, 'TREXFactory')
        
        if self.identity_registry_address:
            self.identity_registry_contract = self.web3.get_contract(self.identity_registry_address, 'IdentityRegistry')
        
        if self.claim_topics_registry_address:
            self.claim_topics_registry_contract = self.web3.get_contract(self.claim_topics_registry_address, 'ClaimTopicsRegistry')
        
        if self.trusted_issuers_registry_address:
            self.trusted_issuers_registry_contract = self.web3.get_contract(self.trusted_issuers_registry_address, 'TrustedIssuersRegistry')
    
    def _get_contract_address(self, contract_type):
        """Get contract address from database"""
        try:
            from models import Contract
            from flask import current_app
            
            with current_app.app_context():
                contract = Contract.query.filter_by(contract_type=contract_type).first()
                return contract.contract_address if contract else None
        except Exception as e:
            print(f"Warning: Could not load {contract_type} address from database: {e}")
            return None
    
    def _hash_address_abi_encoded(self, address):
        """
        Hash an address using 32-byte ABI encoding (correct method for OnchainID contracts)
        
        Args:
            address (str): Ethereum address to hash
            
        Returns:
            bytes: 32-byte keccak hash of the ABI-encoded address
        """
        return self.w3.keccak(
            self.w3.codec.encode(['address'], [address])
        )
    
    def deploy_token(self, issuer_address, token_name, token_symbol, total_supply, 
                    ir_agent, token_agent, claim_topics, claim_issuer_type, claim_issuer_id=None):
        """Deploy a new security token using direct Python deployment"""
        try:
            from scripts.deploy_token import TokenDeployment
            
            # Create deployment instance
            deployment = TokenDeployment()
            
            # Set token details directly
            deployment.token_details.update({
                'name': token_name,
                'symbol': token_symbol,
                'decimals': 18,
                'totalSupply': str(total_supply),
                'tokenAgents': [issuer_address] if token_agent == 'issuer' else [self.web3.default_account],
                'irAgents': [issuer_address] if ir_agent == 'issuer' else [self.web3.default_account],
                'complianceAgents': [issuer_address] if token_agent == 'issuer' else [self.web3.default_account]
            })
            
            # Determine claim issuer address
            if claim_issuer_type == 'trusted_issuer' and claim_issuer_id:
                from models.user import User
                trusted_issuer = User.query.get(claim_issuer_id)
                if not trusted_issuer:
                    return {'success': False, 'error': 'Trusted issuer not found'}
                print(f"🔍 DEBUG: Trusted issuer found: {trusted_issuer.username}")
                print(f"🔍 DEBUG: Wallet address: {trusted_issuer.wallet_address}")
                print(f"🔍 DEBUG: Claim issuer address: {trusted_issuer.claim_issuer_address}")
                claim_issuer_address = trusted_issuer.claim_issuer_address
                print(f"🔍 DEBUG: Using claim_issuer_address: {claim_issuer_address}")
            elif claim_issuer_type == 'issuer':
                claim_issuer_address = issuer_address
            else: # admin
                claim_issuer_address = self.web3.default_account
            
            # Set claim details directly - proper T-REX structure
            # issuerClaims should be an array of arrays, where each inner array contains the topics for that issuer
            print(f"🔍 DEBUG: claim_topics parameter: {claim_topics}")
            print(f"🔍 DEBUG: claim_topics type: {type(claim_topics)}")
            claim_topics_int = [int(topic) for topic in claim_topics]
            print(f"🔍 DEBUG: claim_topics_int: {claim_topics_int}")
            deployment.claim_details = {
                'claimTopics': claim_topics_int,
                'issuers': [claim_issuer_address],
                'issuerClaims': [claim_topics_int]  # Array of arrays - each issuer gets all topics
            }
            print(f"🔍 DEBUG: deployment.claim_details: {deployment.claim_details}")
            
            # Store claim issuer address for deployment script
            deployment.claim_issuer_address = claim_issuer_address
            print(f"🔍 DEBUG: Storing claim_issuer_address in deployment: {claim_issuer_address}")
            
            print(f"🔧 Token Details Structure:")
            print(f"   Name: {deployment.token_details['name']}")
            print(f"   Symbol: {deployment.token_details['symbol']}")
            print(f"   Total Supply: {deployment.token_details['totalSupply']}")
            print(f"   Token Agents: {deployment.token_details['tokenAgents']}")
            print(f"   IR Agents: {deployment.token_details['irAgents']}")
            print(f"   Compliance Agents: {deployment.token_details['complianceAgents']}")
            
            print(f"🔧 Claim Details Structure:")
            print(f"   Claim Topics: {deployment.claim_details['claimTopics']}")
            print(f"   Issuers: {deployment.claim_details['issuers']}")
            print(f"   Issuer Claims: {deployment.claim_details['issuerClaims']}")
            print(f"   Claim Issuer Address: {claim_issuer_address}")
            
            # Deploy the token
            deployment_result = deployment.deploy(deployer_address=issuer_address)
            
            # Check if deployment was successful
            if not deployment_result.get('success', False):
                return deployment_result  # Return the error from deployment script
            
            # The deployment script now returns all contract addresses
            # The route will handle the database storage
            return {
                'success': True,
                'token_address': deployment_result['token_address'],
                'identity_registry': deployment_result['identity_registry'],
                'compliance': deployment_result['compliance'],
                'claim_topics_registry': deployment_result['claim_topics_registry'],
                'trusted_issuers_registry': deployment_result['trusted_issuers_registry']
            }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def check_issuer_gateway_authorization(self, issuer_address):
        """Check if an issuer is authorized to deploy through the Gateway"""
        try:
            if not self.gateway_address:
                return {'authorized': False, 'reason': 'Gateway not deployed'}
            
            if not self.gateway_contract:
                return {'authorized': False, 'reason': 'Gateway contract not loaded'}
            
            # Check if issuer is an approved deployer
            is_deployer = self.gateway_contract.functions.isDeployer(issuer_address).call()
            
            if is_deployer:
                return {'authorized': True, 'reason': 'Issuer is approved deployer'}
            
            # Check if public deployment is enabled
            public_enabled = self.gateway_contract.functions.getPublicDeploymentStatus().call()
            
            if public_enabled:
                return {'authorized': True, 'reason': 'Public deployment enabled'}
            
            return {'authorized': False, 'reason': 'Issuer not authorized and public deployment disabled'}
            
        except Exception as e:
            return {'authorized': False, 'reason': f'Error checking authorization: {str(e)}'}
    
    def check_investor_compliance(self, wallet_address, required_claim_topics=None):
        """Check if an investor is compliant for token transfers based on required claim topics"""
        try:
            # Check if wallet has an identity
            if not self.identity_registry_address:
                return {'compliant': False, 'reason': 'Identity registry not deployed'}
            
            has_identity = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'contains',
                wallet_address
            )
            
            if not has_identity:
                return {'compliant': False, 'reason': 'No identity registered'}
            
            # Get identity address
            identity_address = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'identity',
                wallet_address
            )
            
            # Use provided claim topics or default to KYC (topic 1)
            if required_claim_topics is None:
                required_claim_topics = [1]  # Default to KYC claim topic (1)
            
            # Check if identity has all required claims
            for topic in required_claim_topics:
                has_claim = self.web3.call_contract_function(
                    'IdentityRegistry',
                    self.identity_registry_address,
                    'hasClaim',
                    identity_address,
                    topic
                )
                
                if not has_claim:
                    return {'compliant': False, 'reason': f'Missing claim topic {topic}'}
            
            return {'compliant': True, 'reason': f'All required claims verified: {required_claim_topics}'}
            
        except Exception as e:
            return {'compliant': False, 'reason': f'Error checking compliance: {str(e)}'}
    
    def issue_claim(self, wallet_address, claim_topic, claim_value=1, issuer_address=None):
        """Issue a specific claim to an investor"""
        try:
            if not self.identity_registry_address:
                return {'success': False, 'error': 'Identity registry not deployed'}
            
            # Check if wallet has identity
            has_identity = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'contains',
                wallet_address
            )
            
            if not has_identity:
                return {'success': False, 'error': 'No identity registered for this wallet'}
            
            # Get identity address
            identity_address = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'identity',
                wallet_address
            )
            
            # Use provided issuer or default account
            issuer = issuer_address if issuer_address else self.web3.default_account
            
            # Issue claim
            tx_hash = self.web3.transact_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'addClaim',
                identity_address,
                claim_topic,
                claim_value,
                issuer
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def issue_kyc_claim(self, wallet_address):
        """Issue KYC claim to an investor (backward compatibility)"""
        return self.issue_claim(wallet_address, 1, 1)  # KYC topic 1, value 1
    
    def add_user_to_token_identity_registry(self, token_address, user_address, onchain_id_address, country_code=840):
        """Add a user's OnchainID to a token's Identity Registry"""
        try:
            # Get the token contract to find its Identity Registry
            token_info = self.get_token_info(token_address)
            if not token_info['success']:
                return {'success': False, 'error': 'Could not get token info'}
            
            identity_registry_address = token_info['token_info'].get('identity_registry')
            if not identity_registry_address:
                return {'success': False, 'error': 'Token has no Identity Registry'}
            
            # Check if user already has an OnchainID registered
            existing_onchain_id = self.web3.call_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'identity',
                user_address
            )
            
            if existing_onchain_id != '0x0000000000000000000000000000000000000000':
                return {'success': False, 'error': 'User already has OnchainID registered in this Identity Registry'}
            
            # Register the OnchainID in the token's Identity Registry
            tx_hash = self.web3.transact_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'registerIdentity',
                user_address,
                onchain_id_address,
                country_code
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def check_user_verification(self, token_address, user_address):
        """Check if a user is verified for a specific token using Identity Registry isVerified() method"""
        try:
            # Get the token contract to find its Identity Registry
            token_info = self.get_token_info(token_address)
            if not token_info['success']:
                return {'success': False, 'verified': False, 'reason': 'Could not get token info'}
            
            identity_registry_address = token_info['token_info'].get('identity_registry')
            if not identity_registry_address:
                return {'success': False, 'verified': False, 'reason': 'Token has no Identity Registry'}
            
            # Check if user has an OnchainID registered
            print(f"🔍 Calling identity() for user {user_address} on IR {identity_registry_address}")
            onchain_id_address = self.web3.call_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'identity',
                user_address
            )
            print(f"🔍 identity() result: {onchain_id_address}")
            
            if onchain_id_address == '0x0000000000000000000000000000000000000000':
                return {
                    'success': True, 
                    'verified': False, 
                    'reason': 'User has no OnchainID registered'
                }
            
            # Check if user is verified using Identity Registry's isVerified() method
            print(f"🔍 Calling isVerified for user {user_address} on IR {identity_registry_address}")
            is_verified = self.web3.call_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'isVerified',
                user_address
            )
            print(f"🔍 isVerified result: {is_verified}")
            
            # If not verified, let's check what claim topics are required
            if not is_verified:
                try:
                    # Get the compliance contract to check required claim topics
                    compliance_address = token_info['token_info'].get('compliance')
                    if compliance_address:
                        print(f"🔍 Checking compliance contract: {compliance_address}")
                        # Try to get claim topics from compliance
                        try:
                            # Try different compliance contract types
                            for contract_type in ['Compliance', 'ModularCompliance']:
                                try:
                                    claim_topics = self.web3.call_contract_function(
                                        contract_type,
                                        compliance_address,
                                        'getClaimTopics'
                                    )
                                    print(f"🔍 Required claim topics from {contract_type}: {claim_topics}")
                                    break
                                except Exception as e:
                                    print(f"⚠️ {contract_type} doesn't have getClaimTopics: {e}")
                        except Exception as e:
                            print(f"⚠️ Could not get claim topics: {e}")
                    
                    # Check trusted issuers registry
                    try:
                        # Get the trusted issuers registry from the Identity Registry
                        trusted_issuers_registry_address = self.web3.call_contract_function(
                            'IdentityRegistry',
                            identity_registry_address,
                            'issuersRegistry'
                        )
                        print(f"🔍 Trusted Issuers Registry: {trusted_issuers_registry_address}")
                        
                        # Get the claim topics registry
                        try:
                            claim_topics_registry_address = self.web3.call_contract_function(
                                'IdentityRegistry',
                                identity_registry_address,
                                'claimTopicsRegistry'
                            )
                            print(f"🔍 Claim Topics Registry: {claim_topics_registry_address}")
                            
                            # Get required claim topics
                            try:
                                required_topics = self.web3.call_contract_function(
                                    'ClaimTopicsRegistry',
                                    claim_topics_registry_address,
                                    'getClaimTopics'
                                )
                                print(f"🔍 Required claim topics: {required_topics}")
                            except Exception as e:
                                print(f"⚠️ Could not get required claim topics: {e}")
                        except Exception as e:
                            print(f"⚠️ Could not get claim topics registry: {e}")
                        
                        # Get trusted issuers
                        try:
                            trusted_issuers = self.web3.call_contract_function(
                                'TrustedIssuersRegistry',
                                trusted_issuers_registry_address,
                                'getTrustedIssuers'
                            )
                            print(f"🔍 Trusted issuers: {trusted_issuers}")
                        except Exception as e:
                            print(f"⚠️ Could not get trusted issuers: {e}")
                            
                    except Exception as e:
                        print(f"⚠️ Error checking trusted issuers: {e}")
                except Exception as e:
                    print(f"⚠️ Error checking compliance: {e}")
            
            if is_verified:
                return {
                    'success': True, 
                    'verified': True, 
                    'reason': 'User is verified'
                }
            else:
                return {
                    'success': True, 
                    'verified': False, 
                    'reason': 'User is not verified by Identity Registry'
                }
                
        except Exception as e:
            return {'success': False, 'verified': False, 'reason': f'Error checking verification: {str(e)}'}
    
    def purchase_tokens(self, token_address, investor_address, amount, required_claim_topics=None):
        """Purchase tokens if investor is compliant with required claim topics"""
        try:
            # Get required claim topics for this token if not provided
            if required_claim_topics is None:
                token_info = self.get_token_info(token_address)
                if token_info['success'] and 'claim_topics' in token_info['token_info']:
                    required_claim_topics = token_info['token_info']['claim_topics']
                else:
                    required_claim_topics = [1]  # Default to KYC
            
            # Check compliance first with specific claim topics
            compliance_check = self.check_investor_compliance(investor_address, required_claim_topics)
            if not compliance_check['compliant']:
                return {'success': False, 'error': compliance_check['reason']}
            
            # Check if token can be transferred
            can_transfer = self.web3.call_contract_function(
                'Token',
                token_address,
                'canTransfer',
                investor_address,
                investor_address,
                self.web3.parse_units(amount, 18)
            )
            
            if not can_transfer:
                return {'success': False, 'error': 'Transfer not allowed by compliance rules'}
            
            # Transfer tokens from issuer to investor (proper purchase flow)
            # First check if issuer has enough tokens
            issuer_balance = self.web3.call_contract_function(
                'Token',
                token_address,
                'balanceOf',
                self.web3.default_account
            )
            
            required_amount = self.web3.parse_units(amount, 18)
            if issuer_balance < required_amount:
                return {'success': False, 'error': 'Issuer does not have enough tokens for this purchase'}
            
            # Transfer tokens from issuer to investor
            tx_hash = self.web3.transact_contract_function(
                'Token',
                token_address,
                'transfer',
                investor_address,
                required_amount
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def mint_tokens(self, token_address, to_address, amount):
        """Mint tokens to a specific address - DEPRECATED: Use build_mint_transaction instead"""
        print("⚠️  WARNING: mint_tokens() is deprecated. Use build_mint_transaction() for MetaMask integration.")
        return self.build_mint_transaction(token_address, to_address, amount)
    
    def burn_tokens(self, token_address, from_address, amount):
        """Burn tokens from a specific address - DEPRECATED: Use build_burn_transaction instead"""
        print("⚠️  WARNING: burn_tokens() is deprecated. Use build_burn_transaction() for MetaMask integration.")
        return self.build_burn_transaction(token_address, from_address, amount)
    
    def force_transfer(self, token_address, from_address, to_address, amount):
        """Force transfer tokens from one address to another"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_from_address = self.web3.to_checksum_address(from_address)
            checksum_to_address = self.web3.to_checksum_address(to_address)
            
            print(f"🔍 Force transferring tokens:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   From address: {from_address} -> {checksum_from_address}")
            print(f"   To address: {to_address} -> {checksum_to_address}")
            print(f"   Amount: {amount}")
            
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Force transfer tokens
            tx_hash = self.web3.transact_contract_function(
                'Token',
                checksum_token_address,
                'forcedTransfer',
                checksum_from_address,
                checksum_to_address,
                amount_wei
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def transfer_tokens(self, token_address, from_address, to_address, amount):
        """Force transfer tokens from one address to another (for agents)"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_from_address = self.web3.to_checksum_address(from_address)
            checksum_to_address = self.web3.to_checksum_address(to_address)
            
            print(f"🔍 Transferring tokens:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   From address: {from_address} -> {checksum_from_address}")
            print(f"   To address: {to_address} -> {checksum_to_address}")
            print(f"   Amount: {amount}")
            
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Force transfer tokens from one address to another
            tx_hash = self.web3.transact_contract_function(
                'Token',
                checksum_token_address,
                'forcedTransfer',
                checksum_from_address,
                checksum_to_address,
                amount_wei
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_token_info(self, token_address):
        """Get comprehensive token information from blockchain"""
        try:
            print(f"🔍 DEBUG: get_token_info called for token: {token_address}")
            
            # Convert address to checksum format
            checksum_address = self.w3.to_checksum_address(token_address)
            print(f"🔍 Converted to checksum address: {checksum_address}")
            
            # Ensure Token ABI is loaded
            if 'Token' not in self.web3.contract_abis:
                print(f"❌ Token ABI not loaded in web3 service")
                return {'success': False, 'error': 'Token ABI not loaded'}
            
            print(f"✅ Token ABI loaded: {list(self.web3.contract_abis.keys())}")
            
            # Basic token info
            print(f"🔍 Calling token.name()...")
            name = self.web3.call_contract_function('Token', checksum_address, 'name')
            print(f"✅ Token name: {name}")
            
            print(f"🔍 Calling token.symbol()...")
            symbol = self.web3.call_contract_function('Token', checksum_address, 'symbol')
            print(f"✅ Token symbol: {symbol}")
            
            print(f"🔍 Calling token.decimals()...")
            decimals = self.web3.call_contract_function('Token', checksum_address, 'decimals')
            print(f"✅ Token decimals: {decimals}")
            
            print(f"🔍 Calling token.totalSupply()...")
            totalSupply = self.web3.call_contract_function('Token', checksum_address, 'totalSupply')
            print(f"✅ Token totalSupply: {totalSupply}")
            
            print(f"🔍 Calling token.owner()...")
            owner = self.web3.call_contract_function('Token', checksum_address, 'owner')
            print(f"✅ Token owner: {owner}")
            
            token_info = {
                'name': name,
                'symbol': symbol,
                'decimals': decimals,
                'totalSupply': totalSupply,
                'owner': owner
            }
            
            # Format total supply
            token_info['totalSupplyFormatted'] = self.web3.format_units(token_info['totalSupply'], token_info['decimals'])
            
            # Get compliance info
            try:
                print(f"🔍 Calling token.compliance()...")
                compliance_address = self.web3.call_contract_function('Token', checksum_address, 'compliance')
                token_info['compliance_address'] = compliance_address
                print(f"✅ Compliance address: {compliance_address}")
                
                # Get claim topics from compliance
                print(f"🔍 Calling compliance.getClaimTopics()...")
                claim_topics = self.web3.call_contract_function('Compliance', compliance_address, 'getClaimTopics')
                token_info['claim_topics'] = claim_topics
                print(f"✅ Claim topics: {claim_topics}")
            except Exception as e:
                print(f"⚠️ Warning getting compliance info: {e}")
                token_info['compliance_address'] = None
                token_info['claim_topics'] = []
            
            # Get identity registry info
            try:
                print(f"🔍 Calling token.identityRegistry()...")
                identity_registry = self.web3.call_contract_function('Token', checksum_address, 'identityRegistry')
                token_info['identity_registry'] = identity_registry
                print(f"✅ Identity registry: {identity_registry}")
            except Exception as e:
                print(f"⚠️ Warning getting identity registry: {e}")
                token_info['identity_registry'] = None
            
            return {'success': True, 'token_info': token_info}
            
        except Exception as e:
            print(f"❌ Error in get_token_info: {e}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}
    
    def get_token_required_claims(self, token_address):
        """Get the required claim topics for a specific token"""
        try:
            token_info = self.get_token_info(token_address)
            if not token_info['success']:
                return {'success': False, 'error': 'Could not get token info'}
            
            claim_topics = token_info['token_info'].get('claim_topics', [])
            
            # Import centralized claim topics configuration
            from config.claim_topics import CLAIM_TOPICS
            claim_topic_names = CLAIM_TOPICS
            
            required_claims = []
            for topic in claim_topics:
                required_claims.append({
                    'topic': topic,
                    'name': claim_topic_names.get(topic, f'Claim Topic {topic}'),
                    'description': f'Required claim topic {topic}'
                })
            
            return {
                'success': True, 
                'required_claims': required_claims,
                'claim_topics': claim_topics
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def verify_token_on_chain(self, token_address):
        """Verify token exists and is valid on blockchain"""
        try:
            # Check if token contract exists
            code = self.w3.eth.get_code(token_address)
            if code == b'':
                return {'valid': False, 'error': 'Token contract does not exist'}
            
            # Try to get basic token info
            token_info = self.get_token_info(token_address)
            if not token_info['success']:
                return {'valid': False, 'error': token_info['error']}
            
            return {
                'valid': True,
                'token_info': token_info['token_info'],
                'contract_exists': True
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def get_contract_deployment_info(self, contract_address):
        """Get comprehensive contract deployment information"""
        try:
            # Check if contract exists
            code = self.w3.eth.get_code(contract_address)
            if code == b'':
                return {'exists': False, 'error': 'Contract does not exist'}
            
            # Get contract balance
            balance = self.w3.eth.get_balance(contract_address)
            
            # Get current block for reference
            current_block = self.w3.eth.block_number
            
            return {
                'exists': True,
                'address': contract_address,
                'code_size': len(code),
                'balance': balance,
                'balance_eth': self.w3.from_wei(balance, 'ether'),
                'current_block': current_block,
                'verified': True
            }
            
        except Exception as e:
            return {'exists': False, 'error': str(e)}
    
    def get_system_status(self):
        """Get comprehensive system status"""
        try:
            return {
                'connected': self.w3.is_connected(),
                'current_block': self.w3.eth.block_number,
                'network_id': self.w3.eth.chain_id,
                'gas_price': self.w3.eth.gas_price,
                'gas_price_gwei': self.w3.from_wei(self.w3.eth.gas_price, 'gwei'),
                'latest_block': self.w3.eth.get_block('latest'),
                'peer_count': self.w3.net.peer_count if hasattr(self.w3.net, 'peer_count') else 0
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_recent_transactions(self, limit=50):
        """Get recent transactions from Hardhat network"""
        try:
            transactions = []
            current_block = self.w3.eth.block_number
            
            # Get transactions from the last few blocks
            for block_number in range(current_block, max(0, current_block - 10), -1):
                if len(transactions) >= limit:
                    break
                    
                try:
                    block = self.w3.eth.get_block(block_number, full_transactions=True)
                    
                    for tx in block.transactions:
                        if len(transactions) >= limit:
                            break
                            
                        # Get transaction receipt for additional info
                        try:
                            receipt = self.w3.eth.get_transaction_receipt(tx.hash)
                            
                            # Determine transaction type and description
                            tx_type = "Unknown"
                            tx_description = "Unknown transaction"
                            
                            # Check if it's a contract creation
                            if tx.to is None:
                                tx_type = "Contract Creation"
                                tx_description = f"Contract deployed at {receipt.contractAddress}"
                            # Check if it's a token transfer (common method signatures)
                            elif tx.input and len(tx.input) >= 10:
                                method_id = tx.input[:10]
                                if method_id == "0xa9059cbb":  # transfer(address,uint256)
                                    tx_type = "Token Transfer"
                                    tx_description = "ERC-20 token transfer"
                                elif method_id == "0x23b872dd":  # transferFrom(address,address,uint256)
                                    tx_type = "Token Transfer From"
                                    tx_description = "ERC-20 transferFrom"
                                elif method_id == "0x40c10f19":  # mint(address,uint256)
                                    tx_type = "Token Mint"
                                    tx_description = "Token minting"
                                elif method_id == "0x42966c68":  # burn(uint256)
                                    tx_type = "Token Burn"
                                    tx_description = "Token burning"
                                elif method_id == "0x8456cb59":  # pause()
                                    tx_type = "Contract Pause"
                                    tx_description = "Contract paused"
                                elif method_id == "0x3f4ba83a":  # unpause()
                                    tx_type = "Contract Unpause"
                                    tx_description = "Contract unpaused"
                                else:
                                    tx_type = "Contract Interaction"
                                    tx_description = f"Contract call: {method_id}"
                            else:
                                tx_type = "ETH Transfer"
                                tx_description = "Ether transfer"
                            
                            # Format transaction data
                            tx_data = {
                                'hash': tx.hash.hex(),
                                'block_number': block_number,
                                'from': tx['from'],
                                'to': tx['to'] if tx['to'] else receipt.contractAddress,
                                'value': tx['value'],
                                'value_eth': self.w3.from_wei(tx['value'], 'ether'),
                                'gas_used': receipt.gasUsed,
                                'gas_price': tx['gasPrice'],
                                'gas_price_gwei': self.w3.from_wei(tx['gasPrice'], 'gwei'),
                                'status': 'Success' if receipt.status == 1 else 'Failed',
                                'timestamp': block.timestamp,
                                'type': tx_type,
                                'description': tx_description,
                                'input_length': len(tx.input),
                                'contract_address': receipt.contractAddress if receipt.contractAddress else None
                            }
                            
                            transactions.append(tx_data)
                            
                        except Exception as e:
                            # If we can't get receipt, still include basic tx info
                            tx_data = {
                                'hash': tx.hash.hex(),
                                'block_number': block_number,
                                'from': tx['from'],
                                'to': tx['to'],
                                'value': tx['value'],
                                'value_eth': self.w3.from_wei(tx['value'], 'ether'),
                                'gas_used': None,
                                'gas_price': tx['gasPrice'],
                                'gas_price_gwei': self.w3.from_wei(tx['gasPrice'], 'gwei'),
                                'status': 'Unknown',
                                'timestamp': block.timestamp,
                                'type': 'Unknown',
                                'description': 'Transaction details unavailable',
                                'input_length': len(tx.input),
                                'contract_address': None
                            }
                            transactions.append(tx_data)
                            
                except Exception as e:
                    # Skip blocks that can't be read
                    continue
            
            return {
                'success': True,
                'transactions': transactions,
                'total_count': len(transactions),
                'current_block': current_block
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'transactions': [],
                'total_count': 0
            }
    
    def get_investor_balance(self, token_address, investor_address):
        """Get investor's token balance"""
        try:
            balance = self.web3.get_token_balance(token_address, investor_address)
            return {'success': True, 'balance': balance}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def register_identity(self, wallet_address, country_code=840):
        """Register a new identity for an investor"""
        try:
            if not self.identity_registry_address:
                return {'success': False, 'error': 'Identity registry not deployed'}
            
            # Check if already registered
            has_identity = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'contains',
                wallet_address
            )
            
            if has_identity:
                return {'success': False, 'error': 'Identity already registered'}
            
            # Register identity
            tx_hash = self.web3.transact_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'registerIdentity',
                wallet_address,
                country_code
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_identity_info(self, wallet_address):
        """Get identity information for a wallet"""
        try:
            if not self.identity_registry_address:
                return {'success': False, 'error': 'Identity registry not deployed'}
            
            # Check if has identity
            has_identity = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'contains',
                wallet_address
            )
            
            if not has_identity:
                return {'success': False, 'error': 'No identity registered'}
            
            # Get identity details
            identity_address = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'identity',
                wallet_address
            )
            
            country_code = self.web3.call_contract_function(
                'IdentityRegistry',
                self.identity_registry_address,
                'investorCountry',
                wallet_address
            )
            
            return {
                'success': True,
                'identity_address': identity_address,
                'country_code': country_code,
                'has_identity': has_identity
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_deployment_details(self):
        """Get deployment details from database"""
        try:
            # Import here to avoid circular imports
            from app import get_contract_address
            
            return {
                'identityFactory': get_contract_address('IdentityFactory'),
                'trexFactory': get_contract_address('TREXFactory'),
                'identityRegistry': get_contract_address('IdentityRegistry'),
                'claimTopicsRegistry': get_contract_address('ClaimTopicsRegistry'),
                'trustedIssuersRegistry': get_contract_address('TrustedIssuersRegistry')
            }
        except Exception as e:
            print(f"Error getting deployment details: {e}")
            return None

    def get_identity(self, wallet_address, identity_factory_address):
        """Get existing OnchainID address for a wallet"""
        try:
            # Get identity factory contract - use Factory (not IIdFactory interface)
            identity_factory = self.web3.get_contract(identity_factory_address, 'Factory')
            
            # Check if identity exists
            identity_address = identity_factory.functions.getIdentity(wallet_address).call()
            return identity_address
            
        except Exception as e:
            print(f"Error getting identity: {e}")
            return '0x0000000000000000000000000000000000000000'

    def create_identity(self, wallet_address, identity_factory_address):
        """Create OnchainID using T-REX Factory pattern"""
        try:
            from web3 import Web3
            import time
            
            # Get identity factory contract - use Factory (not IIdFactory interface)
            identity_factory = self.web3.get_contract(identity_factory_address, 'Factory')
            
            # Use the deployer account (first Hardhat account) to call createIdentity
            # The IdFactory is owned by the deployer, so only the deployer can call createIdentity
            deployer_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
            deployer_account = Account.from_key(deployer_private_key)
            deployer_address = deployer_account.address
            
            # Check if identity already exists
            existing_identity = identity_factory.functions.getIdentity(wallet_address).call()
            if existing_identity != '0x0000000000000000000000000000000000000000':
                return {
                    'success': True,
                    'onchain_id_address': existing_identity,
                    'transaction_hash': None,
                    'is_new': False
                }
            
            # Create salt for deterministic deployment
            salt_bytes = self.w3.keccak(
                self.w3.codec.encode(
                    ['address', 'uint256'],
                    [wallet_address, int(time.time())]
                )
            )
            # Convert to string for the contract
            salt = salt_bytes.hex()
            
            # Create identity based on whether user is deployer or not
            if wallet_address.lower() == deployer_address.lower():
                # User is deployer - create simple identity
                tx = identity_factory.functions.createIdentity(wallet_address, salt).build_transaction({
                    'from': deployer_address,
                    'gasPrice': self.w3.eth.gas_price,
                    'nonce': self.w3.eth.get_transaction_count(deployer_address)
                })
                
                # Estimate gas for createIdentity
                try:
                    estimated_gas = identity_factory.functions.createIdentity(wallet_address, salt).estimate_gas({
                        'from': deployer_address
                    })
                    tx['gas'] = int(estimated_gas * 1.2)  # Add 20% buffer
                    print(f"📊 Estimated gas for createIdentity: {estimated_gas}, Using: {tx['gas']}")
                except Exception as e:
                    print(f"⚠️ Could not estimate gas for createIdentity, using default: {e}")
                    tx['gas'] = 3000000  # Fallback to 3M gas
            else:
                # User is not deployer - create with management keys
                deployer_key_hash = self._hash_address_abi_encoded(deployer_address)
                management_keys = [deployer_key_hash]
                
                tx = identity_factory.functions.createIdentityWithManagementKeys(
                    wallet_address, salt, management_keys
                ).build_transaction({
                    'from': deployer_address,
                    'gasPrice': self.w3.eth.gas_price,
                    'nonce': self.w3.eth.get_transaction_count(deployer_address)
                })
                
                # Estimate gas for createIdentityWithManagementKeys
                try:
                    estimated_gas = identity_factory.functions.createIdentityWithManagementKeys(
                        wallet_address, salt, management_keys
                    ).estimate_gas({
                        'from': deployer_address
                    })
                    tx['gas'] = int(estimated_gas * 1.2)  # Add 20% buffer
                    print(f"📊 Estimated gas for createIdentityWithManagementKeys: {estimated_gas}, Using: {tx['gas']}")
                except Exception as e:
                    print(f"⚠️ Could not estimate gas for createIdentityWithManagementKeys, using default: {e}")
                    tx['gas'] = 4000000  # Fallback to 4M gas
            
            # Sign and send transaction using deployer's private key
            signed_tx = self.w3.eth.account.sign_transaction(tx, deployer_private_key)
            # Handle both old and new eth-account versions
            raw_tx = getattr(signed_tx, 'rawTransaction', None) or getattr(signed_tx, 'raw_transaction', None)
            if not raw_tx:
                raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
            # Wait for transaction
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                # Get the created identity address
                onchain_id_address = identity_factory.functions.getIdentity(wallet_address).call()
                
                # Index the initial management key (the deployer's key hash)
                try:
                    from services.onchainid_key_manager import OnchainIDKeyManager
                    # Pass the Web3Service object, not the raw Web3 object
                    key_manager = OnchainIDKeyManager(self.web3)
                    
                    # The initial management key is the deployer's key hash (as set in createIdentityWithManagementKeys)
                    # This is what gets stored on the blockchain
                    deployer_key_hash = self._hash_address_abi_encoded(deployer_address).hex()
                    
                    print(f"🔍 Indexing initial management key (deployer) for OnchainID {onchain_id_address}")
                    print(f"🔍 Deployer address: {deployer_address}")
                    print(f"🔍 Deployer key hash: {deployer_key_hash}")
                    print(f"🔍 User getting OnchainID: {wallet_address}")
                    
                    # The management key owner is the deployer (Account 0), not the user who got the OnchainID
                    # For the initial management key, the owner is always the deployer
                    owner_type = 'Account 0'  # This represents the deployer who owns the management key
                    owner_id = None  # No specific user ID for the deployer
                    
                    indexed_key_id = key_manager.index_management_key(
                        onchainid_address=onchain_id_address,
                        wallet_address=deployer_address,  # The deployer's wallet (initial management key)
                        owner_type=owner_type,
                        owner_id=owner_id,
                        transaction_hash=tx_hash.hex(),
                        key_hash=deployer_key_hash  # The deployer's key hash
                    )
                    
                    if indexed_key_id:
                        print(f"✅ Successfully indexed initial management key (Account 0) for OnchainID {wallet_address}")
                        print(f"✅ Deployer key hash: {deployer_key_hash}")
                        print(f"✅ Database ID: {indexed_key_id}")
                        print(f"✅ Management key owner: {owner_type} ({deployer_address})")
                    else:
                        print(f"❌ Failed to index initial management key (Account 0)")
                        
                except Exception as e:
                    print(f"⚠️ Error indexing initial management key: {e}")
                    import traceback
                    traceback.print_exc()
                
                return {
                    'success': True,
                    'onchain_id_address': onchain_id_address,
                    'transaction_hash': tx_hash.hex(),
                    'is_new': True
                }
            else:
                return {
                    'success': False,
                    'error': 'Transaction failed'
                }
                
        except Exception as e:
            print(f"Error creating identity: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def deploy_claimissuer_contract(self, wallet_address):
        """Deploy ClaimIssuer contract for a trusted issuer"""
        try:
            print(f"🎯 Deploying ClaimIssuer contract for: {wallet_address}")
            
            # Get ClaimIssuer contract ABI and bytecode
            if 'ClaimIssuer' not in self.web3.contract_abis:
                raise Exception("ClaimIssuer ABI not found")
            
            # Load bytecode from the artifact file
            import json
            from pathlib import Path
            
            artifacts_dir = Path(__file__).parent.parent / 'artifacts' / '@onchain-id' / 'solidity' / 'contracts'
            claimissuer_artifact_path = artifacts_dir / 'ClaimIssuer.sol' / 'ClaimIssuer.json'
            
            if not claimissuer_artifact_path.exists():
                raise Exception(f"ClaimIssuer artifact not found: {claimissuer_artifact_path}")
            
            with open(claimissuer_artifact_path, 'r') as f:
                artifact_data = json.load(f)
                bytecode = artifact_data['bytecode']
            
            # Deploy ClaimIssuer contract with the trusted issuer as management key
            deployer_address = self.web3.default_account
            
            # Use the trusted issuer as the initial management key (like Hardhat test does)
            print(f"🔧 Deploying ClaimIssuer with trusted issuer ({wallet_address}) as management key")
            
            # Create contract instance for deployment
            claimissuer_contract = self.w3.eth.contract(
                abi=self.web3.contract_abis['ClaimIssuer'],
                bytecode=bytecode
            )
            
            # Build deployment transaction with trusted issuer as initial management key
            tx = claimissuer_contract.constructor(wallet_address).build_transaction({
                'from': deployer_address,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(deployer_address)
            })
            
            # Estimate gas and add buffer
            try:
                estimated_gas = claimissuer_contract.constructor(wallet_address).estimate_gas({
                    'from': deployer_address
                })
                tx['gas'] = int(estimated_gas * 1.5)  # Add 50% buffer for safety
                print(f"📊 Estimated gas: {estimated_gas}, Using: {tx['gas']}")
            except Exception as e:
                print(f"⚠️ Could not estimate gas, using default: {e}")
                tx['gas'] = 8000000  # Fallback to 8M gas
            
            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.web3.private_key)
            # Handle both old and new eth-account versions
            raw_tx = getattr(signed_tx, 'rawTransaction', None) or getattr(signed_tx, 'raw_transaction', None)
            if not raw_tx:
                raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
            # Wait for transaction
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                claimissuer_address = receipt.contractAddress
                
                print(f"✅ ClaimIssuer contract deployed at: {claimissuer_address}")
                
                # Verify the ClaimIssuer was deployed successfully
                print(f"🔍 ClaimIssuer deployed with trusted issuer ({wallet_address}) as management key")
                print(f"✅ ClaimIssuer contract is ready to use")
                
                # Note: TrustedIssuersRegistry registration is handled during TokenSuite deployment
                print(f"✅ ClaimIssuer deployed successfully with trusted issuer as management key")
                print(f"ℹ️  TrustedIssuersRegistry registration will be handled during TokenSuite deployment")
                
                return {
                    'success': True,
                    'claimissuer_address': claimissuer_address,
                    'transaction_hash': tx_hash.hex(),
                    'deployer_address': deployer_address
                }
            else:
                return {
                    'success': False,
                    'error': 'Transaction failed'
                }
                
        except Exception as e:
            print(f"Error deploying ClaimIssuer contract: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_token_transactions(self, token_address, from_address=None, to_address=None, limit=50):
        """
        Get token transactions from blockchain using Transfer events
        
        Args:
            token_address (str): Token contract address
            from_address (str, optional): Filter by sender address
            to_address (str, optional): Filter by recipient address
            limit (int): Maximum number of transactions to return
            
        Returns:
            list: List of transaction dictionaries
        """
        try:
            # Convert token address to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            print(f"🔍 Getting token transactions for: {token_address}")
            print(f"   Original address: {token_address}")
            print(f"   Checksum address: {checksum_token_address}")
            
            # Get token contract
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                print(f"❌ Token contract ABI not found for: {token_address}")
                return []
            
            # Get Transfer events
            transfer_filter = token_contract.events.Transfer.create_filter(
                fromBlock=0,
                toBlock='latest'
            )
            
            events = transfer_filter.get_all_entries()
            print(f"📊 Found {len(events)} Transfer events")
            
            transactions = []
            for event in events[-limit:]:  # Get most recent events
                try:
                    # Get transaction details
                    tx_hash = event['transactionHash'].hex()
                    tx_receipt = self.w3.eth.get_transaction_receipt(tx_hash)
                    tx = self.w3.eth.get_transaction(tx_hash)
                    
                    # Get block timestamp
                    block = self.w3.eth.get_block(event['blockNumber'])
                    
                    # Determine transaction type
                    tx_type = 'transfer'
                    if event['args']['from'] == '0x0000000000000000000000000000000000000000':
                        tx_type = 'mint'
                    elif event['args']['to'] == '0x0000000000000000000000000000000000000000':
                        tx_type = 'burn'
                    
                    # Debug logging for transaction classification
                    print(f"🔍 Transaction {tx_hash[:10]}... classification:")
                    print(f"   From: {event['args']['from']}")
                    print(f"   To: {event['args']['to']}")
                    print(f"   Type: {tx_type}")
                    print(f"   Amount: {event['args']['value']}")
                    print(f"   Executed by: {tx['from']}")
                    
                    # Format amount
                    decimals = 18  # Default to 18
                    try:
                        decimals = token_contract.functions.decimals().call()
                    except:
                        pass
                    
                    amount_formatted = float(event['args']['value']) / (10 ** decimals)
                    
                    transaction = {
                        'transaction_hash': tx_hash,
                        'transaction_type': tx_type,
                        'from_address': event['args']['from'],
                        'to_address': event['args']['to'],
                        'amount': event['args']['value'],
                        'amount_formatted': amount_formatted,
                        'executed_by_address': tx['from'],
                        'block_number': event['blockNumber'],
                        'timestamp': block.timestamp,
                        'created_at': block.timestamp,  # For compatibility with template
                        'notes': f"Block {event['blockNumber']}"
                    }
                    
                    # Apply filters if specified
                    if from_address and event['args']['from'].lower() != from_address.lower():
                        continue
                    if to_address and event['args']['to'].lower() != to_address.lower():
                        continue
                    
                    transactions.append(transaction)
                    print(f"✅ Added transaction: {tx_type} - {tx_hash[:10]}...")
                    
                except Exception as e:
                    print(f"⚠️ Error processing transaction {event['transactionHash'].hex()}: {e}")
                    continue
            
            # Sort by timestamp (newest first)
            transactions.sort(key=lambda x: x['timestamp'], reverse=True)
            
            print(f"✅ Returned {len(transactions)} token transactions")
            
            # Debug: Print first few transactions to see structure
            for i, tx in enumerate(transactions[:3]):
                print(f"🔍 Transaction {i+1}:")
                print(f"   Hash: {tx['transaction_hash'][:10]}...")
                print(f"   Type: {tx['transaction_type']}")
                print(f"   From: {tx['from_address']}")
                print(f"   To: {tx['to_address']}")
                print(f"   Amount: {tx['amount_formatted']}")
                print(f"   Executed by: {tx['executed_by_address']}")
            
            return transactions
            
        except Exception as e:
            print(f"❌ Error getting token transactions: {e}")
            return []

    def add_trusted_issuer_to_token(self, token_address, trusted_issuer_address, claim_topics):
        """
        Add a trusted issuer to a token's Identity Registry (TIR)
        
        This is equivalent to calling: tirAdmin.addTrustedIssuer(issuer2, [7])
        
        Args:
            token_address (str): Token contract address
            trusted_issuer_address (str): Trusted issuer wallet address
            claim_topics (list): List of claim topic IDs this issuer can verify
            
        Returns:
            dict: Success status and transaction details
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_trusted_issuer_address = self.web3.to_checksum_address(trusted_issuer_address)
            
            print(f"🔗 Adding trusted issuer {trusted_issuer_address} to token {token_address}")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   Trusted issuer address: {trusted_issuer_address} -> {checksum_trusted_issuer_address}")
            print(f"   Claim topics: {claim_topics}")
            
            # Get the token's Identity Registry contract
            # First, we need to get the Identity Registry address from the token
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Get the Identity Registry address from the token
            try:
                identity_registry_address = token_contract.functions.identityRegistry().call()
                print(f"🔍 Found Identity Registry at: {identity_registry_address}")
            except Exception as e:
                print(f"❌ Error getting Identity Registry address: {e}")
                return {'success': False, 'error': f'Could not get Identity Registry address: {str(e)}'}
            
            # Get the Identity Registry contract
            identity_registry_contract = self.w3.eth.contract(
                address=identity_registry_address,
                abi=self.web3.contract_abis.get('IdentityRegistry', [])
            )
            
            if not identity_registry_contract:
                return {'success': False, 'error': 'Identity Registry ABI not found'}
            
            # Get the Trusted Issuers Registry address from the Identity Registry
            try:
                trusted_issuers_registry_address = identity_registry_contract.functions.issuersRegistry().call()
                print(f"🔍 Found Trusted Issuers Registry at: {trusted_issuers_registry_address}")
            except Exception as e:
                print(f"❌ Error getting Trusted Issuers Registry address: {e}")
                return {'success': False, 'error': f'Could not get Trusted Issuers Registry address: {str(e)}'}
            
            # Get the Trusted Issuers Registry contract
            trusted_issuers_registry_contract = self.w3.eth.contract(
                address=trusted_issuers_registry_address,
                abi=self.web3.contract_abis.get('TrustedIssuersRegistry', [])
            )
            
            if not trusted_issuers_registry_contract:
                return {'success': False, 'error': 'Trusted Issuers Registry ABI not found'}
            
            # Convert claim topics to integers and ensure they're in the right format
            claim_topics_int = [int(topic) for topic in claim_topics]
            
            # Check if trusted issuer already exists before adding
            try:
                # Check if the trusted issuer is already registered
                existing_topics = trusted_issuers_registry_contract.functions.getTrustedIssuerClaimTopics(trusted_issuer_address).call()
                if existing_topics and len(existing_topics) > 0:
                    return {
                        'success': False, 
                        'error': f'Trusted issuer {trusted_issuer_address} already exists with topics {existing_topics}'
                    }
            except Exception as e:
                print(f"🔍 Error checking existing trusted issuer: {e}")
                # Continue anyway
            
            # Call addTrustedIssuer on the Trusted Issuers Registry
            # This is the equivalent of: tirAdmin.addTrustedIssuer(issuer2, [7])
            
            # Use the current account from Web3Service (which should be the correct key after switching)
            current_account = self.web3.default_account
            
            # Build the transaction
            transaction = trusted_issuers_registry_contract.functions.addTrustedIssuer(
                checksum_trusted_issuer_address,
                claim_topics_int
            ).build_transaction({
                'from': current_account,
                'nonce': self.w3.eth.get_transaction_count(current_account),
                'gas': 500000,  # Increased gas limit
                'gasPrice': self.w3.eth.gas_price
            })
            
            # Sign and send the transaction using the current private key
            # This will be either Account 0's key or the issuer's key depending on ownership
            print(f"🔧 Building transaction with gas: 500000, from: {current_account}")
            print(f"🔧 Transaction data: {transaction}")
            
            # DEBUG: Check the exact function call
            print(f"🔍 DEBUG: Function call details:")
            print(f"   Function: addTrustedIssuer")
            print(f"   Parameters: {trusted_issuer_address}, {claim_topics_int}")
            print(f"   Contract: {trusted_issuers_registry_address}")
            print(f"   Caller: {current_account}")
            
            # DEBUG: Try to estimate gas first
            try:
                estimated_gas = trusted_issuers_registry_contract.functions.addTrustedIssuer(
                    trusted_issuer_address,
                    claim_topics_int
                ).estimate_gas({'from': current_account})
                print(f"🔍 DEBUG: Estimated gas: {estimated_gas}")
            except Exception as gas_error:
                print(f"🔍 DEBUG: Gas estimation failed: {gas_error}")
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.web3.private_key)
            # Handle both old and new eth-account versions
            raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
            if not raw_tx:
                raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
            # Wait for transaction confirmation
            print(f"📤 Transaction sent with hash: {tx_hash.hex()}")
            
            # Wait for transaction confirmation
            print(f"⏳ Waiting for transaction confirmation...")
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            print(f"📋 Transaction receipt: status={tx_receipt.status}, gasUsed={tx_receipt.gasUsed}")
            
            if tx_receipt.status == 1:
                print(f"✅ Successfully added trusted issuer to Identity Registry")
                print(f"   Transaction hash: {tx_hash.hex()}")
                print(f"   Block number: {tx_receipt.blockNumber}")
                
                return {
                    'success': True,
                    'transaction_hash': tx_hash.hex(),
                    'block_number': tx_receipt.blockNumber,
                    'message': f'Trusted issuer {trusted_issuer_address} added successfully with topics {claim_topics_int}'
                }
            else:
                print(f"❌ Transaction failed with status: {tx_receipt.status}")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"❌ Error adding trusted issuer to token: {str(e)}")
            return {'success': False, 'error': f'Failed to add trusted issuer: {str(e)}'}

    def remove_trusted_issuer_from_token(self, token_address, trusted_issuer_address):
        """
        Remove a trusted issuer from a token's Identity Registry (TIR)
        
        Args:
            token_address (str): Token contract address
            trusted_issuer_address (str): Trusted issuer wallet address to remove
            
        Returns:
            dict: Success status and transaction details
        """
        try:
            print(f"🔗 Removing trusted issuer {trusted_issuer_address} from token {token_address}")
            
            # Get the token's Identity Registry contract
            token_contract = self.w3.eth.contract(
                address=token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Get the Identity Registry address from the token
            try:
                identity_registry_address = token_contract.functions.identityRegistry().call()
                print(f"🔍 Found Identity Registry at: {identity_registry_address}")
            except Exception as e:
                print(f"❌ Error getting Identity Registry address: {e}")
                return {'success': False, 'error': f'Could not get Identity Registry address: {str(e)}'}
            
            # Get the Identity Registry contract
            identity_registry_contract = self.w3.eth.contract(
                address=identity_registry_address,
                abi=self.web3.contract_abis.get('IdentityRegistry', [])
            )
            
            if not identity_registry_contract:
                return {'success': False, 'error': 'Identity Registry ABI not found'}
            
            # Get the Trusted Issuers Registry address from the Identity Registry
            try:
                trusted_issuers_registry_address = identity_registry_contract.functions.issuersRegistry().call()
                print(f"🔍 Found Trusted Issuers Registry at: {trusted_issuers_registry_address}")
            except Exception as e:
                print(f"❌ Error getting Trusted Issuers Registry address: {e}")
                return {'success': False, 'error': f'Could not get Trusted Issuers Registry address: {str(e)}'}
            
            # Get the Trusted Issuers Registry contract
            trusted_issuers_registry_contract = self.w3.eth.contract(
                address=trusted_issuers_registry_address,
                abi=self.web3.contract_abis.get('TrustedIssuersRegistry', [])
            )
            
            if not trusted_issuers_registry_contract:
                return {'success': False, 'error': 'Trusted Issuers Registry ABI not found'}
            
            # Call removeTrustedIssuer on the Trusted Issuers Registry
            print(f"🚀 Calling removeTrustedIssuer({trusted_issuer_address})")
            
            # IMPORTANT: The caller must be the OWNER of the TrustedIssuersRegistry
            # This is typically the platform (Account 0), not the issuer
            # We need to use the platform's account for this call
            
            # Use the current account from Web3Service (which should be the correct key after switching)
            current_account = self.web3.default_account
            print(f"🔑 Using current account: {current_account}")
            
            # Build the transaction
            transaction = trusted_issuers_registry_contract.functions.removeTrustedIssuer(
                trusted_issuer_address
            ).build_transaction({
                'from': current_account,
                'nonce': self.w3.eth.get_transaction_count(current_account),
                'gas': 100000,  # Adjust gas as needed
                'gasPrice': self.w3.eth.gas_price
            })
            
            # Sign and send the transaction using the current private key
            # This will be either Account 0's key or the issuer's key depending on ownership
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.web3.private_key)
            # Handle both old and new eth-account versions
            raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
            if not raw_tx:
                raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if tx_receipt.status == 1:
                print(f"✅ Successfully removed trusted issuer from Identity Registry")
                print(f"   Transaction hash: {tx_hash.hex()}")
                print(f"   Block number: {tx_receipt.blockNumber}")
                
                return {
                    'success': True,
                    'transaction_hash': tx_hash.hex(),
                    'block_number': tx_receipt.blockNumber,
                    'message': f'Trusted issuer {trusted_issuer_address} removed successfully'
                }
            else:
                print(f"❌ Transaction failed")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"❌ Error removing trusted issuer from token: {str(e)}")
            return {'success': False, 'error': f'Failed to remove trusted issuer: {str(e)}'}

    def add_agent_to_token(self, token_address, agent_address, agent_type):
        """
        Add an agent to a token's smart contracts
        
        Args:
            token_address (str): Token contract address
            agent_address (str): Agent wallet address to add
            agent_type (str): Type of agent ('ir_agent' or 'token_agent')
            
        Returns:
            dict: Success status and transaction details
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_agent_address = self.web3.to_checksum_address(agent_address)
            
            print(f"🔗 Adding agent {agent_address} as {agent_type} to token {token_address}")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   Agent address: {agent_address} -> {checksum_agent_address}")
            
            # Get the token contract
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Get the Identity Registry address from the token
            try:
                identity_registry_address = token_contract.functions.identityRegistry().call()
                print(f"🔍 Found Identity Registry at: {identity_registry_address}")
            except Exception as e:
                print(f"❌ Error getting Identity Registry address: {e}")
                return {'success': False, 'error': f'Could not get Identity Registry address: {str(e)}'}
            
            # Add agent to the appropriate contract based on type
            if agent_type == 'ir_agent':
                # Add agent to Identity Registry
                print(f"🚀 Adding agent to Identity Registry...")
                contract = self.w3.eth.contract(
                    address=identity_registry_address,
                    abi=self.web3.contract_abis.get('IdentityRegistry', [])
                )
                
            elif agent_type == 'token_agent':
                # Add agent to Token contract
                print(f"🚀 Adding agent to Token contract...")
                contract = token_contract
                
            else:
                return {'success': False, 'error': f'Invalid agent type: {agent_type}'}
            
            # Build the transaction
            # IMPORTANT: The caller must have the appropriate permissions on the contract
            # For agents, this is typically the platform (Account 0) or an existing agent
            # In our current architecture, Account 0 represents the platform
            platform_address = self.web3.default_account
            print(f"🔑 Using platform account (Account 0): {platform_address}")
            
            transaction = contract.functions.addAgent(agent_address).build_transaction({
                'from': platform_address,
                'nonce': self.w3.eth.get_transaction_count(platform_address),
                'gas': 150000,  # Adjust gas as needed
                'gasPrice': self.w3.eth.gas_price
            })
            
            # Sign and send the transaction using the platform's private key
            # This represents the platform acting on behalf of the issuer
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.web3.private_key)
            # Handle both old and new eth-account versions
            raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
            if not raw_tx:
                raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if tx_receipt.status == 1:
                print(f"✅ Successfully added agent to {agent_type}")
                print(f"   Transaction hash: {tx_hash.hex()}")
                print(f"   Block number: {tx_receipt.blockNumber}")
                
                return {
                    'success': True,
                    'transaction_hash': tx_hash.hex(),
                    'block_number': tx_receipt.blockNumber,
                    'message': f'Agent {agent_address} added successfully as {agent_type}'
                }
            else:
                print(f"❌ Transaction failed")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"❌ Error adding agent to token: {str(e)}")
            return {'success': False, 'error': f'Failed to add agent: {str(e)}'}

    def remove_agent_from_token(self, token_address, agent_address, agent_type):
        """
        Remove an agent from a token's smart contracts
        
        Args:
            token_address (str): Token contract address
            agent_address (str): Agent wallet address to remove
            agent_type (str): Type of agent ('ir_agent' or 'token_agent')
            
        Returns:
            dict: Success status and transaction details
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_agent_address = self.web3.to_checksum_address(agent_address)
            
            print(f"🔗 Removing agent {agent_address} as {agent_type} from token {token_address}")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   Agent address: {agent_address} -> {checksum_agent_address}")
            
            # Get the token contract
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Get the Identity Registry address from the token
            try:
                identity_registry_address = token_contract.functions.identityRegistry().call()
                print(f"🔍 Found Identity Registry at: {identity_registry_address}")
            except Exception as e:
                print(f"❌ Error getting Identity Registry address: {e}")
                return {'success': False, 'error': f'Could not get Identity Registry address: {str(e)}'}
            
            # Remove agent from the appropriate contract based on type
            if agent_type == 'ir_agent':
                # Remove agent from Identity Registry
                print(f"🚀 Removing agent from Identity Registry...")
                contract = self.w3.eth.contract(
                    address=identity_registry_address,
                    abi=self.web3.contract_abis.get('IdentityRegistry', [])
                )
                
            elif agent_type == 'token_agent':
                # Remove agent from Token contract
                print(f"🚀 Removing agent from Token contract...")
                contract = token_contract
                
            else:
                return {'success': False, 'error': f'Invalid agent type: {agent_type}'}
            
            # Build the transaction
            # IMPORTANT: The caller must have the appropriate permissions on the contract
            # For agents, this is typically the platform (Account 0) or an existing agent
            # In our current architecture, Account 0 represents the platform
            platform_address = self.web3.default_account
            print(f"🔑 Using platform account (Account 0): {platform_address}")
            
            transaction = contract.functions.removeAgent(agent_address).build_transaction({
                'from': platform_address,
                'nonce': self.w3.eth.get_transaction_count(platform_address),
                'gas': 150000,  # Adjust gas as needed
                'gasPrice': self.w3.eth.gas_price
            })
            
            # Sign and send the transaction using the platform's private key
            # This represents the platform acting on behalf of the issuer
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.web3.private_key)
            # Handle both old and new eth-account versions
            raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
            if not raw_tx:
                raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
            # Wait for transaction confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if tx_receipt.status == 1:
                print(f"✅ Successfully removed agent from {agent_type}")
                print(f"   Transaction hash: {tx_hash.hex()}")
                print(f"   Block number: {tx_receipt.blockNumber}")
                
                return {
                    'success': True,
                    'transaction_hash': tx_hash.hex(),
                    'block_number': tx_receipt.blockNumber,
                    'message': f'Agent {agent_address} removed successfully from {agent_type}'
                }
            else:
                print(f"❌ Transaction failed")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"❌ Error removing agent from token: {str(e)}")
            return {'success': False, 'error': f'Failed to remove agent: {str(e)}'}

    # ============================================================================
    # META MASK TRANSACTION BUILDING METHODS
    # ============================================================================
    
    def build_mint_transaction(self, token_address, to_address, amount, user_address=None):
        """
        Build mint transaction for MetaMask signing (without executing)
        
        Args:
            token_address (str): Token contract address
            to_address (str): Address to mint tokens to
            amount (str): Amount to mint (will be converted to wei)
            user_address (str): User's wallet address for gas estimation
            
        Returns:
            dict: Transaction data for MetaMask signing
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_to_address = self.web3.to_checksum_address(to_address)
            
            print(f"🔍 Building mint transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   To address: {to_address} -> {checksum_to_address}")
            print(f"   Amount: {amount}")
            
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Get the token contract
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Build the mint transaction (without signing)
            # Note: 'from' field will be overridden by MetaMask with the connected account
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the mint operation
            estimated_gas = token_contract.functions.mint(
                checksum_to_address,
                amount_wei
            ).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for mint: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = token_contract.functions.mint(
                checksum_to_address,
                amount_wei
            ).build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Debug: Print transaction object
            print(f"🔍 Built mint transaction object:")
            print(f"   to: {transaction['to']}")
            print(f"   data: {transaction['data']}")
            print(f"   value: {transaction['value']}")
            print(f"   gas: {transaction['gas']}")
            print(f"   gasPrice: {transaction['gasPrice']}")
            print(f"   chainId: {transaction['chainId']}")
            # Note: 'nonce' is not included - MetaMask will handle it automatically
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - MetaMask will handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building mint transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build mint transaction: {str(e)}'}
    
    def build_burn_transaction(self, token_address, from_address, amount, user_address=None):
        """
        Build burn transaction for MetaMask signing (without executing)
        
        Args:
            token_address (str): Token contract address
            from_address (str): Address to burn tokens from
            amount (str): Amount to burn (will be converted to wei)
            user_address (str): User's wallet address for gas estimation
            
        Returns:
            dict: Transaction data for MetaMask signing
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_from_address = self.web3.to_checksum_address(from_address)
            
            print(f"🔍 Building burn transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   From address: {from_address} -> {checksum_from_address}")
            print(f"   Amount: {amount}")
            
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Get the token contract
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Build the burn transaction (without signing)
            # Note: 'from' field will be set by MetaMask with the connected account
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the burn operation
            estimated_gas = token_contract.functions.burn(
                checksum_from_address,
                amount_wei
            ).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for burn: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = token_contract.functions.burn(
                checksum_from_address,
                amount_wei
            ).build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - MetaMask will handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building burn transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build burn transaction: {str(e)}'}

    def build_transfer_transaction(self, token_address, from_address, to_address, amount, user_address=None):
        """Build transfer transaction for MetaMask signing"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_from_address = self.web3.to_checksum_address(from_address)
            checksum_to_address = self.web3.to_checksum_address(to_address)
            
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Get the token contract
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Build the transfer transaction (without signing)
            # Note: 'from' field will be set by MetaMask with the connected account
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the transfer operation
            estimated_gas = token_contract.functions.transfer(
                checksum_to_address,
                amount_wei
            ).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for transfer: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = token_contract.functions.transfer(
                checksum_to_address,
                amount_wei
            ).build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - MetaMask will handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building transfer transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build transfer transaction: {str(e)}'}

    def _get_country_code_from_nationality(self, nationality):
        """Convert nationality string to ISO country code"""
        if not nationality:
            return 840  # Default to US

        nationality_upper = nationality.upper().strip()

        # Simple mapping for the 7 options in our KYC form
        country_mapping = {
            'US': 840,      # United States
            'EU': 250,      # France (representing EU)
            'UK': 826,      # United Kingdom
            'CA': 124,      # Canada
            'AU': 36,       # Australia
            'ASIA': 156,    # China (representing Asia)
            'OTHER': 840    # Default to US for other
        }

        return country_mapping.get(nationality_upper, 840)  # Default to US if not found

    def configure_compliance_modules_after_deployment(self, token_address, compliance_modules_config, deployer_address):
        """Configure compliance modules after token deployment"""
        try:
            print(f"\n🔧🔧🔧 TREX SERVICE: CONFIGURING COMPLIANCE MODULES 🔧🔧🔧")
            print(f"   Token Address: {token_address}")
            print(f"   Deployer Address: {deployer_address}")
            print(f"   Compliance Modules Config: {compliance_modules_config}")
            
            # Get the token contract to find the ModularCompliance address
            print(f"   🔍 Getting token contract...")
            token_contract = self.web3.get_contract(token_address, "Token")
            compliance_address = token_contract.functions.compliance().call()
            print(f"   🔍 Compliance address from token: {compliance_address}")
            
            if compliance_address == "0x0000000000000000000000000000000000000000":
                print("   ❌ No compliance contract found for this token")
                return {'success': False, 'error': 'No compliance contract found'}
            
            print(f"   ✅ Found ModularCompliance contract: {compliance_address}")
            
            # Get the ModularCompliance contract
            print(f"   🔍 Getting ModularCompliance contract...")
            compliance_contract = self.web3.get_contract(compliance_address, "ModularCompliance")
            
            configuration_transactions = []
            print(f"   🔍 Processing {len(compliance_modules_config)} compliance modules...")
            
            for i, module_config in enumerate(compliance_modules_config):
                print(f"   📋 Module {i+1}:")
                module_type = module_config['type']
                module_address = module_config['address']
                config = module_config['config']
                
                print(f"      Type: {module_type}")
                print(f"      Address: {module_address}")
                print(f"      Config: {config}")
                
                if module_type == 'CountryAllowModule':
                    # Configure country allowances
                    countries = config.get('allowed_countries', [])
                    print(f"      🌍 Allowed countries: {countries}")
                    if countries:
                        # Encode batchAllowCountries(uint16[] countries)
                        module_function_selector = self.w3.keccak(text="batchAllowCountries(uint16[])")[:4]
                        module_encoded_params = self.w3.codec.encode(['uint16[]'], [countries])
                        module_call_data = module_function_selector + module_encoded_params
                        
                        # Build callModuleFunction transaction
                        tx = compliance_contract.functions.callModuleFunction(
                            module_call_data,
                            module_address
                        ).build_transaction({
                            'from': deployer_address,
                            'gas': 500000,  # Generous gas limit
                            'gasPrice': self.w3.eth.gas_price,
                            'nonce': self.w3.eth.get_transaction_count(deployer_address)
                        })
                        
                        configuration_transactions.append({
                            'type': 'CountryAllowModule',
                            'address': module_address,
                            'transaction': tx,
                            'description': f'Allow countries: {countries}'
                        })
                
                elif module_type == 'SupplyLimitModule':
                    # Configure supply limit
                    supply_limit = config.get('supply_limit', 100)
                    if supply_limit > 0:
                        # Convert supply limit to wei (18 decimals)
                        supply_limit_wei = supply_limit * 10**18
                        # Encode setSupplyLimit(uint256 limit)
                        module_function_selector = self.w3.keccak(text="setSupplyLimit(uint256)")[:4]
                        module_encoded_params = self.w3.codec.encode(['uint256'], [supply_limit_wei])
                        module_call_data = module_function_selector + module_encoded_params
                        
                        # Build callModuleFunction transaction
                        tx = compliance_contract.functions.callModuleFunction(
                            module_call_data,
                            module_address
                        ).build_transaction({
                            'from': deployer_address,
                            'gas': 500000,
                            'gasPrice': self.w3.eth.gas_price,
                            'nonce': self.w3.eth.get_transaction_count(deployer_address)
                        })
                        
                        configuration_transactions.append({
                            'type': 'SupplyLimitModule',
                            'address': module_address,
                            'transaction': tx,
                            'description': f'Set supply limit to: {supply_limit} tokens per user'
                        })
                
                elif module_type == 'TimeTransfersLimitsModule':
                    # Configure time transfer limits
                    cooldown_period = config.get('cooldown_period', 300)
                    if cooldown_period > 0:
                        # For TimeTransfersLimitsModule, we need to use setTimeTransferLimit with a Limit struct
                        # Limit struct: {uint32 limitTime, uint256 limitValue}
                        limit_struct = (cooldown_period, 1000)  # (limitTime, limitValue) as tuple
                        
                        # Encode setTimeTransferLimit((uint32,uint256) limit)
                        module_function_selector = self.w3.keccak(text="setTimeTransferLimit((uint32,uint256))")[:4]
                        module_encoded_params = self.w3.codec.encode(['(uint32,uint256)'], [limit_struct])
                        module_call_data = module_function_selector + module_encoded_params
                        
                        # Build callModuleFunction transaction
                        tx = compliance_contract.functions.callModuleFunction(
                            module_call_data,
                            module_address
                        ).build_transaction({
                            'from': deployer_address,
                            'gas': 500000,
                            'gasPrice': self.w3.eth.gas_price,
                            'nonce': self.w3.eth.get_transaction_count(deployer_address)
                        })
                        
                        configuration_transactions.append({
                            'type': 'TimeTransfersLimitsModule',
                            'address': module_address,
                            'transaction': tx,
                            'description': f'Set cooldown period to: {cooldown_period} seconds'
                        })
            
            print(f"✅ Prepared {len(configuration_transactions)} configuration transactions")
            
            return {
                'success': True,
                'compliance_address': compliance_address,
                'configuration_transactions': configuration_transactions
            }
            
        except Exception as e:
            print(f"❌ Error configuring compliance modules: {e}")
            return {'success': False, 'error': str(e)}

    def _load_module_contract(self, module_name):
        """Load pre-compiled module contract data"""
        try:
            import json
            from pathlib import Path
            
            # Path to the module artifact
            module_path = Path(__file__).parent.parent / 'artifacts' / 'contracts' / 'compliance' / 'modular' / 'modules' / f'{module_name}.sol' / f'{module_name}.json'
            
            if not module_path.exists():
                print(f"   ❌ Module artifact not found: {module_path}")
                return None
            
            with open(module_path, 'r') as f:
                artifact = json.load(f)
            
            return {
                'bytecode': artifact['bytecode'],
                'abi': artifact['abi']
            }
            
        except Exception as e:
            print(f"   ❌ Error loading module contract {module_name}: {e}")
            return None

    def deploy_compliance_modules(self, compliance_modules, deployer_address):
        """
        Deploy and configure individual compliance modules
        
        Args:
            compliance_modules (list): List of compliance module configurations
            deployer_address (str): Address of the deployer (platform Account 0)
            
        Returns:
            dict: Result with deployed and configured module addresses
        """
        try:
            print(f"🔧 Deploying and configuring {len(compliance_modules)} compliance modules...")
            
            deployed_modules = []
            
            # Step 1: Deploy individual compliance modules
            for i, module in enumerate(compliance_modules):
                print(f"   Module {i+1}: {module['type']}")
                print(f"     Config: {module['config']}")
                
                if module['type'] == 'CountryAllowModule':
                    result = self._deploy_country_allow_module(module['config'], deployer_address)
                elif module['type'] == 'SupplyLimitModule':
                    result = self._deploy_supply_limit_module(module['config'], deployer_address)
                elif module['type'] == 'TimeTransfersLimitsModule':
                    result = self._deploy_time_transfers_module(module['config'], deployer_address)
                else:
                    print(f"   ⚠️ Unknown module type: {module['type']}")
                    continue
                
                if result and result.get('success'):
                    deployed_modules.append({
                        'type': module['type'],
                        'address': result['address'],
                        'config': module['config']
                    })
                    print(f"   ✅ {module['type']} deployed at: {result['address']}")
                else:
                    error_msg = result.get('error', 'Unknown error') if result else 'No result returned'
                    print(f"   ❌ Failed to deploy {module['type']}: {error_msg}")
                    return {'success': False, 'error': f"Failed to deploy {module['type']}: {error_msg}"}
            
            if not deployed_modules:
                return {
                    'success': False,
                    'error': 'No compliance modules were successfully deployed'
                }
            
            # Step 2: Skip configuration - modules will be configured by the token's compliance contract
            print(f"✅ All compliance modules deployed successfully")
            print(f"   Deployed modules: {len(deployed_modules)}")
            print(f"   Note: Modules will be configured by the token's compliance contract during deployment")
            
            return {
                'success': True,
                'deployed_modules': deployed_modules,
                'compliance_module_addresses': [module['address'] for module in deployed_modules]
            }
            
        except Exception as e:
            print(f"❌ Error deploying compliance modules: {e}")
            return {
                'success': False,
                'error': f'Failed to deploy compliance modules: {e}'
            }

    def _deploy_country_restrict_module(self, config, deployer_address):
        """Deploy CountryRestrictModule contract using pre-compiled bytecode"""
        try:
            print(f"   🚀 Deploying CountryRestrictModule...")
            
            # Load pre-compiled contract data
            module_data = self._load_module_contract('CountryRestrictModule')
            if not module_data:
                print(f"   ❌ Could not load CountryRestrictModule contract data")
                return None
            
            # Deploy the contract
            contract = self.w3.eth.contract(
                bytecode=module_data['bytecode'],
                abi=module_data['abi']
            )
            
            # Deploy the contract
            tx_hash = contract.constructor().transact({
                'from': deployer_address,
                'gas': 4000000  # Increased gas for larger modules
            })
            
            # Wait for deployment
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            module_address = receipt.contractAddress
            
            print(f"   ✅ CountryRestrictModule deployed at: {module_address}")
            print(f"   📋 Will configure with countries: {config.get('allowed_countries', [])}")
            
            return {'success': True, 'address': module_address}
            
        except Exception as e:
            print(f"   ❌ Error deploying CountryRestrictModule: {e}")
            return {'success': False, 'error': str(e)}

    def _deploy_country_allow_module(self, config, deployer_address):
        """Deploy CountryAllowModule contract using pre-compiled bytecode"""
        try:
            print(f"   🚀 Deploying CountryAllowModule...")
            
            # Load pre-compiled contract data
            module_data = self._load_module_contract('CountryAllowModule')
            if not module_data:
                print(f"   ❌ Could not load CountryAllowModule contract data")
                return None
            
            # Deploy the contract
            contract = self.w3.eth.contract(
                bytecode=module_data['bytecode'],
                abi=module_data['abi']
            )
            
            # Deploy the contract
            tx_hash = contract.constructor().transact({
                'from': deployer_address,
                'gas': 4000000  # Increased gas for larger modules
            })
            
            # Wait for deployment
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            module_address = receipt.contractAddress
            
            print(f"   ✅ CountryAllowModule deployed at: {module_address}")
            print(f"   📋 Will configure with allowed countries: {config.get('allowed_countries', [])}")
            
            return {'success': True, 'address': module_address}
            
        except Exception as e:
            print(f"   ❌ Error deploying CountryAllowModule: {e}")
            return {'success': False, 'error': str(e)}

    def _deploy_supply_limit_module(self, config, deployer_address):
        """Deploy SupplyLimitModule contract using pre-compiled bytecode"""
        try:
            print(f"   🚀 Deploying SupplyLimitModule...")
            
            # Load pre-compiled contract data
            module_data = self._load_module_contract('SupplyLimitModule')
            if not module_data:
                print(f"   ❌ Could not load SupplyLimitModule contract data")
                return None
            
            # Deploy the contract
            contract = self.w3.eth.contract(
                bytecode=module_data['bytecode'],
                abi=module_data['abi']
            )
            
            # Deploy the contract
            tx_hash = contract.constructor().transact({
                'from': deployer_address,
                'gas': 3000000  # Increased gas for larger modules
            })
            
            # Wait for deployment
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            module_address = receipt.contractAddress
            
            print(f"   ✅ SupplyLimitModule deployed at: {module_address}")
            
            # Check if this is a per-user limit
            if config.get('per_user_limit', False):
                print(f"   📋 Per-user supply limit: {config.get('supply_limit', 0)} tokens per user")
                # Note: TREX SupplyLimitModule might not support per-user limits directly
                # This would need to be configured after deployment or use a different module
            else:
                print(f"   📋 Total supply limit: {config.get('supply_limit', 0)} tokens")
            
            return {'success': True, 'address': module_address}
            
        except Exception as e:
            print(f"   ❌ Error deploying SupplyLimitModule: {e}")
            return {'success': False, 'error': str(e)}

    def _deploy_time_transfers_module(self, config, deployer_address):
        """Deploy TimeTransfersLimitsModule contract using pre-compiled bytecode"""
        try:
            print(f"   🚀 Deploying TimeTransfersLimitsModule...")
            
            # Load pre-compiled contract data
            module_data = self._load_module_contract('TimeTransfersLimitsModule')
            if not module_data:
                print(f"   ❌ Could not load TimeTransfersLimitsModule contract data")
                return None
            
            # Deploy the contract
            contract = self.w3.eth.contract(
                bytecode=module_data['bytecode'],
                abi=module_data['abi']
            )
            
            # Deploy the contract
            tx_hash = contract.constructor().transact({
                'from': deployer_address,
                'gas': 3000000  # Increased gas for larger modules
            })
            
            # Wait for deployment
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            module_address = receipt.contractAddress
            
            print(f"   ✅ TimeTransfersLimitsModule deployed at: {module_address}")
            print(f"   📋 Will configure with cooldown: {config.get('cooldown_period', 0)} seconds")
            
            return {'success': True, 'address': module_address}
            
        except Exception as e:
            print(f"   ❌ Error deploying TimeTransfersLimitsModule: {e}")
            return {'success': False, 'error': str(e)}

    def _deploy_modular_compliance(self, deployer_address):
        """Deploy ModularCompliance contract using pre-compiled bytecode"""
        try:
            print(f"   🚀 Deploying ModularCompliance contract...")
            
            # Load ModularCompliance contract data
            modular_compliance_data = self._load_modular_compliance_contract()
            if not modular_compliance_data:
                print(f"   ❌ Could not load ModularCompliance contract data")
                return None
            
            # Deploy the contract
            contract = self.w3.eth.contract(
                bytecode=modular_compliance_data['bytecode'],
                abi=modular_compliance_data['abi']
            )
            
            # Deploy the contract
            tx_hash = contract.constructor().transact({
                'from': deployer_address,
                'gas': 5000000  # High gas for complex contract
            })
            
            # Wait for deployment
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            modular_compliance_address = receipt.contractAddress
            
            print(f"   ✅ ModularCompliance deployed at: {modular_compliance_address}")
            
            return modular_compliance_address
            
        except Exception as e:
            print(f"   ❌ Error deploying ModularCompliance: {e}")
            return None

    def _load_modular_compliance_contract(self):
        """Load ModularCompliance contract data from artifacts"""
        try:
            import json
            from pathlib import Path
            
            # Path to the ModularCompliance artifact
            artifact_path = Path(__file__).parent.parent / 'artifacts' / 'trex' / 'ModularCompliance.json'
            
            if not artifact_path.exists():
                print(f"   ❌ ModularCompliance artifact not found: {artifact_path}")
                return None
            
            with open(artifact_path, 'r') as f:
                artifact = json.load(f)
            
            return {
                'bytecode': artifact['bytecode'],
                'abi': artifact['abi']
            }
            
        except Exception as e:
            print(f"   ❌ Error loading ModularCompliance contract: {e}")
            return None

    def _add_modules_to_compliance(self, modular_compliance_address, deployed_modules, deployer_address):
        """Add deployed modules to ModularCompliance contract"""
        try:
            print(f"   🔧 Adding modules to ModularCompliance...")
            
            # Load ModularCompliance contract
            modular_compliance_data = self._load_modular_compliance_contract()
            if not modular_compliance_data:
                return {'success': False, 'error': 'Could not load ModularCompliance contract'}
            
            contract = self.w3.eth.contract(
                address=modular_compliance_address,
                abi=modular_compliance_data['abi']
            )
            
            # Add each module to the compliance contract
            for module in deployed_modules:
                print(f"     Adding {module['type']} at {module['address']}")
                
                # Call addModule function
                tx_hash = contract.functions.addModule(module['address']).transact({
                    'from': deployer_address,
                    'gas': 2000000
                })
                
                # Wait for transaction
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                if receipt.status != 1:
                    return {'success': False, 'error': f'Failed to add {module["type"]} to ModularCompliance'}
                
                print(f"     ✅ Added {module['type']} successfully")
            
            return {'success': True}
            
        except Exception as e:
            print(f"   ❌ Error adding modules to compliance: {e}")
            return {'success': False, 'error': str(e)}

    def _configure_compliance_modules(self, modular_compliance_address, deployed_modules, deployer_address):
        """Configure deployed compliance modules with user settings"""
        try:
            print(f"   🔧 Configuring compliance modules...")
            
            # Configure each module based on its type
            for module in deployed_modules:
                print(f"     Configuring {module['type']}...")
                
                if module['type'] == 'CountryAllowModule':
                    self._configure_country_allow_module(module, deployer_address)
                elif module['type'] == 'SupplyLimitModule':
                    self._configure_supply_limit_module(module, deployer_address)
                elif module['type'] == 'TimeTransfersLimitsModule':
                    self._configure_time_transfers_module(module, deployer_address)
            
            return {'success': True}
            
        except Exception as e:
            print(f"   ❌ Error configuring modules: {e}")
            return {'success': False, 'error': str(e)}

    def _configure_country_restrict_module(self, module, deployer_address):
        """Configure CountryRestrictModule with allowed countries"""
        try:
            config = module['config']
            allowed_countries = config.get('allowed_countries', [])
            
            if not allowed_countries:
                print(f"     ⚠️ No countries specified for CountryRestrictModule")
                return {'success': False, 'error': 'No countries specified'}
            
            # Load module contract
            module_data = self._load_module_contract('CountryRestrictModule')
            if not module_data:
                return {'success': False, 'error': 'Failed to load module contract'}
            
            contract = self.w3.eth.contract(
                address=module['address'],
                abi=module_data['abi']
            )
            
            # Call batchRestrictCountries function
            tx_hash = contract.functions.batchRestrictCountries(allowed_countries).transact({
                'from': deployer_address,
                'gas': 2000000
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status == 1:
                print(f"     ✅ Configured CountryRestrictModule with countries: {allowed_countries}")
                return {'success': True}
            else:
                print(f"     ❌ Failed to configure CountryRestrictModule")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"     ❌ Error configuring CountryRestrictModule: {e}")
            return {'success': False, 'error': str(e)}

    def _configure_country_allow_module(self, module, deployer_address):
        """Configure CountryAllowModule with allowed countries"""
        try:
            config = module['config']
            allowed_countries = config.get('allowed_countries', [])
            
            if not allowed_countries:
                print(f"     ⚠️ No countries specified for CountryAllowModule")
                return {'success': False, 'error': 'No countries specified'}
            
            # Load module contract
            module_data = self._load_module_contract('CountryAllowModule')
            if not module_data:
                return {'success': False, 'error': 'Failed to load module contract'}
            
            contract = self.w3.eth.contract(
                address=module['address'],
                abi=module_data['abi']
            )
            
            # Call batchAllowCountries function
            tx_hash = contract.functions.batchAllowCountries(allowed_countries).transact({
                'from': deployer_address,
                'gas': 2000000
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status == 1:
                print(f"     ✅ Configured CountryAllowModule with allowed countries: {allowed_countries}")
                return {'success': True}
            else:
                print(f"     ❌ Failed to configure CountryAllowModule")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"     ❌ Error configuring CountryAllowModule: {e}")
            return {'success': False, 'error': str(e)}

    def _configure_supply_limit_module(self, module, deployer_address):
        """Configure SupplyLimitModule with supply limit"""
        try:
            config = module['config']
            supply_limit = config.get('supply_limit', 100)
            
            # Load module contract
            module_data = self._load_module_contract('SupplyLimitModule')
            if not module_data:
                return {'success': False, 'error': 'Failed to load module contract'}
            
            contract = self.w3.eth.contract(
                address=module['address'],
                abi=module_data['abi']
            )
            
            # Convert supply limit to wei (18 decimals)
            supply_limit_wei = supply_limit * 10**18
            # Call setSupplyLimit function
            tx_hash = contract.functions.setSupplyLimit(supply_limit_wei).transact({
                'from': deployer_address,
                'gas': 2000000
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status == 1:
                print(f"     ✅ Configured SupplyLimitModule with limit: {supply_limit}")
                return {'success': True}
            else:
                print(f"     ❌ Failed to configure SupplyLimitModule")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"     ❌ Error configuring SupplyLimitModule: {e}")
            return {'success': False, 'error': str(e)}

    def _configure_time_transfers_module(self, module, deployer_address):
        """Configure TimeTransfersLimitsModule with cooldown period"""
        try:
            config = module['config']
            cooldown_period = config.get('cooldown_period', 300)
            
            # Load module contract
            module_data = self._load_module_contract('TimeTransfersLimitsModule')
            if not module_data:
                return {'success': False, 'error': 'Failed to load module contract'}
            
            contract = self.w3.eth.contract(
                address=module['address'],
                abi=module_data['abi']
            )
            
            # Call setCooldownPeriod function (assuming this exists)
            tx_hash = contract.functions.setCooldownPeriod(cooldown_period).transact({
                'from': deployer_address,
                'gas': 2000000
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status == 1:
                print(f"     ✅ Configured TimeTransfersLimitsModule with cooldown: {cooldown_period}s")
                return {'success': True}
            else:
                print(f"     ❌ Failed to configure TimeTransfersLimitsModule")
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            print(f"     ❌ Error configuring TimeTransfersLimitsModule: {e}")
            return {'success': False, 'error': str(e)}

    def _build_deploy_modular_compliance_transaction(self, deployer_address):
        """Build MetaMask transaction for deploying ModularCompliance contract"""
        try:
            print(f"   🔧 Building ModularCompliance deployment transaction...")
            
            # Load ModularCompliance contract data
            modular_compliance_data = self._load_modular_compliance_contract()
            if not modular_compliance_data:
                return {'success': False, 'error': 'Could not load ModularCompliance contract data'}
            
            # Build the contract instance
            contract = self.w3.eth.contract(
                bytecode=modular_compliance_data['bytecode'],
                abi=modular_compliance_data['abi']
            )
            
            # Build unsigned transaction for MetaMask
            tx = contract.constructor().build_transaction({
                'from': deployer_address,
                'gas': 5000000,  # High gas for complex contract
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(deployer_address)
            })
            
            print(f"   ✅ ModularCompliance deployment transaction built successfully")
            
            return {
                'success': True,
                'transaction': {
                    'to': None,  # Contract deployment
                    'data': tx.get('data'),
                    'gas': hex(tx.get('gas')),
                    'gasPrice': hex(tx.get('gasPrice')),
                    'value': '0x0',
                    'chainId': '0x7a69'
                }
            }
            
        except Exception as e:
            print(f"   ❌ Error building ModularCompliance deployment transaction: {e}")
            return {'success': False, 'error': str(e)}

    def _build_add_modules_transactions(self, deployed_modules, deployer_address):
        """Build MetaMask transactions for adding modules to ModularCompliance"""
        try:
            print(f"   🔧 Building add modules transactions...")
            
            # Load ModularCompliance contract data
            modular_compliance_data = self._load_modular_compliance_contract()
            if not modular_compliance_data:
                return {'success': False, 'error': 'Could not load ModularCompliance contract data'}
            
            transactions = []
            
            for i, module in enumerate(deployed_modules):
                print(f"     Building transaction {i+1}: Add {module['type']}")
                
                # Build the actual MetaMask transaction for addModule
                # We'll use a placeholder address that the frontend will replace
                modular_compliance_address = "0x0000000000000000000000000000000000000000"  # Placeholder
                
                # Encode the addModule function call
                add_module_data = self._encode_add_module_call(module['address'], modular_compliance_data['abi'])
                
                transaction = {
                    'to': modular_compliance_address,  # Frontend will replace this
                    'data': add_module_data,
                    'gas': '0x1e8480',  # 2M gas
                    'gasPrice': '0x3b9aca00',  # 1 gwei
                    'value': '0x0',
                    'chainId': '0x7a69',
                    'module_type': module['type'],
                    'module_address': module['address'],
                    'module_config': module['config']
                }
                
                transactions.append(transaction)
            
            return {
                'success': True,
                'transactions': transactions
            }
            
        except Exception as e:
            print(f"   ❌ Error building add modules transactions: {e}")
            return {'success': False, 'error': str(e)}

    def _encode_add_module_call(self, module_address, modular_compliance_abi):
        """Encode the addModule function call for ModularCompliance"""
        try:
            # Find the addModule function in the ABI
            add_module_function = None
            for func in modular_compliance_abi:
                if func.get('name') == 'addModule' and func.get('type') == 'function':
                    add_module_function = func
                    break
            
            if not add_module_function:
                raise Exception("addModule function not found in ModularCompliance ABI")
            
            # Encode the function call
            function_selector = self.web3_service.w3.keccak(
                text=f"{add_module_function['name']}({','.join([inp['type'] for inp in add_module_function['inputs']])})"
            )[:4]
            
            # Encode the parameters
            encoded_params = self.web3_service.w3.codec.encode(
                [inp['type'] for inp in add_module_function['inputs']],
                [module_address]
            )
            
            # Combine selector and encoded parameters
            encoded_data = function_selector + encoded_params
            
            return encoded_data.hex()
            
        except Exception as e:
            print(f"   ❌ Error encoding addModule call: {e}")
            return '0x'

    def _build_configure_modules_transactions(self, deployed_modules, deployer_address):
        """Build MetaMask transactions for configuring modules"""
        try:
            print(f"   🔧 Building configure modules transactions...")
            
            transactions = []
            
            for i, module in enumerate(deployed_modules):
                print(f"     Building transaction {i+1}: Configure {module['type']}")
                
                # Build the actual MetaMask transaction for configuring the module
                config_data = self._encode_configure_module_call(module)
                
                transaction = {
                    'to': module['address'],  # Each module has its own address
                    'data': config_data,
                    'gas': '0x1e8480',  # 2M gas
                    'gasPrice': '0x3b9aca00',  # 1 gwei
                    'value': '0x0',
                    'chainId': '0x7a69',
                    'module_type': module['type'],
                    'module_address': module['address'],
                    'module_config': module['config']
                }
                
                transactions.append(transaction)
            
            return {
                'success': True,
                'transactions': transactions
            }
            
        except Exception as e:
            print(f"   ❌ Error building configure modules transactions: {e}")
            return {'success': False, 'error': str(e)}

    def _encode_configure_module_call(self, module):
        """Encode the configuration function call for a specific module"""
        try:
            module_type = module['type']
            module_config = module['config']
            
            if module_type == 'CountryAllowModule':
                return self._encode_country_allow_config(module_config, module['address'])
            elif module_type == 'SupplyLimitModule':
                return self._encode_supply_limit_config(module_config, module['address'])
            elif module_type == 'TimeTransfersLimitsModule':
                return self._encode_time_transfers_config(module_config, module['address'])
            else:
                print(f"   ⚠️ Unknown module type for configuration: {module_type}")
                return '0x'
                
        except Exception as e:
            print(f"   ❌ Error encoding configure module call: {e}")
            return '0x'

    def _encode_country_restrict_config(self, config, module_address):
        """Encode batchRestrictCountries function call for CountryRestrictModule"""
        try:
            allowed_countries = config.get('allowed_countries', [])
            
            # Function signature: batchRestrictCountries(uint16[] memory _countries)
            function_selector = self.w3.keccak(text="batchRestrictCountries(uint16[])")[:4]
            
            # Encode the parameters
            encoded_params = self.w3.codec.encode(['uint16[]'], [allowed_countries])
            
            return (function_selector + encoded_params).hex()
            
        except Exception as e:
            print(f"   ❌ Error encoding country restrict config: {e}")
            return "0x"  # Return empty data on error

    def _encode_country_allow_config(self, config, module_address):
        """Encode batchAllowCountries function call for CountryAllowModule"""
        try:
            allowed_countries = config.get('allowed_countries', [])
            
            # Function signature: batchAllowCountries(uint16[] memory _countries)
            function_selector = self.w3.keccak(text="batchAllowCountries(uint16[])")[:4]
            
            # Encode the parameters
            encoded_params = self.w3.codec.encode(['uint16[]'], [allowed_countries])
            
            return (function_selector + encoded_params).hex()
            
        except Exception as e:
            print(f"   ❌ Error encoding country allow config: {e}")
            return "0x"  # Return empty data on error

    def _encode_supply_limit_config(self, config, module_address):
        """Encode setSupplyLimit function call for SupplyLimitModule"""
        try:
            supply_limit = config.get('supply_limit', 100)
            # Convert supply limit to wei (18 decimals)
            supply_limit_wei = supply_limit * 10**18
            
            # Function signature: setSupplyLimit(uint256 _limit)
            function_selector = self.w3.keccak(text="setSupplyLimit(uint256)")[:4]
            
            # Encode the parameters
            encoded_params = self.w3.codec.encode(['uint256'], [supply_limit_wei])
            
            return (function_selector + encoded_params).hex()
            
        except Exception as e:
            print(f"   ❌ Error encoding supply limit config: {e}")
            return "0x"  # Return empty data on error

    def _encode_time_transfers_config(self, config, module_address):
        """Encode setCooldownPeriod function call for TimeTransfersLimitsModule"""
        try:
            cooldown_period = config.get('cooldown_period', 300)
            
            # Function signature: setCooldownPeriod(uint256 _cooldownPeriod)
            function_selector = self.w3.keccak(text="setCooldownPeriod(uint256)")[:4]
            
            # Encode the parameters
            encoded_params = self.w3.codec.encode(['uint256'], [cooldown_period])
            
            return (function_selector + encoded_params).hex()
            
        except Exception as e:
            print(f"   ❌ Error encoding time transfers config: {e}")
            return "0x"  # Return empty data on error

    def _get_configure_function_name(self, module_type):
        """Get the function name for configuring a module"""
        function_names = {
            'CountryAllowModule': 'batchAllowCountries',
            'SupplyLimitModule': 'setSupplyLimit',
            'TimeTransfersLimitsModule': 'setCooldownPeriod'
        }
        return function_names.get(module_type, 'configure')

    def _get_configure_function_params(self, module_type, config):
        """Get the function parameters for configuring a module"""
        if module_type == 'CountryAllowModule':
            return [config.get('allowed_countries', [])]
        elif module_type == 'SupplyLimitModule':
            return [config.get('supply_limit', 100)]
        elif module_type == 'TimeTransfersLimitsModule':
            return [config.get('cooldown_period', 300)]
        else:
            return []

    def _build_token_deployment_with_compliance(self, modular_compliance_tx, deployer_address):
        """Build token deployment transaction that includes ModularCompliance address"""
        try:
            print(f"   🔧 Building token deployment with ModularCompliance...")
            
            # For the hybrid approach, we can't build the token deployment transaction yet
            # because we don't have the ModularCompliance address. The frontend will need to:
            # 1. Deploy ModularCompliance first
            # 2. Add and configure modules
            # 3. Then build the token deployment with the actual ModularCompliance address
            
            # Return a placeholder that indicates the token deployment needs to be built later
            return {
                'success': True,
                'transaction': {
                    'to': None,  # Will be set after ModularCompliance deployment
                    'data': '0x',  # Will be built after ModularCompliance deployment
                    'gas': '0x1e8480',  # 2M gas
                    'gasPrice': '0x3b9aca00',  # 1 gwei
                    'value': '0x0',
                    'chainId': '0x7a69',
                    'requires_modular_compliance_address': True  # Flag for frontend
                }
            }
            
        except Exception as e:
            print(f"   ❌ Error building token deployment transaction: {e}")
            return {'success': False, 'error': str(e)}

    def build_add_to_ir_transaction(self, token_address, user_address, onchain_id_address, user_address_for_gas=None, country_code=None):
        """
        Build Add to Identity Registry transaction for MetaMask signing (without executing)
        
        Args:
            token_address (str): Token contract address
            user_address (str): Address to add to Identity Registry
            onchain_id_address (str): OnchainID address
            user_address_for_gas (str): User's wallet address for gas estimation
            country_code (int): Country code for the user (defaults to 840 for US if not provided)
            
        Returns:
            dict: Transaction data for MetaMask signing
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_user_address = self.web3.to_checksum_address(user_address)
            checksum_onchain_id_address = self.web3.to_checksum_address(onchain_id_address)
            
            print(f"🔍 Building Add to IR transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   User address: {user_address} -> {checksum_user_address}")
            print(f"   OnchainID address: {onchain_id_address} -> {checksum_onchain_id_address}")
            
            # Get the token contract to get the Identity Registry address
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Get the Identity Registry address from the token
            identity_registry_address = token_contract.functions.identityRegistry().call()
            print(f"   Identity Registry address: {identity_registry_address}")
            
            # Get the Identity Registry contract
            identity_registry_contract = self.w3.eth.contract(
                address=identity_registry_address,
                abi=self.web3.contract_abis.get('IdentityRegistry', [])
            )
            
            if not identity_registry_contract:
                return {'success': False, 'error': 'Identity Registry ABI not found'}
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address_for_gas if user_address_for_gas else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # Check if the issuer is an agent of the Identity Registry
            try:
                is_agent = identity_registry_contract.functions.isAgent(estimate_from).call()
                print(f"🔍 Is {estimate_from} an agent of Identity Registry? {is_agent}")
                if not is_agent:
                    return {'success': False, 'error': f'Address {estimate_from} is not an agent of the Identity Registry. Cannot register identities.'}
            except Exception as e:
                print(f"⚠️ Could not check agent status: {e}")
            
            # Check if the user is already registered
            try:
                is_registered = identity_registry_contract.functions.contains(checksum_user_address).call()
                print(f"🔍 Is {checksum_user_address} already registered? {is_registered}")
                if is_registered:
                    return {'success': False, 'error': f'Address {checksum_user_address} is already registered in the Identity Registry.'}
            except Exception as e:
                print(f"⚠️ Could not check registration status: {e}")
            
            # Verify OnchainID address is valid (not zero address)
            if checksum_onchain_id_address == "0x0000000000000000000000000000000000000000":
                return {'success': False, 'error': 'OnchainID address is zero address. User must have a valid OnchainID.'}
            
            # Use the correct function name that works in V1: registerIdentity
            # Use provided country_code or default to US (840)
            user_country_code = country_code if country_code is not None else 840
            print(f"🔍 Using country code: {user_country_code}")
            
            estimated_gas = identity_registry_contract.functions.registerIdentity(
                checksum_user_address,
                checksum_onchain_id_address,
                user_country_code
            ).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for registerIdentity: {estimated_gas}, Using: {gas_with_buffer}")
            
            # Build the transaction using the correct function name
            # Use the actual user address for the transaction (not placeholder)
            actual_from_address = user_address_for_gas if user_address_for_gas else checksum_user_address
            
            # DEBUG: Check what function we're actually calling
            print(f"🔍 DEBUG: About to call registerIdentity with:")
            print(f"   Contract address: {identity_registry_address}")
            print(f"   Function: registerIdentity")
            print(f"   Parameters: {checksum_user_address}, {checksum_onchain_id_address}, {user_country_code}")
            
            # Get the function object
            try:
                register_identity_func = identity_registry_contract.functions.registerIdentity
                print(f"🔍 DEBUG: Function object: {register_identity_func}")
                print(f"🔍 DEBUG: Function signature: {register_identity_func.abi}")
            except Exception as e:
                print(f"❌ ERROR getting function object: {e}")
                return {'success': False, 'error': f'Failed to get registerIdentity function: {e}'}
            
            transaction = register_identity_func(
                checksum_user_address,
                checksum_onchain_id_address,
                user_country_code
            ).build_transaction({
                'from': actual_from_address,  # Use actual user address
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'nonce': self.w3.eth.get_transaction_count(actual_from_address),  # Get actual nonce
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
            })
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': str(transaction['data']),  # Already a string, no need to call .hex()
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - let MetaMask handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building Add to IR transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build Add to IR transaction: {str(e)}'}

    def build_verify_kyc_transaction(self, token_address, user_address, user_address_for_gas=None):
        """
        Build Verify KYC transaction for MetaMask signing (without executing)
        
        Args:
            token_address (str): Token contract address
            user_address (str): Address to verify KYC for
            user_address_for_gas (str): User's wallet address for gas estimation
            
        Returns:
            dict: Transaction data for MetaMask signing
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_user_address = self.web3.to_checksum_address(user_address)
            
            print(f"🔍 Building Verify KYC transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   User address: {user_address} -> {checksum_user_address}")
            
            # Get the token contract to get the Identity Registry address
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Get the Identity Registry address from the token
            identity_registry_address = token_contract.functions.identityRegistry().call()
            print(f"   Identity Registry address: {identity_registry_address}")
            
            # Get the Identity Registry contract
            identity_registry_contract = self.w3.eth.contract(
                address=identity_registry_address,
                abi=self.web3.contract_abis.get('IdentityRegistry', [])
            )
            
            if not identity_registry_contract:
                return {'success': False, 'error': 'Identity Registry ABI not found'}
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address_for_gas if user_address_for_gas else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # For KYC verification, we need to check if the user is verified
            # This is typically done by calling isVerified() on the Identity Registry
            # However, since isVerified is read-only, we'll create a transaction that can be used
            # to verify the user's KYC status on-chain
            
            # Estimate gas for a verification check (we'll use a simple call to estimate gas)
            try:
                # Try to estimate gas for isVerified call
                estimated_gas = identity_registry_contract.functions.isVerified(checksum_user_address).estimate_gas({
                    'from': estimate_from
                })
                print(f"📊 Estimated gas for isVerified check: {estimated_gas}")
            except Exception as e:
                print(f"⚠️ Could not estimate gas for isVerified, using default: {e}")
                estimated_gas = 50000  # Default gas for simple verification
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Using gas: {gas_with_buffer}")
            
            # For KYC verification, we'll create a transaction that can be used to verify the user
            # Since this is typically a read operation, we'll create a minimal transaction
            # that can be used to trigger verification logic
            
            # Build a verification transaction (this could be a call to a verification function)
            # For now, we'll use a simple transaction that can be used for verification
            transaction = {
                'to': checksum_token_address,  # Send to token contract
                'data': '0x',  # Empty data (no function call)
                'value': 0,  # No ETH transfer
                'gas': gas_with_buffer,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': 31337
            }
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'],
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - let MetaMask handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building Verify KYC transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build Verify KYC transaction: {str(e)}'}

    def build_transfer_transaction(self, token_address, from_address, to_address, amount, user_address_for_gas=None):
        """
        Build Transfer transaction for MetaMask signing (without executing)
        
        Args:
            token_address (str): Token contract address
            from_address (str): Address to transfer from (should be user's address)
            to_address (str): Address to transfer to
            amount (int): Amount to transfer (in token units, not wei)
            user_address_for_gas (str): User's wallet address for gas estimation
            
        Returns:
            dict: Transaction data for MetaMask signing
        """
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_from_address = self.web3.to_checksum_address(from_address)
            checksum_to_address = self.web3.to_checksum_address(to_address)
            
            print(f"🔍 Building Transfer transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   From address: {from_address} -> {checksum_from_address}")
            print(f"   To address: {to_address} -> {checksum_to_address}")
            print(f"   Amount: {amount}")
            
            # Get the token contract
            token_contract = self.w3.eth.contract(
                address=checksum_token_address,
                abi=self.web3.contract_abis.get('Token', [])
            )
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Use actual user address for gas estimation if provided, otherwise use from_address
            estimate_from = user_address_for_gas if user_address_for_gas else checksum_from_address
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # Parse amount to wei (assuming 18 decimals)
            amount_wei = self.web3.parse_units(amount, 18)
            print(f"🔍 Amount in wei: {amount_wei}")
            
            # Estimate gas for transfer
            try:
                estimated_gas = token_contract.functions.transfer(
                    checksum_to_address,
                    amount_wei
                ).estimate_gas({
                    'from': estimate_from
                })
                print(f"📊 Estimated gas for transfer: {estimated_gas}")
            except Exception as e:
                print(f"⚠️ Could not estimate gas for transfer, using default: {e}")
                estimated_gas = 100000  # Default gas for transfer
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Using gas: {gas_with_buffer}")
            
            # Build the transfer transaction
            transaction = {
                'to': checksum_token_address,
                'data': token_contract.functions.transfer(
                    checksum_to_address,
                    amount_wei
                ).build_transaction({
                    'from': estimate_from,
                    'gas': gas_with_buffer,
                    'gasPrice': self.w3.eth.gas_price,
                    'chainId': 31337
                })['data'],
                'value': 0,  # No ETH transfer
                'gas': gas_with_buffer,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': 31337
            }
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'from': checksum_from_address,  # Add the 'from' address for MetaMask
                    'to': transaction['to'],
                    'data': transaction['data'],
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - let MetaMask handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building Transfer transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build Transfer transaction: {str(e)}'}

    def build_add_key_transaction(self, onchainid_address, wallet_address, purpose, key_type=1, user_address=None):
        """Build add key transaction for MetaMask signing"""
        try:
            print(f"🔍 Building add key transaction:")
            print(f"   OnchainID: {onchainid_address}")
            print(f"   Wallet: {wallet_address}")
            print(f"   Purpose: {purpose}")
            print(f"   Key Type: {key_type}")
            print(f"   User Address: {user_address}")
            
            # Convert addresses to checksum format
            checksum_onchainid_address = self.web3.w3.to_checksum_address(onchainid_address)
            checksum_wallet_address = self.web3.w3.to_checksum_address(wallet_address)
            
            # The user_address is the one who will sign with MetaMask
            if user_address:
                checksum_user_address = self.web3.w3.to_checksum_address(user_address)
            else:
                # Fallback to wallet_address if no user_address provided
                checksum_user_address = checksum_wallet_address
            
            # Get the OnchainID contract
            print(f"🔍 Creating OnchainID contract:")
            print(f"   Address: {checksum_onchainid_address}")
            print(f"   ABI loaded: {'Identity' in self.web3.contract_abis}")
            
            contract = self.web3.get_contract(checksum_onchainid_address, 'Identity')
            if not contract:
                return {'success': False, 'error': 'OnchainID contract not found'}
            
            # Calculate key hash using 32-byte ABI encoding (correct method)
            key_hash = self._hash_address_abi_encoded(checksum_wallet_address)
            print(f"🔍 Calculated key hash (32-byte ABI encoded): {key_hash.hex()}")
            
            # Build the transaction data
            add_key_function = contract.functions.addKey(
                key_hash,
                purpose,  # 1=Management, 2=Action, 3=Claim Signer
                key_type  # 1=ECDSA, 2=ERC725
            )
            
            # Estimate gas with the user's address (like transfer function does)
            try:
                gas_estimate = add_key_function.estimate_gas({'from': checksum_user_address})
                gas_with_buffer = int(gas_estimate * 1.2)  # Add 20% buffer
                print(f"🔍 Gas estimated: {gas_estimate}, with buffer: {gas_with_buffer}")
            except Exception as e:
                print(f"⚠️ Gas estimation failed: {str(e)}, using fallback")
                gas_with_buffer = 200000000  # Fallback gas limit

            print(f"🔍 Using gas limit: {gas_with_buffer}")
            
            # Build transaction with 'from' field (like transfer function does)
            transaction_data = add_key_function.build_transaction({
                'from': checksum_user_address,
                'gas': gas_with_buffer,
                'gasPrice': self.web3.w3.eth.gas_price,
                'chainId': 31337
            })
            
            # Build the transaction (like transfer function does)
            transaction = {
                'to': checksum_onchainid_address,
                'data': add_key_function.build_transaction({
                    'from': checksum_user_address,
                    'gas': gas_with_buffer,
                    'gasPrice': self.web3.w3.eth.gas_price,
                    'chainId': 31337
                })['data'],
                'value': 0,  # No ETH transfer
                'gas': gas_with_buffer,
                'gasPrice': self.web3.w3.eth.gas_price,
                'chainId': 31337
            }
            
            # Return transaction data for MetaMask signing (exactly like transfer function)
            return {
                'success': True,
                'message': f'Ready to add key {checksum_wallet_address} with purpose {purpose}',
                'transaction': {
                    'from': checksum_user_address,  # Add the 'from' address for MetaMask
                    'to': transaction['to'],
                    'data': transaction['data'],
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - let MetaMask handle it automatically
                },
                'key_hash': key_hash.hex(),
                'purpose': purpose,
                'key_type': key_type
            }
            
        except Exception as e:
            print(f"❌ Error building add key transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build add key transaction: {str(e)}'}

    def build_remove_key_transaction(self, onchainid_address, wallet_address, user_address):
        """Build remove key transaction for MetaMask signing"""
        try:
            print(f"🔍 Building remove key transaction:")
            print(f"   OnchainID: {onchainid_address}")
            print(f"   Wallet to remove: {wallet_address}")
            print(f"   User signing: {user_address}")
            
            # Convert addresses to checksum format
            checksum_onchainid_address = self.web3.to_checksum_address(onchainid_address)
            checksum_wallet_address = self.web3.to_checksum_address(wallet_address)
            checksum_user_address = self.web3.to_checksum_address(user_address)
            
            # Get the OnchainID contract
            print(f"🔍 Creating OnchainID contract:")
            print(f"   Address: {checksum_onchainid_address}")
            print(f"   ABI loaded: {'Identity' in self.web3.contract_abis}")
            
            contract = self.web3.get_contract(checksum_onchainid_address, 'Identity')
            if not contract:
                return {'success': False, 'error': 'OnchainID contract not found'}
            
            # Calculate key hash using 32-byte ABI encoding (correct method)
            key_hash = self._hash_address_abi_encoded(checksum_wallet_address)
            print(f"🔍 Calculated key hash (32-byte ABI encoded): {key_hash.hex()}")
            
            # Build the transaction data
            transaction_data = contract.functions.removeKey(
                key_hash
            ).build_transaction({
                'from': checksum_user_address,  # The user who will sign with MetaMask
                'gas': 150000,  # Estimated gas for removeKey
                'gasPrice': self.web3.w3.eth.gas_price,
                'chainId': self.web3.w3.eth.chain_id,
                'nonce': self.web3.w3.eth.get_transaction_count(checksum_user_address)
            })
            
            print(f"🔍 Transaction data built successfully")
            print(f"   Gas: {transaction_data['gas']}")
            print(f"   Gas Price: {transaction_data['gasPrice']}")
            print(f"   Chain ID: {transaction_data['chainId']}")
            
            return {
                'success': True,
                'message': f'Ready to remove key {checksum_wallet_address}',
                'transaction': {
                    'to': transaction_data['to'],
                    'value': hex(transaction_data['value']),
                    'data': transaction_data['data'],
                    'gas': hex(transaction_data['gas']),
                    'gasPrice': hex(transaction_data['gasPrice']),
                    'chainId': hex(transaction_data['chainId']),
                    'from': transaction_data['from']
                },
                'key_hash': key_hash.hex(),
                'wallet_address': checksum_wallet_address
            }
            
        except Exception as e:
            print(f"❌ Error building remove key transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build remove key transaction: {str(e)}'}

    def build_pause_transaction(self, token_address, user_address=None):
        """Build pause transaction for MetaMask signing"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            
            # Get the token contract
            print(f"🔍 Creating pause token contract:")
            print(f"   Address: {checksum_token_address}")
            print(f"   ABI loaded: {'Token' in self.web3.contract_abis}")
            print(f"   ABI length: {len(self.web3.contract_abis.get('Token', []))}")
            
            token_contract = self.web3.get_contract(checksum_token_address, 'Token')
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            print(f"   Contract created: {token_contract is not None}")
            print(f"   Contract address: {token_contract.address}")
            
            # Build the pause transaction (without signing)
            # Note: 'from' field will be overridden by MetaMask with the connected account
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the pause operation
            estimated_gas = token_contract.functions.pause().estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for pause: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = token_contract.functions.pause().build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Debug: Print transaction object
            print(f"🔍 Built pause transaction object:")
            print(f"   to: {transaction['to']}")
            print(f"   data: {transaction['data']}")
            print(f"   value: {transaction['value']}")
            print(f"   gas: {transaction['gas']}")
            print(f"   gasPrice: {transaction['gasPrice']}")
            print(f"   chainId: {transaction['chainId']}")
            # Note: 'nonce' is not included - MetaMask will handle it automatically
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - MetaMask will handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building pause transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build pause transaction: {str(e)}'}

    def build_unpause_transaction(self, token_address, user_address=None):
        """Build unpause transaction for MetaMask signing"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            
            # Get the token contract
            token_contract = self.web3.get_contract(checksum_token_address, 'Token')
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Build the unpause transaction (without signing)
            # Note: 'from' field will be set by MetaMask with the connected account
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the unpause operation
            estimated_gas = token_contract.functions.unpause().estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for unpause: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = token_contract.functions.unpause().build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - MetaMask will handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building unpause transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build unpause transaction: {str(e)}'}

    def build_force_transfer_transaction(self, token_address, from_address, to_address, amount, user_address=None):
        """Build force transfer transaction for MetaMask signing"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_from_address = self.web3.to_checksum_address(from_address)
            checksum_to_address = self.web3.to_checksum_address(to_address)
            
            # Get the token contract
            token_contract = self.web3.get_contract(checksum_token_address, 'Token')
            
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Build the force transfer transaction (without signing)
            # Note: 'from' field will be set by MetaMask with the connected account
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the force transfer operation
            estimated_gas = token_contract.functions.forcedTransfer(
                checksum_from_address,
                checksum_to_address,
                amount_wei
            ).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for force transfer: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = token_contract.functions.forcedTransfer(
                checksum_from_address,
                checksum_to_address,
                amount_wei
            ).build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Debug: Print transaction object
            print(f"🔍 Built force transfer transaction object:")
            print(f"   to: {transaction['to']}")
            print(f"   data: {transaction['data']}")
            print(f"   value: {transaction['value']}")
            print(f"   gas: {transaction['gas']}")
            print(f"   gasPrice: {transaction['gasPrice']}")
            print(f"   chainId: {transaction['chainId']}")
            # Note: 'nonce' is not included - MetaMask will handle it automatically
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                    # Note: 'nonce' is not included - MetaMask will handle it automatically
                }
            }
            
        except Exception as e:
            print(f"❌ Error building force transfer transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build force transfer transaction: {str(e)}'} 

    def build_add_ir_agent_transaction(self, token_address, agent_address, user_address=None):
        """Build add IR agent transaction for MetaMask signing"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_agent_address = self.web3.to_checksum_address(agent_address)
            
            print(f"🔍 Building add IR agent transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   Agent address: {agent_address} -> {checksum_agent_address}")
            
            # Get the Identity Registry address from the database (like V1 did)
            # Since we know the deployment worked and we have the real addresses, use them directly
            try:
                from models import Token
                token_record = Token.query.filter_by(token_address=token_address).first()
                if not token_record:
                    return {'success': False, 'error': 'Token not found in database'}
                
                identity_registry_address = token_record.identity_registry_address
                if not identity_registry_address:
                    return {'success': False, 'error': 'Identity Registry address not found in token record'}
                
                print(f"🔍 Using Identity Registry address from database: {identity_registry_address}")
                print(f"🔍 Token address: {token_address}")
                print(f"🔍 Token name: {token_record.name if token_record else 'Unknown'}")
                print(f"🔍 Token symbol: {token_record.symbol if token_record else 'Unknown'}")
                
            except Exception as e:
                print(f"❌ Error getting Identity Registry address from database: {e}")
                return {'success': False, 'error': f'Could not get Identity Registry address: {str(e)}'}
            
            # Get the Identity Registry contract
            ir_contract = self.web3.get_contract(identity_registry_address, 'IdentityRegistry')
            if not ir_contract:
                return {'success': False, 'error': 'Identity Registry contract ABI not found'}
            
            print(f"🔍 Identity Registry contract loaded successfully")
            print(f"🔍 IR contract address: {identity_registry_address}")
            print(f"🔍 IR contract ABI: {len(ir_contract.abi) if hasattr(ir_contract, 'abi') else 'Unknown'} functions")
            
            # CHECK ISSUER PERMISSIONS
            print(f"🔍 CHECKING ISSUER PERMISSIONS:")
            
            # Check if issuer can add agents to IR
            try:
                # Check if issuer is IR owner or has admin role
                ir_owner = ir_contract.functions.owner().call()
                print(f"   IR owner: {ir_owner}")
                print(f"   Issuer address: {user_address if user_address else 'Not provided'}")
                if user_address:
                    print(f"   Issuer is IR owner: {ir_owner.lower() == user_address.lower()}")
            except Exception as e:
                print(f"   ❌ Error checking IR owner: {e}")
            
            # Check if issuer is already an agent
            if user_address:
                try:
                    is_agent = ir_contract.functions.isAgent(user_address).call()
                    print(f"   Issuer is already IR agent: {is_agent}")
                    
                    # If issuer is NOT an agent, we can't add new agents
                    if not is_agent:
                        print(f"   ❌ ISSUER IS NOT AN IR AGENT! Cannot add new agents.")
                        print(f"   This means the deployment did NOT properly set the issuer as an IR agent.")
                        return {'success': False, 'error': 'Issuer is not an IR agent. Cannot add new agents.'}
                    else:
                        print(f"   ✅ ISSUER IS AN IR AGENT! Can proceed with adding new agent.")
                        
                except Exception as e:
                    print(f"   ❌ Error checking if issuer is agent: {e}")
                    return {'success': False, 'error': f'Could not verify issuer agent status: {e}'}
            else:
                print(f"   ⚠️ No user address provided for agent check")
                return {'success': False, 'error': 'User address required to verify agent status'}
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the addAgent operation
            estimated_gas = ir_contract.functions.addAgent(checksum_agent_address).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for add IR agent: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = ir_contract.functions.addAgent(checksum_agent_address).build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Debug: Print transaction object
            print(f"🔍 Built add IR agent transaction object:")
            print(f"   to: {transaction['to']}")
            print(f"   data: {transaction['data']}")
            print(f"   value: {transaction['value']}")
            print(f"   gas: {transaction['gas']}")
            print(f"   gasPrice: {transaction['gasPrice']}")
            print(f"   chainId: {transaction['chainId']}")
            
            # PRINT EXACT PARAMETERS BEING SENT TO METAMASK
            print(f"🔍 EXACT PARAMETERS BEING SENT TO METAMASK:")
            print(f"   to: {transaction['to']}")
            print(f"   data: {transaction['data']}")
            print(f"   value: {transaction['value']}")
            print(f"   gas: {transaction['gas']}")
            print(f"   gasPrice: {transaction['gasPrice']}")
            print(f"   chainId: {transaction['chainId']}")
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': str(transaction['data']),  # Already a string, no need to call .hex()
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                }
            }
            
        except Exception as e:
            print(f"❌ Error building add IR agent transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build add IR agent transaction: {str(e)}'}

    def build_add_token_agent_transaction(self, token_address, agent_address, user_address=None):
        """Build add token agent transaction for MetaMask signing"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_agent_address = self.web3.to_checksum_address(agent_address)
            
            print(f"🔍 Building add token agent transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   Agent address: {agent_address} -> {checksum_agent_address}")
            
            # Get the token contract
            token_contract = self.web3.get_contract(checksum_token_address, 'Token')
            if not token_contract:
                return {'success': False, 'error': 'Token contract ABI not found'}
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the addAgent operation
            estimated_gas = token_contract.functions.addAgent(checksum_agent_address).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for add token agent: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = token_contract.functions.addAgent(checksum_agent_address).build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Debug: Print transaction object
            print(f"🔍 Built add token agent transaction object:")
            print(f"   to: {transaction['to']}")
            print(f"   data: {transaction['data']}")
            print(f"   value: {transaction['value']}")
            print(f"   gas: {transaction['gas']}")
            print(f"   gasPrice: {transaction['gasPrice']}")
            print(f"   chainId: {transaction['chainId']}")
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                }
            }
            
        except Exception as e:
            print(f"❌ Error building add token agent transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build add token agent transaction: {str(e)}'}

    def build_add_trusted_issuer_transaction(self, token_address, trusted_issuer_address, claim_topics, user_address=None):
        """Build add trusted issuer transaction for MetaMask signing"""
        try:
            # Convert addresses to checksum format
            checksum_token_address = self.web3.to_checksum_address(token_address)
            checksum_trusted_issuer_address = self.web3.to_checksum_address(trusted_issuer_address)
            
            print(f"🔍 Building add trusted issuer transaction:")
            print(f"   Token address: {token_address} -> {checksum_token_address}")
            print(f"   Trusted issuer address: {trusted_issuer_address} -> {checksum_trusted_issuer_address}")
            print(f"   Claim topics: {claim_topics}")
            
            # Get the token's Identity Registry address first
            token_info = self.get_token_info(token_address)
            if not token_info.get('success') or not token_info.get('token_info'):
                return {'success': False, 'error': 'Failed to get token info'}
            
            identity_registry_address = token_info['token_info'].get('identity_registry')
            if not identity_registry_address:
                return {'success': False, 'error': 'Token has no Identity Registry'}
            
            # Get the TrustedIssuersRegistry address from the Identity Registry
            ir_contract = self.web3.get_contract(identity_registry_address, 'IdentityRegistry')
            if not ir_contract:
                return {'success': False, 'error': 'Identity Registry contract ABI not found'}
            
            # Get the TrustedIssuersRegistry address
            trusted_issuers_registry_address = ir_contract.functions.issuersRegistry().call()
            if not trusted_issuers_registry_address:
                return {'success': False, 'error': 'Token has no TrustedIssuersRegistry'}
            
            # Get the TrustedIssuersRegistry contract
            tir_contract = self.web3.get_contract(trusted_issuers_registry_address, 'TrustedIssuersRegistry')
            if not tir_contract:
                return {'success': False, 'error': 'TrustedIssuersRegistry contract ABI not found'}
            
            # Use actual user address for gas estimation if provided, otherwise use placeholder
            estimate_from = user_address if user_address else '0x0000000000000000000000000000000000000000'
            print(f"🔍 Using address for gas estimation: {estimate_from}")
            
            # First estimate gas for the addTrustedIssuer operation
            estimated_gas = tir_contract.functions.addTrustedIssuer(
                checksum_trusted_issuer_address,
                claim_topics
            ).estimate_gas({
                'from': estimate_from
            })
            
            # Add 20% buffer for safety
            gas_with_buffer = int(estimated_gas * 1.2)
            print(f"📊 Estimated gas for add trusted issuer: {estimated_gas}, Using: {gas_with_buffer}")
            
            transaction = tir_contract.functions.addTrustedIssuer(
                checksum_trusted_issuer_address,
                claim_topics
            ).build_transaction({
                'from': '0x0000000000000000000000000000000000000000',  # Placeholder, will be set by MetaMask
                'gas': gas_with_buffer,  # Estimated gas with buffer
                'gasPrice': self.w3.eth.gas_price,  # Use current network gas price
                'chainId': 31337  # Hardhat local network (0x7a69 in hex)
                # Note: Removed 'nonce' - let MetaMask handle it automatically
            })
            
            # Debug: Print transaction object
            print(f"🔍 Built add trusted issuer transaction object:")
            print(f"   to: {transaction['to']}")
            print(f"   data: {transaction['data']}")
            print(f"   value: {transaction['value']}")
            print(f"   gas: {transaction['gas']}")
            print(f"   gasPrice: {transaction['gasPrice']}")
            print(f"   chainId: {transaction['chainId']}")
            
            # Return transaction data for MetaMask signing
            return {
                'success': True,
                'transaction': {
                    'to': transaction['to'],
                    'data': transaction['data'].hex() if hasattr(transaction['data'], 'hex') else str(transaction['data']),
                    'value': hex(transaction['value']) if isinstance(transaction['value'], int) else str(transaction['value']),
                    'gas': hex(transaction['gas']) if isinstance(transaction['gas'], int) else str(transaction['gas']),
                    'gasPrice': hex(transaction['gasPrice']) if isinstance(transaction['gasPrice'], int) else str(transaction['gasPrice']),
                    'chainId': hex(transaction['chainId']) if isinstance(transaction['chainId'], int) else str(transaction['chainId'])
                }
            }
            
        except Exception as e:
            print(f"❌ Error building add trusted issuer transaction: {str(e)}")
            return {'success': False, 'error': f'Failed to build add trusted issuer transaction: {str(e)}'}

    def build_deployment_transaction(self, deployer_address, token_name, token_symbol, total_supply, claim_topics, claim_issuer_address, compliance_modules=None, compliance_module_addresses=None):
        print(f"🔍 DEBUG: build_deployment_transaction called with claim_issuer_address: {claim_issuer_address}")
        """Build unsigned deployment transaction for MetaMask"""
        try:
            print("🚀 Building ERC-3643 Token Deployment transaction for MetaMask")
            print("=" * 60)
            
            # Get contract addresses from database
            try:
                from models import Contract
                gateway_contract = Contract.query.filter_by(contract_type='TREXGateway').first()
                gateway_address = gateway_contract.contract_address if gateway_contract else None
                
                factory_contract = Contract.query.filter_by(contract_type='TREXFactory').first()
                trex_factory_address = factory_contract.contract_address if factory_contract else None
                
                if not gateway_address or not trex_factory_address:
                    raise ValueError("Gateway or Factory not found in database")
                    
                print(f"🏛️ Using contract addresses from database:")
                print(f"   Gateway: {gateway_address}")
                print(f"   Factory: {trex_factory_address}")
                    
            except Exception as e:
                print(f"❌ Error getting contract addresses from database: {e}")
                return {
                    'success': False,
                    'error': f'Could not get contract addresses: {e}',
                    'note': 'Check if contracts are deployed and in database'
                }
            
            # Get Gateway contract instance once and reuse it
            print(f"\n🔍 Getting Gateway contract instance...")
            try:
                gateway_contract = self.web3.get_contract(gateway_address, 'TREXGateway')
                if not gateway_contract:
                    raise ValueError("Failed to get Gateway contract instance")
                print(f"✅ Gateway contract instance obtained successfully")
            except Exception as e:
                print(f"❌ Error getting Gateway contract: {e}")
                return {
                    'success': False,
                    'error': f'Could not get Gateway contract: {e}',
                    'note': 'Check if Gateway contract is deployed and ABI is loaded'
                }
            
            # Check Gateway roles for deployer
            print(f"\n🔍 Checking Gateway roles for {deployer_address}...")
            try:
                is_deployer = gateway_contract.functions.isDeployer(deployer_address).call()
                is_agent = gateway_contract.functions.isAgent(deployer_address).call()
                gateway_owner = gateway_contract.functions.owner().call()
                
                print(f"   Is Deployer: {is_deployer}")
                print(f"   Is Agent: {is_agent}")
                print(f"   Gateway Owner: {gateway_owner}")
                
                if not is_deployer and not is_agent:
                    print("❌ Deployer has no Gateway permissions!")
                    return {
                        'success': False,
                        'error': 'Deployer has no Gateway permissions',
                        'note': 'Contact admin to add deployer role'
                    }
                    
            except Exception as e:
                print(f"⚠️ Could not check Gateway roles: {e}")
            
            # Process compliance modules
            if compliance_module_addresses:
                # Use provided compliance module addresses (for build_with_compliance)
                print(f"🔧 Using provided compliance module addresses: {compliance_module_addresses}")
                compliance_settings = [b""] * len(compliance_module_addresses)  # Empty settings for now
            elif compliance_modules:
                print(f"🔧 Processing {len(compliance_modules)} compliance modules...")
                
                # Deploy and configure compliance modules
                deployment_result = self.deploy_compliance_modules(compliance_modules, deployer_address)
                
                if deployment_result['success']:
                    print(f"✅ Compliance modules deployed and configured successfully")
                    print(f"   Deployed modules: {len(deployment_result['deployed_modules'])}")
                    
                    # Use the deployed module addresses directly
                    compliance_module_addresses = deployment_result['compliance_module_addresses']
                    
                    # Use empty compliance settings during deployment (modules will be added but not configured)
                    # Configuration will be done after deployment via separate transactions
                    compliance_settings = []
                    print(f"   ⚠️  Using empty compliance settings - modules will be added but not configured")
                    print(f"   📝 Note: Compliance modules will be configured after token deployment")
                    
                    print(f"   Compliance module addresses: {compliance_module_addresses}")
                    print(f"   Compliance settings: {[s.hex() for s in compliance_settings]}")
                else:
                    print(f"❌ Failed to deploy compliance modules: {deployment_result.get('error', 'Unknown error')}")
                    print("⚠️  Proceeding without compliance modules")
                    compliance_module_addresses = []
                    compliance_settings = []
            else:
                print("🔧 No compliance modules specified")
                compliance_module_addresses = []
                compliance_settings = []
            
            # Build token details structure as TUPLE - MUST match TREX Gateway ABI exactly
            # Format: (address,string,string,uint8,address,address,address[],address[],address[],bytes[])
            token_details_tuple = (
                deployer_address,  # owner (address)
                token_name,        # name (string)
                token_symbol,      # symbol (string)
                18,                # decimals (uint8)
                "0x" + "0" * 40,  # irs (address) - ZeroAddress
                "0x" + "0" * 40,  # ONCHAINID (address) - ZeroAddress
                [deployer_address],  # irAgents (address[])
                [deployer_address],  # tokenAgents (address[])
                compliance_module_addresses,  # complianceModules (address[])
                compliance_settings           # complianceSettings (bytes[])
            )
            
            # Build claim details structure as TUPLE
            # Format: (uint256[],address[],uint256[][])
            claim_topics_int = [int(topic) for topic in claim_topics]
            claim_details_tuple = (
                claim_topics_int,                    # claimTopics (uint256[])
                [claim_issuer_address],              # issuers (address[])
                [claim_topics_int]                   # issuerClaims (uint256[][]) - Array of arrays
            )
            
            print(f"🔧 Token Details Structure (Tuple Format):")
            print(f"   Owner: {token_details_tuple[0]}")
            print(f"   Name: {token_details_tuple[1]}")
            print(f"   Symbol: {token_details_tuple[2]}")
            print(f"   Decimals: {token_details_tuple[3]}")
            print(f"   IRS: {token_details_tuple[4]}")
            print(f"   ONCHAINID: {token_details_tuple[5]}")
            print(f"   IR Agents: {token_details_tuple[6]}")
            print(f"   Token Agents: {token_details_tuple[7]}")
            print(f"   Compliance Modules: {token_details_tuple[8]}")
            print(f"   Compliance Settings: {token_details_tuple[9]}")
            
            if compliance_modules:
                print(f"🔧 Compliance Modules Configuration:")
                for i, module in enumerate(compliance_modules):
                    print(f"   Module {i+1}: {module['type']}")
                    print(f"     Config: {module['config']}")
            
            print(f"🔧 Claim Details Structure (Tuple Format):")
            print(f"   Claim Topics: {claim_details_tuple[0]}")
            print(f"   Issuers: {claim_details_tuple[1]}")
            print(f"   Issuer Claims: {claim_details_tuple[2]}")
            print(f"   Claim Issuer Address: {claim_issuer_address}")
            
            # CRITICAL: Add post-deployment minting step
            print(f"🔧 Post-Deployment Plan:")
            print(f"   1. Deploy token suite via Gateway")
            print(f"   2. Mint initial supply to owner: {total_supply} tokens")
            print(f"   3. Verify token responds to identityRegistry() calls")
            print(f"   4. Verify token responds to compliance() calls")
            
            # Build unsigned transaction for MetaMask
            print("🔧 Building unsigned deployment transaction...")
            try:
                # Reuse the same gateway_contract instance from above
                
                # Build the transaction
                print(f"🔍 CRITICAL: About to call deployTREXSuite with:")
                print(f"   token_details_tuple: {token_details_tuple}")
                print(f"   claim_details_tuple: {claim_details_tuple}")
                print(f"   deployer_address: {deployer_address}")
                
                # Verify the structure matches the ABI exactly
                print(f"🔍 VERIFYING STRUCTURE MATCHES ABI:")
                print(f"   token_details_tuple length: {len(token_details_tuple)}")
                print(f"   claim_details_tuple length: {len(claim_details_tuple)}")
                

                # Try to estimate gas first, with fallback to reasonable limit
                try:
                    estimated_gas = gateway_contract.functions.deployTREXSuite(
                        token_details_tuple,
                        claim_details_tuple
                    ).estimate_gas({'from': deployer_address})
                    gas_limit = int(estimated_gas * 1.2)  # Add 20% buffer
                    print(f"✅ Gas estimated: {estimated_gas}, using: {gas_limit}")
                except Exception as gas_error:
                    print(f"⚠️ Gas estimation failed: {gas_error}")
                    gas_limit = 2000000  # Fallback to 2M gas limit
                    print(f"🔄 Using fallback gas limit: {gas_limit}")

                tx = gateway_contract.functions.deployTREXSuite(
                    token_details_tuple,
                    claim_details_tuple
                ).build_transaction({
                    'from': deployer_address,
                    'gas': gas_limit,
                    'gasPrice': self.web3.w3.eth.gas_price,
                    'nonce': self.web3.w3.eth.get_transaction_count(deployer_address)
                })
                
                print(f"✅ Transaction built successfully!")
                print(f"   To: {tx.get('to')}")
                print(f"   From: {tx.get('from')}")
                print(f"   Gas: {tx.get('gas')}")
                print(f"   Gas Price: {tx.get('gasPrice')}")
                print(f"   Nonce: {tx.get('nonce')}")
                print(f"   Data: {tx.get('data')[:66]}...")
                
                # CRITICAL: Print the exact transaction data being sent to MetaMask
                print(f"🔍 CRITICAL DEBUG - EXACT TRANSACTION DATA:")
                print(f"   Raw data length: {len(tx.get('data'))}")
                print(f"   Raw data type: {type(tx.get('data'))}")
                print(f"   Raw data: {tx.get('data')}")
                # Only try to get hex if it's bytes, otherwise it's already a string
                if hasattr(tx.get('data'), 'hex'):
                    print(f"   Raw data (hex): {tx.get('data').hex()}")
                    print(f"   Function selector: {tx.get('data')[:10].hex()}")
                else:
                    print(f"   Raw data (already string): {tx.get('data')[:100]}...")
                    print(f"   Function selector: {tx.get('data')[:10]}")
                
                # Decode the function call to see what's actually being sent
                try:
                    # Get the function signature from the ABI
                    deploy_function = gateway_contract.functions.deployTREXSuite
                    print(f"   Function name: deployTREXSuite")
                    print(f"   Function signature: {deploy_function.fn_name}")
                    
                    # Decode the input data to verify parameters
                    # Use the contract's decode_function_result method instead
                    try:
                        # Try to decode using the contract's built-in method
                        decoded_input = gateway_contract.decode_function_result('deployTREXSuite', tx.get('data'))
                        print(f"   Decoded function result: {decoded_input}")
                    except Exception as decode_error:
                        print(f"   Could not decode using contract method: {decode_error}")
                        # Fallback: manually parse the data to extract agent addresses
                        print(f"   🔍 MANUAL AGENT ADDRESS EXTRACTION:")
                        data_str = tx.get('data')
                        if data_str and len(data_str) > 10:
                            # Look for our issuer address in the data
                            issuer_address_lower = deployer_address.lower()[2:]  # Remove 0x prefix
                            if issuer_address_lower in data_str.lower():
                                print(f"      ✅ Found issuer address {deployer_address} in transaction data!")
                            else:
                                print(f"      ❌ Issuer address {deployer_address} NOT found in transaction data!")
                                print(f"      This would explain why agent permissions are not set!")
                        else:
                            print(f"      ❌ Transaction data is empty or too short")
                    
                    # CRITICAL: Check if our issuer address is in the transaction data
                    print(f"   🔍 CRITICAL AGENT VERIFICATION:")
                    print(f"      deployer_address: {deployer_address}")
                    print(f"      deployer_address type: {type(deployer_address)}")
                    print(f"      deployer_address checksum: {self.web3.to_checksum_address(deployer_address) if deployer_address else 'None'}")
                    
                    # Manual verification that our agent addresses are in the transaction data
                    data_str = tx.get('data')
                    if data_str and len(data_str) > 10:
                        # Look for our issuer address in the data
                        issuer_address_lower = deployer_address.lower()[2:]  # Remove 0x prefix
                        if issuer_address_lower in data_str.lower():
                            print(f"      ✅ Found issuer address {deployer_address} in transaction data!")
                            print(f"      This confirms our agent parameters are being sent correctly!")
                        else:
                            print(f"      ❌ Issuer address {deployer_address} NOT found in transaction data!")
                            print(f"      This would explain why agent permissions are not set!")
                    else:
                        print(f"      ❌ Transaction data is empty or too short")
                        
                except Exception as decode_error:
                    print(f"   ❌ Error decoding transaction data: {decode_error}")
                    import traceback
                    traceback.print_exc()
                
                # Print the exact MetaMask transaction parameters
                metamask_transaction = {
                    'to': tx.get('to'),
                    'data': tx.get('data').hex() if hasattr(tx.get('data'), 'hex') else tx.get('data'),
                    'gas': hex(tx.get('gas')) if isinstance(tx.get('gas'), int) else str(tx.get('gas')),
                    'gasPrice': hex(tx.get('gasPrice')) if isinstance(tx.get('gasPrice'), int) else str(tx.get('gasPrice')),
                    # Remove nonce - let MetaMask calculate it automatically
                    'value': '0x0',
                    'chainId': '0x7a69'
                }
                print(f"🔍 META MASK TRANSACTION PARAMETERS:")
                print(f"   {json.dumps(metamask_transaction, indent=2)}")
                
                # CRITICAL: Verify the transaction data integrity
                print(f"🔍 CRITICAL: Transaction data integrity check:")
                print(f"   Original tx data type: {type(tx.get('data'))}")
                print(f"   Original tx data length: {len(tx.get('data')) if tx.get('data') else 0}")
                print(f"   MetaMask data type: {type(metamask_transaction['data'])}")
                print(f"   MetaMask data length: {len(metamask_transaction['data']) if metamask_transaction['data'] else 0}")
                
                # Verify the data conversion didn't lose information
                if tx.get('data'):
                    if hasattr(tx.get('data'), 'hex'):
                        original_hex = tx.get('data').hex()
                        metamask_hex = metamask_transaction['data']
                        print(f"   Data conversion check:")
                        print(f"      Original hex: {original_hex[:100]}...")
                        print(f"      MetaMask hex: {metamask_hex[:100]}...")
                        print(f"      Are they equal? {original_hex == metamask_hex}")
                    else:
                        print(f"   Data conversion check:")
                        print(f"      Original data (string): {tx.get('data')[:100]}...")
                        print(f"      MetaMask data: {metamask_transaction['data'][:100]}...")
                        print(f"      Are they equal? {tx.get('data') == metamask_transaction['data']}")
                
                # Return the unsigned transaction for MetaMask (MetaMask expects specific formats)
                result = {
                    'success': True,
                    'transaction': {
                        'to': tx.get('to'),
                        'data': tx.get('data').hex() if hasattr(tx.get('data'), 'hex') else tx.get('data'),
                        'gas': hex(tx.get('gas')) if isinstance(tx.get('gas'), int) else str(tx.get('gas')),
                        'gasPrice': hex(tx.get('gasPrice')) if isinstance(tx.get('gasPrice'), int) else str(tx.get('gasPrice')),
                        # Remove nonce - let MetaMask calculate it automatically
                        'value': '0x0',  # MetaMask expects hex string for value
                        'chainId': '0x7a69'  # MetaMask expects hex string for chainId
                    },
                    'gateway_address': gateway_address,
                    'note': 'Transaction built for MetaMask signing'
                }
                
                # Add compliance modules configuration for post-deployment if present
                if compliance_modules:
                    # Store the deployed module addresses with the config
                    compliance_modules_with_addresses = []
                    for i, module in enumerate(compliance_modules):
                        module_with_address = module.copy()
                        module_with_address['address'] = compliance_module_addresses[i]
                        compliance_modules_with_addresses.append(module_with_address)
                    
                    result['compliance_modules_config'] = compliance_modules_with_addresses
                    result['needs_post_deployment_config'] = True
                    result['note'] = 'Transaction built for MetaMask signing - compliance modules will be configured after deployment'
                
                return result
                
            except Exception as e:
                print(f"❌ Error building transaction: {e}")
                return {
                    'success': False,
                    'error': f'Failed to build transaction: {e}',
                    'note': 'Error occurred while building deployment transaction'
                }
                
        except Exception as e:
            print(f"❌ Token deployment transaction building failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Token deployment transaction building failed: {e}',
                'note': 'Exception occurred during transaction building process'
            }
    
    def post_deployment_mint_and_verify(self, token_address, deployer_address, total_supply):
        """
        Post-deployment steps: mint initial supply and verify token functionality
        
        Args:
            token_address (str): Deployed token address
            deployer_address (str): Token owner/deployer address
            total_supply (str): Total supply to mint
            
        Returns:
            dict: Success status and verification results
        """
        try:
            print(f"🔧 POST-DEPLOYMENT: Minting and verifying token {token_address}")
            print(f"   Deployer: {deployer_address}")
            print(f"   Total Supply: {total_supply}")
            
            # Step 1: Verify token is properly deployed
            print(f"\n📋 Step 1: Verifying token deployment...")
            token_info = self.get_token_info(token_address)
            if not token_info['success']:
                return {'success': False, 'error': f'Token verification failed: {token_info["error"]}'}
            
            print(f"✅ Token verified: {token_info['token_info']['name']} ({token_info['token_info']['symbol']})")
            
            # Step 2: Check if token responds to identityRegistry() calls
            print(f"\n📋 Step 2: Testing identityRegistry() call...")
            try:
                identity_registry = self.web3.call_contract_function(
                    'Token', 
                    token_address, 
                    'identityRegistry'
                )
                print(f"✅ identityRegistry() call successful: {identity_registry}")
            except Exception as e:
                print(f"❌ identityRegistry() call failed: {e}")
                return {'success': False, 'error': f'Token does not respond to identityRegistry() calls: {e}'}
            
            # Step 3: Check if token responds to compliance() calls
            print(f"\n📋 Step 3: Testing compliance() call...")
            try:
                compliance = self.web3.call_contract_function(
                    'Token', 
                    token_address, 
                    'compliance'
                )
                print(f"✅ compliance() call successful: {compliance}")
            except Exception as e:
                print(f"❌ compliance() call failed: {e}")
                return {'success': False, 'error': f'Token does not respond to compliance() calls: {e}'}
            
            # Step 4: Mint initial supply if total_supply > 0
            if int(total_supply) > 0:
                print(f"\n📋 Step 4: Minting initial supply...")
                try:
                    # Check if deployer is a token agent
                    is_agent = self.web3.call_contract_function(
                        'Token', 
                        token_address, 
                        'isAgent', 
                        deployer_address
                    )
                    
                    if not is_agent:
                        print(f"⚠️ Deployer is not a token agent, cannot mint")
                        return {
                            'success': False, 
                            'error': 'Deployer is not a token agent. Token deployed but cannot mint initial supply.',
                            'token_verified': True,
                            'identity_registry': identity_registry,
                            'compliance': compliance
                        }
                    
                    # Mint tokens to deployer
                    amount_wei = self.web3.parse_units(total_supply, 18)
                    tx_hash = self.web3.transact_contract_function(
                        'Token',
                        token_address,
                        'mint',
                        deployer_address,
                        amount_wei
                    )
                    
                    receipt = self.web3.wait_for_transaction(tx_hash)
                    
                    if receipt.status == 1:
                        print(f"✅ Successfully minted {total_supply} tokens to {deployer_address}")
                        
                        # Verify minting worked
                        balance = self.web3.call_contract_function(
                            'Token',
                            token_address,
                            'balanceOf',
                            deployer_address
                        )
                        balance_formatted = self.web3.format_units(balance, 18)
                        print(f"✅ Deployer balance after mint: {balance_formatted} tokens")
                        
                        return {
                            'success': True,
                            'token_verified': True,
                            'identity_registry': identity_registry,
                            'compliance': compliance,
                            'minted': True,
                            'mint_tx_hash': tx_hash.hex(),
                            'deployer_balance': balance_formatted
                        }
                    else:
                        print(f"❌ Minting transaction failed")
                        return {
                            'success': False,
                            'error': 'Minting transaction failed',
                            'token_verified': True,
                            'identity_registry': identity_registry,
                            'compliance': compliance
                        }
                        
                except Exception as e:
                    print(f"❌ Error during minting: {e}")
                    return {
                        'success': False,
                        'error': f'Minting failed: {e}',
                        'token_verified': True,
                        'identity_registry': identity_registry,
                        'compliance': compliance
                    }
            else:
                print(f"\n📋 Step 4: Skipping minting (total_supply = 0)")
                return {
                    'success': True,
                    'token_verified': True,
                    'identity_registry': identity_registry,
                    'compliance': compliance,
                    'minted': False,
                    'note': 'Token deployed with 0 total supply (minting skipped)'
                }
                
        except Exception as e:
            print(f"❌ Post-deployment verification failed: {e}")
            return {'success': False, 'error': f'Post-deployment verification failed: {e}'}

    def parse_deployment_events(self, transaction_hash, gateway_address, deployer_address=None):
        """
        Parse deployment events to get contract addresses using V1 approach
        Instead of parsing events, use direct contract calls like original TokenPlatform
        """
        try:
            print(f"🔍 V1 APPROACH: Using direct contract calls (like original TokenPlatform)...")
            
            # Get the Factory address from the database
            from models.contract import Contract
            factory_contract = Contract.query.filter_by(contract_type='TREXFactory').first()
            if not factory_contract:
                print(f"❌ TREXFactory not found in database")
                return None
            
            factory_address = factory_contract.contract_address
            print(f"🔍 Using Factory address: {factory_address}")
            
            # Get the Gateway address from the database
            gateway_contract = Contract.query.filter_by(contract_type='TREXGateway').first()
            if not gateway_contract:
                print(f"❌ TREXGateway not found in database")
                return None
            
            gateway_address_db = gateway_contract.contract_address
            print(f"🔍 Gateway address from DB: {gateway_address_db}")
            
            # Verify that the Gateway owns the Factory
            try:
                # Try to get the Factory ABI - handle missing method gracefully
                try:
                    factory_abi = self.web3.get_contract_abi('TREXFactory')
                except AttributeError:
                    print(f"⚠️ Web3Service missing get_contract_abi method, using fallback...")
                    # Fallback: try to get ABI from contract_abis if available
                    if hasattr(self.web3, 'contract_abis') and 'TREXFactory' in self.web3.contract_abis:
                        factory_abi = self.web3.contract_abis['TREXFactory']
                    else:
                        print(f"⚠️ No Factory ABI available, skipping ownership check")
                        factory_abi = None
                
                if factory_abi:
                    factory_contract_instance = self.w3.eth.contract(
                        address=factory_address, 
                        abi=factory_abi
                    )
                    factory_owner = factory_contract_instance.functions.owner().call()
                    print(f"🔍 Factory owner: {factory_owner}")
                    print(f"🔍 Gateway address: {gateway_address_db}")
                    if factory_owner.lower() != gateway_address_db.lower():
                        print(f"⚠️ WARNING: Factory is NOT owned by Gateway!")
                        print(f"   Factory owner: {factory_owner}")
                        print(f"   Gateway: {gateway_address_db}")
                    else:
                        print(f"✅ Factory is correctly owned by Gateway")
                else:
                    print(f"⚠️ Could not verify Factory ownership - no ABI available")
                    
            except Exception as e:
                print(f"⚠️ Could not verify Factory ownership: {e}")
                print(f"   Continuing with deployment address extraction...")
            
            # ROBUST EVENT-DRIVEN INDEXING: Gateway-first with Factory fallback
            # This is the most reliable way to index deployments
            
            print(f"\n🔍 ROBUST EVENT-DRIVEN INDEXING: Gateway-first with Factory fallback...")
            
            # Get the transaction receipt
            receipt = self.w3.eth.get_transaction_receipt(transaction_hash)
            if receipt.status != 1:
                print(f"❌ Transaction failed, cannot get addresses")
                return None
                
            # Step 1: Try to parse TREXSuiteDeployed from Gateway (primary source)
            print(f"🔍 Step 1: Parsing Gateway deployment events...")
            gateway_addresses = [gateway_address_db]  # Primary: the Gateway we used
            
            # Add Factory as fallback (some versions only emit there)
            if factory_address:
                gateway_addresses.append(factory_address)
                print(f"🔍 Added Factory as fallback: {factory_address}")
            
            # DEBUG: Show all logs to see what we're actually getting
            print(f"🔍 DEBUG: Transaction has {len(receipt.logs)} logs")
            print(f"🔍 DEBUG: Looking for TREXSuiteDeployed event...")
            
            # Define event signatures to try - using ACTUAL events from ABIs
            event_signatures = [
                # Gateway events (from TREXGateway.json)
                "GatewaySuiteDeploymentProcessed(address,address,uint256)",
                
                # Check those interesting topic hashes we saw multiple times in logs
                # 0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41
                # 0x3ddb07c2df247d32c71cd94e46f101dd4a4bcd5ce07afc925673aa63ba24960e
                
                # Fallback to generic names (in case ABIs are incomplete)
                "TREXSuiteDeployed(address,bytes32,address,address,address,address,address)",
                "TREXSuiteDeployed(address,address,address,address,address,address)",
                "SuiteDeployed(address,address,address,address,address,address)",
                "DeploymentCompleted(address,address,address,address,address,address)"
            ]
            
            deployed_addresses = None
            
            # Also check those specific topic hashes we saw multiple times in logs
            interesting_topics = [
                "0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41",
                "0x3ddb07c2df247d32c71cd94e46f101dd4a4bcd5ce07afc925673aa63ba24960e"
            ]
            
            for gateway_address in gateway_addresses:
                print(f"🔍 Checking {gateway_address} for deployment events...")
                
                # Try the event signatures
                try:
                    for event_sig in event_signatures:
                        try:
                            topic0 = self.w3.keccak(text=event_sig).hex()
                            
                            for log in receipt.logs:
                                if log.topics and len(log.topics) > 0:
                                    log_topic0 = log.topics[0].hex()
                                    
                                    if log_topic0 == topic0:
                                        print(f"✅ Found matching event on {gateway_address}!")
                                        print(f"   Event signature: {event_sig}")
                                        print(f"   Log address: {log.address}")
                                        print(f"   Log topics: {[t.hex() for t in log.topics]}")
                                        print(f"   Log data length: {len(log.data)}")
                                        
                                        # Parse the event data using web3.py's event decoder
                                        try:
                                            from web3._utils.events import get_event_data
                                            
                                            # Define the event structure based on signature
                                            if "GatewaySuiteDeploymentProcessed" in event_sig:
                                                # Actual Gateway event from ABI
                                                GATEWAY_EVENT = {
                                                    "anonymous": False,
                                                    "inputs": [
                                                        {"indexed": True, "internalType": "address", "name": "requester", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "intendedOwner", "type": "address"},
                                                        {"indexed": False, "internalType": "uint256", "name": "feeApplied", "type": "uint256"},
                                                    ],
                                                    "name": "GatewaySuiteDeploymentProcessed",
                                                    "type": "event"
                                                }
                                            
                                                # Decode the Gateway event
                                                decoded_event = get_event_data(self.w3.codec, GATEWAY_EVENT, log)
                                                args = decoded_event["args"]
                                                
                                                print(f"✅ Gateway event decoded successfully!")
                                                print(f"   Requester: {args['requester']}")
                                                print(f"   Intended Owner: {args['intendedOwner']}")
                                                print(f"   Fee Applied: {args['feeApplied']}")
                                                
                                                # For Gateway events, we need to extract addresses from log data
                                                # This event doesn't contain the deployed addresses directly
                                                print(f"🔄 Gateway event found, but need to extract addresses from log data...")
                                                
                                                # Try manual parsing of the log data
                                                deployed_addresses = self._parse_deployment_event_log_fallback([log], deployer_address)
                                                if deployed_addresses:
                                                    deployed_addresses['source'] = f'gateway_{gateway_address}_gateway_event'
                                                    deployed_addresses['method_used'] = 'gateway_event_parsing'
                                                    deployed_addresses['event_signature'] = event_sig
                                                    deployed_addresses['gateway_requester'] = args['requester']
                                                    deployed_addresses['gateway_intended_owner'] = args['intendedOwner']
                                                    deployed_addresses['gateway_fee_applied'] = args['feeApplied']
                                                
                                                break
                                            
                                            elif "bytes32" in event_sig:
                                                # Full signature with salt
                                                TREX_SUITE_DEPLOYED = {
                                                    "anonymous": False,
                                                    "inputs": [
                                                        {"indexed": True, "internalType": "address", "name": "factory", "type": "address"},
                                                        {"indexed": True, "internalType": "bytes32", "name": "salt", "type": "bytes32"},
                                                        {"indexed": False, "internalType": "address", "name": "token", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "identityRegistry", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "compliance", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "claimTopicsRegistry", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "trustedIssuersRegistry", "type": "address"},
                                                    ],
                                                    "name": "TREXSuiteDeployed",
                                                    "type": "event"
                                                }
                                            else:
                                                # Simplified signature without salt
                                                TREX_SUITE_DEPLOYED = {
                                                    "anonymous": False,
                                                    "inputs": [
                                                        {"indexed": False, "internalType": "address", "name": "token", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "identityRegistry", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "compliance", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "claimTopicsRegistry", "type": "address"},
                                                        {"indexed": False, "internalType": "address", "name": "trustedIssuersRegistry", "type": "address"},
                                                    ],
                                                    "name": "TREXSuiteDeployed",
                                                    "type": "event"
                                                }
                                        
                                            # Decode the event
                                            decoded_event = get_event_data(self.w3.codec, TREX_SUITE_DEPLOYED, log)
                                            args = decoded_event["args"]
                                            
                                            print(f"✅ Event decoded successfully!")
                                            if "factory" in args:
                                                print(f"   Factory: {args['factory']}")
                                                print(f"   Salt: {args['salt'].hex()}")
                                            print(f"   Token: {args['token']}")
                                            print(f"   Identity Registry: {args['identityRegistry']}")
                                            print(f"   Compliance: {args['compliance']}")
                                            print(f"   Claim Topics Registry: {args['claimTopicsRegistry']}")
                                            print(f"   Trusted Issuers Registry: {args['trustedIssuersRegistry']}")
                                            
                                            deployed_addresses = {
                                                'token_address': args['token'],
                                                'identity_registry': args['identityRegistry'],
                                                'compliance': args['compliance'],
                                                'claim_topics_registry': args['claimTopicsRegistry'],
                                                'trusted_issuers_registry': args['trustedIssuersRegistry'],
                                                'source': f'gateway_{gateway_address}',
                                                'method_used': 'gateway_event_parsing',
                                                'event_signature': event_sig
                                            }
                                            
                                            if "factory" in args:
                                                deployed_addresses.update({
                                                    'factory': args['factory'],
                                                    'salt': args['salt'].hex()
                                                })
                                            
                                            break
                                        
                                        except Exception as e:
                                            print(f"❌ Error decoding event: {e}")
                                            print(f"🔄 Falling back to manual parsing...")
                                            
                                            # Fallback: manual parsing if web3.py decoder fails
                                            deployed_addresses = self._parse_deployment_event_log_fallback([log], deployer_address)
                                            if deployed_addresses:
                                                deployed_addresses['source'] = f'gateway_{gateway_address}_manual'
                                                deployed_addresses['method_used'] = 'gateway_event_manual_fallback'
                                                deployed_addresses['event_signature'] = event_sig
                                            
                                            break
                                        
                        except Exception as e:
                            print(f"⚠️ Error with event signature {event_sig}: {e}")
                            continue
                    
                    if deployed_addresses:
                        break
                        
                except Exception as e:
                    print(f"⚠️ Error checking {gateway_address}: {e}")
                    continue
            
            # Step 1.5: If Gateway events didn't work, try Factory events directly
            if not deployed_addresses:
                print(f"🔍 Step 1.5: Gateway events didn't work, trying Factory events directly...")
                
                # Get Factory address from database
                try:
                    from models import Contract
                    factory_contract = Contract.query.filter_by(contract_type='TREXFactory').first()
                    if factory_contract:
                        factory_address = factory_contract.contract_address
                        print(f"🔍 Checking Factory {factory_address} for TREXSuiteDeployed event...")
                        
                        # Look for TREXSuiteDeployed event in Factory logs
                        trex_suite_deployed_topic = "0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41"
                        
                        for log in receipt.logs:
                            if (log.address.lower() == factory_address.lower() and 
                                log.topics and log.topics[0].hex() == trex_suite_deployed_topic):
                                print(f"✅ Found TREXSuiteDeployed event in Factory logs!")
                                print(f"   Log address: {log.address}")
                                print(f"   Log topics: {[t.hex() for t in log.topics]}")
                                print(f"   Log data length: {len(log.data)}")
                                
                                # Parse the Factory event
                                deployed_addresses = self._parse_deployment_event_log(log, deployer_address)
                                if deployed_addresses:
                                    deployed_addresses['source'] = f'factory_{factory_address}'
                                    deployed_addresses['method_used'] = 'factory_event_direct'
                                    deployed_addresses['event_signature'] = 'TREXSuiteDeployed'
                                    break
                        
                        if not deployed_addresses:
                            print(f"❌ No TREXSuiteDeployed event found in Factory logs")
                    else:
                        print(f"❌ Factory contract not found in database")
                        
                except Exception as e:
                    print(f"❌ Error checking Factory events: {e}")
            
            # Step 2: Enrich with on-chain reads (defensive checks)
            if deployed_addresses:
                print(f"\n🔍 Step 2: Enriching with on-chain reads and defensive checks...")
                
                try:
                    # Get Token contract and verify it's actually a T-REX Token
                    token_address = deployed_addresses['token_address']
                    token_contract = self.w3.eth.contract(
                        address=token_address,
                        abi=self.web3.get_contract_abi('Token')
                    )
                    
                    print(f"🔧 Verifying Token contract...")
                    token_name = token_contract.functions.name().call()
                    token_symbol = token_contract.functions.symbol().call()
                    token_decimals = token_contract.functions.decimals().call()
                    token_owner = token_contract.functions.owner().call()
                    
                    print(f"✅ Token verified: {token_name} ({token_symbol}) - {token_decimals} decimals")
                    print(f"   Owner: {token_owner}")
                    
                    # Verify the addresses match what we got from events
                    token_ir = token_contract.functions.identityRegistry().call()
                    token_compliance = token_contract.functions.compliance().call()
                    
                    if (token_ir.lower() == deployed_addresses['identity_registry'].lower() and
                        token_compliance.lower() == deployed_addresses['compliance'].lower()):
                        print(f"✅ Token addresses match event data!")
                    else:
                        print(f"⚠️ WARNING: Token addresses don't match event data!")
                        print(f"   Event IR: {deployed_addresses['identity_registry']}")
                        print(f"   Token IR: {token_ir}")
                        print(f"   Event Compliance: {deployed_addresses['compliance']}")
                        print(f"   Token Compliance: {token_compliance}")
                    
                    # Get Identity Registry contract and verify
                    ir_address = deployed_addresses['identity_registry']
                    ir_contract = self.w3.eth.contract(
                        address=ir_address,
                        abi=self.web3.get_contract_abi('IdentityRegistry')
                    )
                    
                    print(f"🔧 Verifying Identity Registry contract...")
                    ir_owner = ir_contract.functions.owner().call()
                    ir_ctr = ir_contract.functions.topicsRegistry().call()
                    ir_tir = ir_contract.functions.issuersRegistry().call()
                    
                    print(f"✅ IR verified - Owner: {ir_owner}")
                    print(f"   CTR: {ir_ctr}")
                    print(f"   TIR: {ir_tir}")
                    
                    # Verify IR addresses match event data
                    if (ir_ctr.lower() == deployed_addresses['claim_topics_registry'].lower() and
                        ir_tir.lower() == deployed_addresses['trusted_issuers_registry'].lower()):
                        print(f"✅ IR addresses match event data!")
                    else:
                        print(f"⚠️ WARNING: IR addresses don't match event data!")
                    
                    # Defensive checks: verify issuer permissions
                    print(f"🔧 Defensive checks: verifying issuer permissions...")
                    issuer_is_token_agent = token_contract.functions.isAgent(deployer_address).call()
                    issuer_is_ir_agent = ir_contract.functions.isAgent(deployer_address).call()
                    
                    print(f"   Issuer is Token Agent: {issuer_is_token_agent}")
                    print(f"   Issuer is IR Agent: {issuer_is_ir_agent}")
                    
                    if issuer_is_token_agent and issuer_is_ir_agent:
                        print(f"✅ All permissions correctly set!")
                    else:
                        print(f"⚠️ WARNING: Some permissions not set correctly!")
                        print(f"   This may indicate a deployment configuration issue")
                    
                    # Add enriched data to results
                    deployed_addresses.update({
                        'token_name': token_name,
                        'token_symbol': token_symbol,
                        'token_decimals': token_decimals,
                        'token_owner': token_owner,
                        'ir_owner': ir_owner,
                        'issuer_is_token_agent': issuer_is_token_agent,
                        'issuer_is_ir_agent': issuer_is_ir_agent,
                        'verification_passed': True
                    })
                    
                except Exception as e:
                    print(f"❌ Error during enrichment: {e}")
                    print(f"   Addresses from events may be incorrect")
                    deployed_addresses['verification_passed'] = False
                    deployed_addresses['verification_error'] = str(e)
            
            # Show final results
            if deployed_addresses:
                print(f"\n✅ SUCCESS: Addresses retrieved and verified!")
                print(f"   Token: {deployed_addresses.get('token_address', 'N/A')}")
                print(f"   Identity Registry: {deployed_addresses.get('identity_registry', 'N/A')}")
                print(f"   Compliance: {deployed_addresses.get('compliance', 'N/A')}")
                print(f"   Claim Topics Registry: {deployed_addresses.get('claim_topics_registry', 'N/A')}")
                print(f"   Trusted Issuers Registry: {deployed_addresses.get('trusted_issuers_registry', 'N/A')}")
                print(f"🎯 METHOD: {deployed_addresses.get('method_used', 'unknown')}")
                print(f"📡 SOURCE: {deployed_addresses.get('source', 'unknown')}")
                print(f"✅ VERIFICATION: {'PASSED' if deployed_addresses.get('verification_passed', False) else 'FAILED'}")
            else:
                print(f"❌ Could not get addresses using any method")
            
            return deployed_addresses
            
        except Exception as e:
            print(f"❌ Error in V1 approach: {e}")
            return None

    def _parse_deployment_event_log_fallback(self, logs, deployer_address=None):
        """Fallback method for event parsing if direct calls fail"""
        try:
            print(f"🔍 Fallback: Parsing deployment event logs...")
            
            # Look for TREXSuiteDeployed event
            deployment_event_topic = "0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41"
            
            for log in logs:
                if log.topics and len(log.topics) > 0 and log.topics[0].hex() == deployment_event_topic:
                    print(f"✅ Found TREXSuiteDeployed event in logs!")
                    return self._parse_deployment_event_log(log, deployer_address)
            
            print(f"❌ No TREXSuiteDeployed event found in logs")
            return None
            
        except Exception as e:
            print(f"❌ Fallback event parsing failed: {e}")
            return None

    def _parse_deployment_event_log(self, log, deployer_address=None):
        """Parse a single TREXSuiteDeployed event log"""
        try:
            print(f"🔍 Parsing deployment event log:")
            print(f"   Topics: {[t.hex() for t in log.topics]}")
            print(f"   Data length: {len(log.data)}")
            print(f"   Event data: {log.data.hex()}")
            
            # CORRECTED: TREXSuiteDeployed event structure:
            # - Token address is in Topic 1 (indexed)
            # - Data field contains: [IR, IRS, TIR, CTR, MC] in that order
            # - Each address is 32 bytes (padded to 32 bytes)
            
            # Extract token address from Topic 1 (indexed field)
            if len(log.topics) < 2:
                print(f"❌ Not enough topics in event log")
                return None
                
            token_address = self.w3.to_checksum_address(log.topics[1][-20:])
            print(f"🔍 Token address from Topic 1: {token_address}")
            
            # Extract addresses from data field (5 addresses: IR, IRS, TIR, CTR, MC)
            data = log.data
            if len(data) < 160:  # 5 addresses * 32 bytes each
                print(f"❌ Not enough data in event log: {len(data)} bytes")
                return None
            
            # Extract addresses from data field in correct order
            data_addresses = []
            for i in range(0, 160, 32):  # Only first 5 addresses (160 bytes)
                address_bytes = data[i:i+32]
                address = self.w3.to_checksum_address(address_bytes[-20:])
                data_addresses.append(address)
            
            print(f"🔍 Data addresses: {data_addresses}")
            
            # Map addresses correctly based on our testing
            if len(data_addresses) >= 5:
                return {
                    'token_address': token_address,  # From Topic 1
                    'identity_registry': data_addresses[0],  # IR (first in data)
                    'identity_registry_storage': data_addresses[1],  # IRS (second in data)
                    'trusted_issuers_registry': data_addresses[2],  # TIR (third in data)
                    'claim_topics_registry': data_addresses[3],  # CTR (fourth in data)
                    'compliance': data_addresses[4],  # MC (fifth in data)
                    'direct_calls_used': False,
                    'method_used': 'event_parsing_corrected'
                }
            else:
                print(f"⚠️ Not enough addresses extracted from data: {len(data_addresses)}")
                return None
            
        except Exception as e:
            print(f"❌ Error parsing deployment event log: {e}")
            return None