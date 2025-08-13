from services.web3_service import Web3Service
from eth_account import Account
import json
from pathlib import Path
import os

class TREXService:
    """Service for TREX (ERC-3643) specific operations"""
    
    def __init__(self, web3_service: Web3Service):
        self.web3 = web3_service
        self.w3 = web3_service.w3
        
        # Load contract addresses from environment or use defaults
        self.factory_address = os.environ.get('TREX_FACTORY_ADDRESS')
        self.identity_registry_address = os.environ.get('IDENTITY_REGISTRY_ADDRESS')
        self.claim_topics_registry_address = os.environ.get('CLAIM_TOPICS_REGISTRY_ADDRESS')
        self.trusted_issuers_registry_address = os.environ.get('TRUSTED_ISSUERS_REGISTRY_ADDRESS')
        
        # Get contract instances
        if self.factory_address:
            self.factory_contract = self.web3.get_contract('TREXFactory', self.factory_address)
        
        if self.identity_registry_address:
            self.identity_registry_contract = self.web3.get_contract('IdentityRegistry', self.identity_registry_address)
        
        if self.claim_topics_registry_address:
            self.claim_topics_registry_contract = self.web3.get_contract('ClaimTopicsRegistry', self.claim_topics_registry_address)
        
        if self.trusted_issuers_registry_address:
            self.trusted_issuers_registry_contract = self.web3.get_contract('TrustedIssuersRegistry', self.trusted_issuers_registry_address)
    
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
                'irAgents': [issuer_address] if ir_agent == 'issuer' else [self.web3.default_account]
            })
            
            # Determine claim issuer address
            if claim_issuer_type == 'trusted_issuer' and claim_issuer_id:
                from models.user import User
                trusted_issuer = User.query.get(claim_issuer_id)
                if not trusted_issuer:
                    return {'success': False, 'error': 'Trusted issuer not found'}
                claim_issuer_address = trusted_issuer.claim_issuer_address
            elif claim_issuer_type == 'issuer':
                claim_issuer_address = issuer_address
            else: # admin
                claim_issuer_address = self.web3.default_account
            
            # Set claim details directly - proper T-REX structure
            # issuerClaims should be an array of arrays, where each inner array contains the topics for that issuer
            claim_topics_int = [int(topic) for topic in claim_topics]
            deployment.claim_details = {
                'claimTopics': claim_topics_int,
                'issuers': [claim_issuer_address],
                'issuerClaims': [claim_topics_int]  # Array of arrays - each issuer gets all topics
            }
            
            print(f"🔧 Claim Details Structure:")
            print(f"   claimTopics: {deployment.claim_details['claimTopics']}")
            print(f"   issuers: {deployment.claim_details['issuers']}")
            print(f"   issuerClaims: {deployment.claim_details['issuerClaims']}")
            
            # Deploy the token
            deployment_result = deployment.deploy(deployer_address=issuer_address)
            
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
            onchain_id_address = self.web3.call_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'identity',
                user_address
            )
            
            if onchain_id_address == '0x0000000000000000000000000000000000000000':
                return {
                    'success': True, 
                    'verified': False, 
                    'reason': 'User has no OnchainID registered'
                }
            
            # Check if user is verified using Identity Registry's isVerified() method
            is_verified = self.web3.call_contract_function(
                'IdentityRegistry',
                identity_registry_address,
                'isVerified',
                user_address
            )
            
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
        """Mint tokens to a specific address"""
        try:
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Mint tokens to the specified address
            tx_hash = self.web3.transact_contract_function(
                'Token',
                token_address,
                'mint',
                to_address,
                amount_wei
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def burn_tokens(self, token_address, from_address, amount):
        """Burn tokens from a specific address"""
        try:
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Burn tokens from the specified address
            tx_hash = self.web3.transact_contract_function(
                'Token',
                token_address,
                'burn',
                from_address,
                amount_wei
            )
            
            receipt = self.web3.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                return {'success': True, 'tx_hash': tx_hash}
            else:
                return {'success': False, 'error': 'Transaction failed'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def force_transfer(self, token_address, from_address, to_address, amount):
        """Force transfer tokens from one address to another"""
        try:
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Force transfer tokens
            tx_hash = self.web3.transact_contract_function(
                'Token',
                token_address,
                'forceTransfer',
                from_address,
                to_address,
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
            # Parse amount to wei
            amount_wei = self.web3.parse_units(amount, 18)
            
            # Force transfer tokens from one address to another
            tx_hash = self.web3.transact_contract_function(
                'Token',
                token_address,
                'forcedTransfer',
                from_address,
                to_address,
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
            # Basic token info
            token_info = {
                'name': self.web3.call_contract_function('Token', token_address, 'name'),
                'symbol': self.web3.call_contract_function('Token', token_address, 'symbol'),
                'decimals': self.web3.call_contract_function('Token', token_address, 'decimals'),
                'totalSupply': self.web3.call_contract_function('Token', token_address, 'totalSupply'),
                'owner': self.web3.call_contract_function('Token', token_address, 'owner')
            }
            
            # Format total supply
            token_info['totalSupplyFormatted'] = self.web3.format_units(token_info['totalSupply'], token_info['decimals'])
            
            # Get compliance info
            try:
                compliance_address = self.web3.call_contract_function('Token', token_address, 'compliance')
                token_info['compliance_address'] = compliance_address
                
                # Get claim topics from compliance
                claim_topics = self.web3.call_contract_function('Compliance', compliance_address, 'getClaimTopics')
                token_info['claim_topics'] = claim_topics
            except:
                token_info['compliance_address'] = None
                token_info['claim_topics'] = []
            
            # Get identity registry info
            try:
                identity_registry = self.web3.call_contract_function('Token', token_address, 'identityRegistry')
                token_info['identity_registry'] = identity_registry
            except:
                token_info['identity_registry'] = None
            
            return {'success': True, 'token_info': token_info}
            
        except Exception as e:
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
            identity_factory = self.web3.get_contract('Factory', identity_factory_address)
            
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
            identity_factory = self.web3.get_contract('Factory', identity_factory_address)
            
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
                deployer_key_hash = self.w3.keccak(
                    self.w3.codec.encode(['address'], [deployer_address])
                )
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
                    deployer_key_hash = self.w3.keccak(
                        self.w3.codec.encode(['address'], [deployer_address])
                    ).hex()
                    
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
            print(f"🔍 Getting token transactions for: {token_address}")
            
            # Get token contract
            token_contract = self.w3.eth.contract(
                address=token_address,
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
                    
                except Exception as e:
                    print(f"⚠️ Error processing transaction {event['transactionHash'].hex()}: {e}")
                    continue
            
            # Sort by timestamp (newest first)
            transactions.sort(key=lambda x: x['timestamp'], reverse=True)
            
            print(f"✅ Returned {len(transactions)} token transactions")
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
            print(f"🔗 Adding trusted issuer {trusted_issuer_address} to token {token_address}")
            print(f"   Claim topics: {claim_topics}")
            
            # Get the token's Identity Registry contract
            # First, we need to get the Identity Registry address from the token
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
                trusted_issuer_address,
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
            print(f"🔗 Adding agent {agent_address} as {agent_type} to token {token_address}")
            
            # Get the token contract
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
            print(f"🔗 Removing agent {agent_address} as {agent_type} from token {token_address}")
            
            # Get the token contract
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