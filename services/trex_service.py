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
            
            # Map claim topics to human-readable names
            claim_topic_names = {
                1: 'KYC Status',
                2: 'Nationality',
                3: 'Residency',
                4: 'Accreditation',
                7: 'Compliance Status',
                8: 'Transfer Restrictions'
            }
            
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
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for transaction
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                # Get the created identity address
                onchain_id_address = identity_factory.functions.getIdentity(wallet_address).call()
                
                # Index the initial management key (Account 0)
                try:
                    from services.transaction_indexer import TransactionIndexer
                    transaction_indexer = TransactionIndexer(self.web3_service)
                    
                    # Account 0 (deployer) is the initial management key
                    transaction_indexer.index_onchainid_key(
                        onchainid_address=onchain_id_address,
                        wallet_address=deployer_address,  # Account 0
                        key_hash=self.w3.keccak(self.w3.codec.encode(['address'], [deployer_address])).hex(),
                        key_type='management',
                        owner_type='admin'  # Account 0 is admin
                    )
                    
                    print(f"✅ Indexed initial management key: {deployer_address} -> {onchain_id_address}")
                except Exception as e:
                    print(f"⚠️ Error indexing initial management key: {e}")
                
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
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
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