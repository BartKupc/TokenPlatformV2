"""
Transaction Indexer Service
Handles enhanced transaction indexing and OnchainID management
"""

from models import db
from models.enhanced_models import TokenTransactionEnhanced, TokenBalanceSnapshot, OnchainIDKey
from models.user import User
from models.token import Token
from services.web3_service import Web3Service
from services.trex_service import TREXService
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)

class TransactionIndexer:
    """Service for indexing blockchain transactions and managing OnchainID keys"""
    
    def __init__(self, web3_service: Web3Service = None):
        self.web3_service = web3_service or Web3Service()
        self.trex_service = TREXService(self.web3_service)
        self._last_deployment_result = None
    
    def index_token_transaction(self, token_id, transaction_type, from_address=None, to_address=None, 
                               amount=None, transaction_hash=None, executed_by_user_id=None, 
                               executed_by_address=None, purchase_request_id=None, notes=None, 
                               deployment_data=None):
        """Index a token transaction in the database"""
        try:
            # Special handling for deployment transactions
            if transaction_type == 'deploy' and deployment_data:
                return self._handle_deployment_transaction(
                    deployment_data, transaction_hash, executed_by_user_id, executed_by_address, notes
                )
            
            # Regular transaction indexing
            # Get token for symbol
            token = Token.query.get(token_id)
            if not token:
                logger.error(f"Token {token_id} not found")
                return False
            
            # Format amount if provided
            amount_formatted = None
            if amount is not None:
                try:
                    amount_formatted = Decimal(amount) / Decimal(10**18)
                except:
                    amount_formatted = Decimal(amount)
            
            # Create enhanced transaction record
            transaction = TokenTransactionEnhanced(
                token_id=token_id,
                transaction_type=transaction_type,
                from_address=from_address,
                to_address=to_address,
                amount=amount or 0,
                amount_formatted=amount_formatted,
                transaction_hash=transaction_hash,
                executed_by=executed_by_user_id,
                executed_by_address=executed_by_address,
                purchase_request_id=purchase_request_id,
                notes=notes
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            logger.info(f"Indexed transaction: {transaction_type} {amount_formatted} {token.symbol}")
            return True
            
        except Exception as e:
            logger.error(f"Error indexing transaction: {e}")
            db.session.rollback()
            return False
    
    def create_balance_snapshot(self, token_id, wallet_address, snapshot_type='manual', transaction_id=None):
        """Create a balance snapshot for verification"""
        try:
            # Get current balance from blockchain
            balance_wei = self.web3_service.call_contract_function(
                'Token', 
                Token.query.get(token_id).token_address, 
                'balanceOf', 
                wallet_address
            )
            
            # Format balance
            balance_formatted = Decimal(balance_wei) / Decimal(10**18)
            
            # Create snapshot
            snapshot = TokenBalanceSnapshot(
                token_id=token_id,
                wallet_address=wallet_address,
                balance_wei=balance_wei,
                balance_formatted=balance_formatted,
                snapshot_type=snapshot_type,
                transaction_id=transaction_id
            )
            
            db.session.add(snapshot)
            db.session.commit()
            
            logger.info(f"Created balance snapshot: {wallet_address} {balance_formatted}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating balance snapshot: {e}")
            db.session.rollback()
            return False
    
    def _handle_deployment_transaction(self, deployment_data, transaction_hash, executed_by_user_id, executed_by_address, notes):
        """Handle deployment transaction by parsing events and creating token record"""
        try:
            print(f"🔍 DEBUG: _handle_deployment_transaction called with:")
            print(f"   deployment_data: {deployment_data}")
            print(f"   transaction_hash: {transaction_hash}")
            print(f"   executed_by_user_id: {executed_by_user_id}")
            print(f"   executed_by_address: {executed_by_address}")
            print(f"   notes: {notes}")
            print(f"   deployment_data type: {type(deployment_data)}")
            print(f"   transaction_hash type: {type(transaction_hash)}")
            
            # Parse deployment events to get real contract addresses
            gateway_address = deployment_data.get('gateway_address')
            if not gateway_address:
                logger.error("Gateway address not found in deployment data")
                return False
            
            print(f"🔍 CRITICAL: TransactionIndexer handling deployment:")
            print(f"   transaction_hash: {transaction_hash}")
            print(f"   gateway_address: {gateway_address}")
            print(f"   deployment_data: {deployment_data}")
            print(f"   executed_by_address: {executed_by_address}")
            print(f"   issuer_address from deployment_data: {deployment_data.get('issuer_address')}")
            
            # Use TREXService to parse deployment events
            print(f"🔍 DEBUG: Calling trex_service.parse_deployment_events...")
            event_result = self.trex_service.parse_deployment_events(
                transaction_hash, 
                gateway_address, 
                deployer_address=executed_by_address
            )
            print(f"🔍 DEBUG: parse_deployment_events returned:")
            print(f"   event_result: {event_result}")
            print(f"   event_result type: {type(event_result)}")
            print(f"   event_result keys: {event_result.keys() if isinstance(event_result, dict) else 'Not a dict'}")
            
            if not event_result.get('verification_passed'):
                logger.error(f"Failed to parse deployment events: {event_result.get('error', 'Unknown error')}")
                return False
                
            # Extract contract addresses from parsed events
            contract_addresses = event_result
            
            # Create token record in database with REAL addresses
            import json
            
            # Set initial agents to the issuer's wallet address
            issuer_address = deployment_data['issuer_address']
            ir_agent = issuer_address
            token_agent = issuer_address
            
            # Create token with real contract addresses
            print(f"🔍 CRITICAL: Creating token in database:")
            print(f"   token_address: {contract_addresses['token_address']}")
            print(f"   issuer_address: {issuer_address}")
            print(f"   ir_agent: {ir_agent}")
            print(f"   token_agent: {token_agent}")
            print(f"   identity_registry_address: {contract_addresses['identity_registry']}")
            print(f"   identity_registry_storage: {contract_addresses.get('identity_registry_storage', 'N/A')}")
            
            token = Token(
                token_address=contract_addresses['token_address'],
                name=deployment_data['token_name'],
                symbol=deployment_data['token_symbol'],
                total_supply=int(deployment_data['total_supply']),
                issuer_address=issuer_address,
                description=deployment_data['description'],
                price_per_token=float(deployment_data['price_per_token']) if deployment_data['price_per_token'] else 1.00,
                ir_agent=ir_agent,
                token_agent=token_agent,
                claim_topics=','.join(map(str, deployment_data['claim_topics'])),
                claim_issuer_id=deployment_data['claim_issuer_id'],
                claim_issuer_type='trusted_issuer',
                # Use REAL addresses from parsed events (corrected mapping)
                identity_registry_address=contract_addresses['identity_registry'],
                compliance_address=contract_addresses['compliance'],
                claim_topics_registry_address=contract_addresses['claim_topics_registry'],
                trusted_issuers_registry_address=contract_addresses['trusted_issuers_registry'],
                agents=json.dumps({
                    'identity_agents': [ir_agent],
                    'token_agents': [token_agent],
                    'compliance_agents': [],
                    # Store IRS address in agents metadata for reference
                    'identity_registry_storage': contract_addresses.get('identity_registry_storage')
                })
            )
            
            db.session.add(token)
            db.session.commit()
            
            print(f"✅ Token created successfully in database:")
            print(f"   Token ID: {token.id}")
            print(f"   Token address: {token.token_address}")
            print(f"   IR agent: {token.ir_agent}")
            print(f"   Token agent: {token.token_agent}")
            print(f"   Identity Registry: {token.identity_registry_address}")
            
            # Store deployment result for retrieval
            self._last_deployment_result = {
                'token_id': token.id,
                'contract_addresses': contract_addresses
            }
            
            # Create enhanced transaction record for deployment
            transaction = TokenTransactionEnhanced(
                token_id=token.id,
                transaction_type='deploy',
                from_address=executed_by_address,  # Issuer deploying
                to_address=None,  # No recipient for deployment
                amount=0,  # Set to 0 for deployment (no token transfer)
                amount_formatted=Decimal(0),
                transaction_hash=transaction_hash,
                executed_by=executed_by_user_id,
                executed_by_address=executed_by_address,
                notes=notes
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            logger.info(f"Successfully deployed token: {token.symbol} with address: {token.token_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling deployment transaction: {e}")
            db.session.rollback()
            return False
    
    def get_last_deployment_result(self):
        """Get the result of the last deployment transaction"""
        return getattr(self, '_last_deployment_result', None)
    
    def index_onchainid_key(self, onchainid_address, wallet_address, key_hash, key_type, 
                           owner_type, owner_id=None):
        """Index an OnchainID key with owner information"""
        try:
            # Check if key already exists
            existing = OnchainIDKey.query.filter_by(
                onchainid_address=onchainid_address,
                wallet_address=wallet_address,
                key_type=key_type
            ).first()
            
            if existing:
                # Update existing record
                existing.owner_type = owner_type
                existing.owner_id = owner_id
                db.session.commit()
                logger.info(f"Updated OnchainID key: {wallet_address} -> {onchainid_address}")
            else:
                # Create new record
                key = OnchainIDKey(
                    onchainid_address=onchainid_address,
                    wallet_address=wallet_address,
                    key_hash=key_hash,
                    key_type=key_type,
                    role='Synced Key',  # Add default role for synced keys
                    owner_type=owner_type,
                    owner_id=owner_id
                )
                db.session.add(key)
                db.session.commit()
                logger.info(f"Indexed OnchainID key: {wallet_address} -> {onchainid_address}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error indexing OnchainID key: {e}")
            db.session.rollback()
            return False
    
    def get_token_transactions(self, token_id, limit=50, offset=0):
        """Get enhanced transaction history for a token"""
        try:
            transactions = TokenTransactionEnhanced.query.filter_by(
                token_id=token_id
            ).order_by(
                TokenTransactionEnhanced.created_at.desc()
            ).limit(limit).offset(offset).all()
            
            return transactions
            
        except Exception as e:
            logger.error(f"Error getting token transactions: {e}")
            return []
    
    def get_wallet_transactions(self, wallet_address, limit=50, offset=0):
        """Get transaction history for a specific wallet"""
        try:
            transactions = TokenTransactionEnhanced.query.filter(
                (TokenTransactionEnhanced.from_address == wallet_address) |
                (TokenTransactionEnhanced.to_address == wallet_address)
            ).order_by(
                TokenTransactionEnhanced.created_at.desc()
            ).limit(limit).offset(offset).all()
            
            return transactions
            
        except Exception as e:
            logger.error(f"Error getting wallet transactions: {e}")
            return []
    
    def get_onchainid_keys(self, onchainid_address=None, wallet_address=None):
        """Get OnchainID keys with filtering"""
        try:
            query = OnchainIDKey.query
            
            if onchainid_address:
                query = query.filter_by(onchainid_address=onchainid_address)
            
            if wallet_address:
                query = query.filter_by(wallet_address=wallet_address)
            
            return query.order_by(OnchainIDKey.created_at.desc()).all()
            
        except Exception as e:
            logger.error(f"Error getting OnchainID keys: {e}")
            return []
    
    def get_balance_history(self, token_id, wallet_address, limit=50):
        """Get balance history for a wallet"""
        try:
            snapshots = TokenBalanceSnapshot.query.filter_by(
                token_id=token_id,
                wallet_address=wallet_address
            ).order_by(
                TokenBalanceSnapshot.created_at.desc()
            ).limit(limit).all()
            
            return snapshots
            
        except Exception as e:
            logger.error(f"Error getting balance history: {e}")
            return []
    
    def sync_onchainid_keys(self, onchainid_address):
        """Sync OnchainID keys from blockchain to database"""
        try:
            # Get management keys (purpose 1)
            management_keys = self.web3_service.call_contract_function(
                'Identity', onchainid_address, 'getKeysByPurpose', 1
            )
            
            # Get claim signer keys (purpose 3)
            claim_signer_keys = self.web3_service.call_contract_function(
                'Identity', onchainid_address, 'getKeysByPurpose', 3
            )
            
            # Index management keys
            for key_hash in management_keys:
                # Get key details to extract the original address
                key_info = self.web3_service.call_contract_function(
                    'Identity', onchainid_address, 'getKey', key_hash
                )
                
                # The key_data contains the original address
                wallet_address = key_info[2]  # key_data field
                
                self.index_onchainid_key(
                    onchainid_address=onchainid_address,
                    wallet_address=wallet_address,
                    key_hash=key_hash.hex(),
                    key_type='management',
                    owner_type='unknown'  # Will be updated when we know the owner
                )
            
            # Index claim signer keys
            for key_hash in claim_signer_keys:
                # Get key details to extract the original address
                key_info = self.web3_service.call_contract_function(
                    'Identity', onchainid_address, 'getKey', key_hash
                )
                
                # The key_data contains the original address
                wallet_address = key_info[2]  # key_data field
                
                self.index_onchainid_key(
                    onchainid_address=onchainid_address,
                    wallet_address=wallet_address,
                    key_hash=key_hash.hex(),
                    key_type='claim_signer',
                    owner_type='unknown'
                )
            
            logger.info(f"Synced OnchainID keys for {onchainid_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error syncing OnchainID keys: {e}")
            return False
    
    def assign_owner_types(self):
        """Automatically assign owner types to OnchainID keys based on user data"""
        try:
            # Get all unknown owner types
            unknown_keys = OnchainIDKey.query.filter_by(owner_type='unknown').all()
            
            for key in unknown_keys:
                # Check if wallet address matches any user
                user = User.query.filter_by(wallet_address=key.wallet_address).first()
                if user:
                    key.owner_type = user.user_type
                    key.owner_id = user.id
                    logger.info(f"Assigned owner type {user.user_type} to key {key.wallet_address}")
                
                # Check if it's a known hardhat account (account 0)
                elif key.wallet_address.lower() == '0x70997970c51812dc3a010c7d01b50e0d17dc79c8':
                    key.owner_type = 'admin'
                    key.owner_id = None
                    logger.info(f"Assigned admin type to hardhat account 0: {key.wallet_address}")
                
                # Check if it's account 1
                elif key.wallet_address.lower() == '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc':
                    key.owner_type = 'issuer'
                    key.owner_id = None
                    logger.info(f"Assigned issuer type to hardhat account 1: {key.wallet_address}")
                
                # Check if it's account 2
                elif key.wallet_address.lower() == '0x90f79bf6eb2c4f870365e785982e1f101e93b906':
                    key.owner_type = 'investor'
                    key.owner_id = None
                    logger.info(f"Assigned investor type to hardhat account 2: {key.wallet_address}")
            
            db.session.commit()
            logger.info(f"Assigned owner types to {len(unknown_keys)} keys")
            return True
            
        except Exception as e:
            logger.error(f"Error assigning owner types: {e}")
            db.session.rollback()
            return False
    
    def sync_all_onchainid_keys(self):
        """Sync all OnchainID keys from all users"""
        try:
            # Get all users with OnchainID addresses
            users_with_onchainid = User.query.filter(User.onchain_id.isnot(None)).all()
            synced_count = 0
            
            for user in users_with_onchainid:
                if user.onchain_id:
                    if self.sync_onchainid_keys(user.onchain_id):
                        synced_count += 1
            
            # Assign owner types after syncing
            self.assign_owner_types()
            
            logger.info(f"Synced OnchainID keys for {synced_count} users")
            return synced_count
            
        except Exception as e:
            logger.error(f"Error syncing all OnchainID keys: {e}")
            return 0
    
    def pre_index_onchainid_key(self, onchainid_address, wallet_address, key_type, owner_type, owner_id=None):
        """Pre-index an OnchainID key before it's added to the blockchain"""
        try:
            # Create a temporary key hash (will be updated after blockchain transaction)
            temp_key_hash = f"pending_{wallet_address}_{key_type}"
            
            # Set proper role based on owner type
            if owner_type == 'Account 0':
                role = 'Initial Management Key'
            elif owner_type == 'admin':
                role = 'Admin Management Key'
            elif owner_type == 'issuer':
                role = 'Issuer Management Key'
            elif owner_type == 'trusted_issuer':
                role = 'Trusted Issuer Management Key'
            elif owner_type == 'investor':
                role = 'Investor Management Key'
            else:
                role = f'{owner_type.title()} Management Key'
            
            # Index the key with proper role
            key = OnchainIDKey(
                onchainid_address=onchainid_address,
                wallet_address=wallet_address,
                key_hash=temp_key_hash,
                key_type=key_type,
                role=role,  # Use meaningful role based on user type
                owner_type=owner_type,
                owner_id=owner_id
            )
            
            db.session.add(key)
            db.session.commit()
            
            logger.info(f"Pre-indexed OnchainID key: {wallet_address} -> {onchainid_address} ({key_type})")
            return key.id
            
        except Exception as e:
            logger.error(f"Error pre-indexing OnchainID key: {e}")
            db.session.rollback()
            return None
    
    def update_onchainid_key_after_transaction(self, key_id, transaction_hash, actual_key_hash):
        """Update OnchainID key after successful blockchain transaction"""
        try:
            key = OnchainIDKey.query.get(key_id)
            if key:
                key.key_hash = actual_key_hash
                key.transaction_hash = transaction_hash
                db.session.commit()
                
                logger.info(f"Updated OnchainID key {key_id} with transaction hash: {transaction_hash}")
                return True
            else:
                logger.error(f"OnchainID key {key_id} not found")
                return False
                
        except Exception as e:
            logger.error(f"Error updating OnchainID key: {e}")
            db.session.rollback()
            return False
    
    def get_pending_onchainid_keys(self, onchainid_address=None):
        """Get pending OnchainID keys that haven't been confirmed on blockchain"""
        try:
            query = OnchainIDKey.query.filter(
                OnchainIDKey.key_hash.like('pending_%')
            )
            
            if onchainid_address:
                query = query.filter_by(onchainid_address=onchainid_address)
            
            return query.all()
            
        except Exception as e:
            logger.error(f"Error getting pending OnchainID keys: {e}")
            return [] 