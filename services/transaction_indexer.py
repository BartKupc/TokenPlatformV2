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
    
    def index_token_transaction(self, token_id, transaction_type, from_address=None, to_address=None, 
                               amount=None, transaction_hash=None, executed_by_user_id=None, 
                               executed_by_address=None, purchase_request_id=None, notes=None):
        """Index a token transaction in the database"""
        try:
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
            
            # Index the key with pending status
            key = OnchainIDKey(
                onchainid_address=onchainid_address,
                wallet_address=wallet_address,
                key_hash=temp_key_hash,
                key_type=key_type,
                role='Pending Role',  # Add default role for pending keys
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