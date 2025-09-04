"""
OnchainID Key Manager Service
Handles OnchainID key addition with proper indexing before and after blockchain transactions
"""

from models import db
from models.enhanced_models import OnchainIDKey
from models.user import User
from services.web3_service import Web3Service
from services.transaction_indexer import TransactionIndexer
import logging

logger = logging.getLogger(__name__)

class OnchainIDKeyManager:
    """Service for managing OnchainID keys with proper indexing"""
    
    def __init__(self, web3_service: Web3Service = None):
        self.web3_service = web3_service or Web3Service()
        self.transaction_indexer = TransactionIndexer(web3_service)
    
    def check_key_exists(self, onchainid_address, key_hash, purpose):
        """Check if a key with specific purpose exists on an OnchainID"""
        try:
            # First check the blockchain
            contract = self.web3_service.get_contract(onchainid_address, 'Identity')
            if not contract:
                return False
            
            # Check if the key has the specified purpose
            has_purpose = contract.functions.keyHasPurpose(key_hash, purpose).call()
            return has_purpose
            
        except Exception as e:
            logger.error(f"Error checking key existence: {e}")
            return False
    
    def _remove_pre_indexed_key(self, key_id):
        """Remove a pre-indexed key if blockchain transaction fails"""
        try:
            key = OnchainIDKey.query.get(key_id)
            if key and key.key_hash.startswith('pending_'):
                db.session.delete(key)
                db.session.commit()
                logger.info(f"Removed pre-indexed key {key_id} due to failed transaction")
        except Exception as e:
            logger.error(f"Error removing pre-indexed key: {e}")
            db.session.rollback()
    
    def get_key_details(self, onchainid_address):
        """Get detailed key information for an OnchainID"""
        try:
            keys = self.transaction_indexer.get_onchainid_keys(onchainid_address=onchainid_address)
            
            # Group keys by type
            management_keys = [k for k in keys if k.key_type == 'management']
            claim_signer_keys = [k for k in keys if k.key_type == 'claim_signer']
            
            return {
                'onchainid_address': onchainid_address,
                'management_keys': management_keys,
                'claim_signer_keys': claim_signer_keys,
                'total_keys': len(keys)
            }
            
        except Exception as e:
            logger.error(f"Error getting key details: {e}")
            return None
    
    def index_management_key(self, onchainid_address, wallet_address, owner_type, owner_id, transaction_hash, key_hash=None):
        """Index an existing management key in the database"""
        try:
            print(f"🔍 index_management_key called with:")
            print(f"  - onchainid_address: {onchainid_address}")
            print(f"  - wallet_address: {wallet_address}")
            print(f"  - owner_type: {owner_type}")
            print(f"  - owner_id: {owner_id}")
            print(f"  - transaction_hash: {transaction_hash}")
            print(f"  - key_hash: {key_hash}")
            
            # If no key_hash provided, use the wallet address hash
            if not key_hash:
                print(f"🔍 No key_hash provided, calculating from wallet address...")
                if self.web3_service and self.web3_service.w3:
                    key_hash = self.web3_service.w3.keccak(text=wallet_address).hex()
                    print(f"🔍 Calculated key_hash: {key_hash}")
                else:
                    print(f"❌ ERROR: No web3_service available to calculate key_hash")
                    return None
            
            print(f"🔍 Using key_hash: {key_hash}")
            
            # Check if key already exists
            print(f"🔍 Checking if key already exists in database...")
            existing_key = OnchainIDKey.query.filter_by(
                onchainid_address=onchainid_address,
                key_hash=key_hash
            ).first()
            
            if existing_key:
                print(f"🔍 Key {key_hash} already indexed for {onchainid_address}")
                return existing_key.id
            
            print(f"🔍 Key does not exist, creating new entry...")
            
            # Create new indexed key
            indexed_key = OnchainIDKey(
                onchainid_address=onchainid_address,
                wallet_address=wallet_address,
                key_hash=key_hash,
                key_type='management',
                role='Initial Management Key',  # Add default role for initial keys
                owner_type=owner_type,
                owner_id=owner_id,  # Can be None for deployer account
                transaction_hash=transaction_hash
            )
            
            print(f"🔍 Adding key to database session...")
            db.session.add(indexed_key)
            
            print(f"🔍 Committing to database...")
            db.session.commit()
            
            print(f"✅ Successfully indexed management key {key_hash} for {onchainid_address}")
            print(f"✅ Database ID: {indexed_key.id}")
            return indexed_key.id
            
        except Exception as e:
            print(f"❌ ERROR in index_management_key: {e}")
            import traceback
            traceback.print_exc()
            logger.error(f"Error indexing management key: {e}")
            db.session.rollback()
            return None
    
    def index_claim_signer_key(self, onchainid_address, wallet_address, owner_type, owner_id, transaction_hash, key_hash=None):
        """Index an existing claim signer key in the database"""
        try:
            # If no key_hash provided, use the wallet address hash
            if not key_hash:
                key_hash = self.web3_service.w3.keccak(text=wallet_address).hex()
            
            # Check if key already exists
            existing_key = OnchainIDKey.query.filter_by(
                onchainid_address=onchainid_address,
                key_hash=key_hash
            ).first()
            
            if existing_key:
                logger.info(f"Key {key_hash} already indexed for {onchainid_address}")
                return existing_key.id
            
            # Create new indexed key
            indexed_key = OnchainIDKey(
                onchainid_address=onchainid_address,
                wallet_address=wallet_address,
                key_hash=key_hash,
                key_type='claim_signer',
                role='Claim Signer',  # Add default role for claim signer keys
                owner_type=owner_type,
                owner_id=owner_id,
                transaction_hash=transaction_hash
            )
            
            db.session.add(indexed_key)
            db.session.commit()
            
            logger.info(f"Successfully indexed claim signer key {key_hash} for {onchainid_address}")
            return indexed_key.id
            
        except Exception as e:
            logger.error(f"Error indexing claim signer key: {e}")
            db.session.rollback()
            return None 