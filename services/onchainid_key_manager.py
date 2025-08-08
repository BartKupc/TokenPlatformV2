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
    
    def add_management_key(self, onchainid_address, wallet_address, added_by_user_id, private_key=None):
        """Add a management key to OnchainID with proper indexing"""
        try:
            # Get the user who is adding the key
            added_by_user = User.query.get(added_by_user_id)
            if not added_by_user:
                logger.error(f"User {added_by_user_id} not found")
                return {'success': False, 'error': 'User not found'}
            
            # Pre-index the key before blockchain transaction
            key_id = self.transaction_indexer.pre_index_onchainid_key(
                onchainid_address=onchainid_address,
                wallet_address=wallet_address,
                key_type='management',
                owner_type=added_by_user.user_type,
                owner_id=added_by_user_id
            )
            
            if not key_id:
                return {'success': False, 'error': 'Failed to pre-index key'}
            
            # Use provided private key or get from user
            if not private_key:
                private_key = added_by_user.private_key
            
            # Create Web3Service with the private key
            web3_service = Web3Service(private_key)
            
            # Get the OnchainID contract
            contract = web3_service.get_contract('Identity', onchainid_address)
            
            # Hash the wallet address (this is what gets stored on blockchain)
            key_hash = web3_service.web3.keccak(text=wallet_address)
            
            # Add the key to the blockchain (purpose 1 = management)
            tx_hash = web3_service.transact_contract_function(
                'Identity', onchainid_address, 'addKey', key_hash, 1, 1
            )
            
            # Wait for transaction
            receipt = web3_service.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                # Update the indexed key with transaction details
                self.transaction_indexer.update_onchainid_key_after_transaction(
                    key_id=key_id,
                    transaction_hash=tx_hash.hex(),
                    actual_key_hash=key_hash.hex()
                )
                
                logger.info(f"Successfully added management key {wallet_address} to {onchainid_address}")
                return {
                    'success': True, 
                    'tx_hash': tx_hash.hex(),
                    'key_hash': key_hash.hex(),
                    'key_id': key_id
                }
            else:
                # Transaction failed, remove the pre-indexed key
                self._remove_pre_indexed_key(key_id)
                return {'success': False, 'error': 'Blockchain transaction failed'}
                
        except Exception as e:
            logger.error(f"Error adding management key: {e}")
            return {'success': False, 'error': str(e)}
    
    def add_claim_signer_key(self, onchainid_address, wallet_address, added_by_user_id, private_key=None):
        """Add a claim signer key to OnchainID with proper indexing"""
        try:
            # Get the user who is adding the key
            added_by_user = User.query.get(added_by_user_id)
            if not added_by_user:
                logger.error(f"User {added_by_user_id} not found")
                return {'success': False, 'error': 'User not found'}
            
            # Pre-index the key before blockchain transaction
            key_id = self.transaction_indexer.pre_index_onchainid_key(
                onchainid_address=onchainid_address,
                wallet_address=wallet_address,
                key_type='claim_signer',
                owner_type=added_by_user.user_type,
                owner_id=added_by_user_id
            )
            
            if not key_id:
                return {'success': False, 'error': 'Failed to pre-index key'}
            
            # Use provided private key or get from user
            if not private_key:
                private_key = added_by_user.private_key
            
            # Create Web3Service with the private key
            web3_service = Web3Service(private_key)
            
            # Get the OnchainID contract
            contract = web3_service.get_contract('Identity', onchainid_address)
            
            # Hash the wallet address (this is what gets stored on blockchain)
            key_hash = web3_service.web3.keccak(text=wallet_address)
            
            # Add the key to the blockchain (purpose 3 = claim signer)
            tx_hash = web3_service.transact_contract_function(
                'Identity', onchainid_address, 'addKey', key_hash, 3, 1
            )
            
            # Wait for transaction
            receipt = web3_service.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                # Update the indexed key with transaction details
                self.transaction_indexer.update_onchainid_key_after_transaction(
                    key_id=key_id,
                    transaction_hash=tx_hash.hex(),
                    actual_key_hash=key_hash.hex()
                )
                
                logger.info(f"Successfully added claim signer key {wallet_address} to {onchainid_address}")
                return {
                    'success': True, 
                    'tx_hash': tx_hash.hex(),
                    'key_hash': key_hash.hex(),
                    'key_id': key_id
                }
            else:
                # Transaction failed, remove the pre-indexed key
                self._remove_pre_indexed_key(key_id)
                return {'success': False, 'error': 'Blockchain transaction failed'}
                
        except Exception as e:
            logger.error(f"Error adding claim signer key: {e}")
            return {'success': False, 'error': str(e)}
    
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