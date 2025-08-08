#!/usr/bin/env python3
"""
Test script for OnchainID key syncing
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from services.transaction_indexer import TransactionIndexer
from services.web3_service import Web3Service
from models import db

def test_onchainid_sync():
    """Test OnchainID key syncing functionality"""
    with app.app_context():
        try:
            print("🔧 Testing OnchainID key syncing...")
            
            # Initialize services
            web3_service = Web3Service()
            transaction_indexer = TransactionIndexer(web3_service)
            
            # Sync all OnchainID keys
            print("📡 Syncing OnchainID keys from blockchain...")
            synced_count = transaction_indexer.sync_all_onchainid_keys()
            
            print(f"✅ Successfully synced OnchainID keys for {synced_count} tokens")
            
            # Get all synced keys
            all_keys = transaction_indexer.get_onchainid_keys()
            print(f"📊 Total OnchainID keys in database: {len(all_keys)}")
            
            # Show some details
            for key in all_keys[:5]:  # Show first 5 keys
                print(f"  - {key.wallet_address[:6]}...{key.wallet_address[-4:]} -> {key.onchainid_address[:6]}...{key.onchainid_address[-4:]} ({key.key_type}, {key.owner_type})")
            
            if len(all_keys) > 5:
                print(f"  ... and {len(all_keys) - 5} more keys")
            
            return True
            
        except Exception as e:
            print(f"❌ Error testing OnchainID sync: {e}")
            return False

if __name__ == "__main__":
    test_onchainid_sync() 