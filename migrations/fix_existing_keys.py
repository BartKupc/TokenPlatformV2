#!/usr/bin/env python3
"""
Migration script to fix existing OnchainID keys with proper roles and owner information
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models.enhanced_models import OnchainIDKey
from models.user import User

def migrate():
    """Fix existing OnchainID keys with proper roles and owner information"""
    with app.app_context():
        try:
            print("🔧 Starting migration: Fix existing OnchainID keys...")
            
            # Get all keys that need fixing
            keys_to_fix = OnchainIDKey.query.all()
            print(f"🔍 Found {len(keys_to_fix)} keys to check...")
            
            fixed_count = 0
            
            for key in keys_to_fix:
                print(f"🔍 Checking key: {key.wallet_address} -> {key.onchainid_address}")
                print(f"  - Current role: {key.role}")
                print(f"  - Current owner_type: {key.owner_type}")
                print(f"  - Current owner_id: {key.owner_id}")
                
                # Fix 1: Set default role if missing
                if not key.role or key.role == 'No Role':
                    if key.key_type == 'management':
                        key.role = 'Initial Management Key'
                    elif key.key_type == 'action':
                        key.role = 'Action Key'
                    elif key.key_type == 'claim_signer':
                        key.role = 'Claim Signer'
                    else:
                        key.role = 'Unknown Role'
                    
                    print(f"  ✅ Fixed role: {key.role}")
                    fixed_count += 1
                
                # Fix 2: Try to find user by wallet address if owner_id is missing
                if not key.owner_id and key.wallet_address:
                    user = User.query.filter_by(wallet_address=key.wallet_address).first()
                    if user:
                        key.owner_id = user.id
                        key.owner_type = user.user_type
                        print(f"  ✅ Fixed owner: {user.username} ({user.user_type})")
                        fixed_count += 1
                    else:
                        print(f"  ⚠️ No user found for wallet: {key.wallet_address}")
                
                # Fix 3: Handle special cases for known hardhat accounts
                if key.wallet_address:
                    wallet_lower = key.wallet_address.lower()
                    if wallet_lower == '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266':
                        # Account 0 - should be admin
                        if key.owner_type != 'admin':
                            key.owner_type = 'admin'
                            key.role = 'Platform Admin'
                            print(f"  ✅ Fixed Account 0: admin")
                            fixed_count += 1
                    elif wallet_lower == '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc':
                        # Account 1 - should be issuer
                        if key.owner_type != 'issuer':
                            key.owner_type = 'issuer'
                            key.role = 'Token Issuer'
                            print(f"  ✅ Fixed Account 1: issuer")
                            fixed_count += 1
                    elif wallet_lower == '0x90f79bf6eb2c4f870365e785982e1f101e93b906':
                        # Account 2 - should be investor
                        if key.owner_type != 'investor':
                            key.owner_type = 'investor'
                            key.role = 'Investor'
                            print(f"  ✅ Fixed Account 2: investor")
                            fixed_count += 1
                
                print()
            
            # Commit all changes
            db.session.commit()
            print(f"🎉 Migration completed! Fixed {fixed_count} issues.")
            
            # Show summary of fixed keys
            print("\n📋 Summary of fixed keys:")
            for key in keys_to_fix:
                print(f"  - {key.wallet_address}: {key.owner_type} - Role: {key.role}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error during migration: {e}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("🚀 Starting migration: Fix existing OnchainID keys")
    success = migrate()
    if success:
        print("🎉 Migration completed successfully!")
    else:
        print("💥 Migration failed!")
        sys.exit(1) 