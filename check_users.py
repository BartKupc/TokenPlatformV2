#!/usr/bin/env python3
"""
Check users and their OnchainID addresses
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models.user import User

def check_users():
    """Check users and their OnchainID addresses"""
    with app.app_context():
        try:
            print("🔍 Checking users and OnchainID addresses...")
            
            # Get all users
            users = User.query.all()
            print(f"📊 Found {len(users)} total users")
            
            # Check users with OnchainID
            users_with_onchainid = [u for u in users if u.onchain_id]
            print(f"🔑 Found {len(users_with_onchainid)} users with OnchainID addresses")
            
            # Show details
            for user in users_with_onchainid:
                print(f"  - {user.username} ({user.user_type}): {user.onchain_id}")
            
            return len(users_with_onchainid)
            
        except Exception as e:
            print(f"❌ Error checking users: {e}")
            return 0

if __name__ == "__main__":
    check_users() 