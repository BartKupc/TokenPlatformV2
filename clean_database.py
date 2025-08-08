#!/usr/bin/env python3
"""
Database Cleaner Script for Token Platform

This script cleans the database by:
1. Dropping all existing tables
2. Recreating tables with current schema
3. Creating default admin user
4. Optionally adding sample data

Usage:
    python clean_database.py [--sample-data]
"""

import os
import sys
import argparse
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models.user import User
from models.token import Token, TokenInterest
from utils.auth_utils import hash_password, create_default_admin

def clean_database(add_sample_data=False):
    """Clean and recreate the database"""
    
    with app.app_context():
        print("🗑️  Cleaning database...")
        
        # Drop all tables
        print("  - Dropping all tables...")
        db.drop_all()
        
        # Create all tables with current schema
        print("  - Creating tables with current schema...")
        db.create_all()
        
        # Create default admin user
        print("  - Creating default admin user...")
        create_default_admin()
        
        if add_sample_data:
            print("  - Adding sample data...")
            add_sample_data_to_db()
        
        print("✅ Database cleaned successfully!")
        print(f"📊 Database file: {app.config['SQLALCHEMY_DATABASE_URI']}")
        
        # Show database stats
        show_database_stats()

def add_sample_data_to_db():
    """Add sample data for testing"""
    
    # Create sample users
    sample_users = [
        {
            'username': 'issuer1',
            'email': 'issuer1@example.com',
            'password': 'password123',
            'wallet_address': '0x1111111111111111111111111111111111111111',
            'user_type': 'issuer',
            'kyc_status': 'approved'
        },
        {
            'username': 'trusted_issuer1',
            'email': 'trusted_issuer1@example.com',
            'password': 'password123',
            'wallet_address': '0x2222222222222222222222222222222222222222',
            'user_type': 'trusted_issuer',
            'kyc_status': 'approved'
        },
        {
            'username': 'investor1',
            'email': 'investor1@example.com',
            'password': 'password123',
            'wallet_address': '0x3333333333333333333333333333333333333333',
            'user_type': 'investor',
            'kyc_status': 'pending',
            'kyc_data': '{"full_name": "John Doe", "nationality": "USA", "date_of_birth": "1990-01-01"}'
        },
        {
            'username': 'investor2',
            'email': 'investor2@example.com',
            'password': 'password123',
            'wallet_address': '0x4444444444444444444444444444444444444444',
            'user_type': 'investor',
            'kyc_status': 'approved',
            'kyc_data': '{"full_name": "Jane Smith", "nationality": "UK", "date_of_birth": "1985-05-15"}',
            'onchain_id': '0x5555555555555555555555555555555555555555'
        }
    ]
    
    for user_data in sample_users:
        user = User(
            username=user_data['username'],
            email=user_data['email'],
            password_hash=hash_password(user_data['password']),
            wallet_address=user_data['wallet_address'],
            user_type=user_data['user_type'],
            kyc_status=user_data['kyc_status']
        )
        
        if 'kyc_data' in user_data:
            user.kyc_data = user_data['kyc_data']
        
        if 'onchain_id' in user_data:
            user.onchain_id = user_data['onchain_id']
        
        db.session.add(user)
    
    # Create sample tokens
    issuer = User.query.filter_by(user_type='issuer').first()
    if issuer:
        sample_tokens = [
            {
                'name': 'Startup Alpha Token',
                'symbol': 'SAT',
                'total_supply': 1000000,
                'price_per_token': 1.50,
                'description': 'Token for innovative startup in AI sector',
                'ir_agent': 'issuer',
                'token_agent': 'issuer',
                'claim_topics': ['1', '6'],  # KYC and Compliance
                'claim_issuer': 'trusted_issuer'
            },
            {
                'name': 'Green Energy Token',
                'symbol': 'GET',
                'total_supply': 5000000,
                'price_per_token': 2.00,
                'description': 'Token for renewable energy projects',
                'ir_agent': 'trusted_issuer',
                'token_agent': 'issuer',
                'claim_topics': ['1', '2', '6'],  # KYC, Nationality, Compliance
                'claim_issuer': 'trusted_issuer'
            }
        ]
        
        for token_data in sample_tokens:
            # Generate mock token address
            import hashlib
            import time
            mock_address = "0x" + hashlib.md5(f"{token_data['name']}{time.time()}".encode()).hexdigest()[:40]
            
            token = Token(
                token_address=mock_address,
                name=token_data['name'],
                symbol=token_data['symbol'],
                total_supply=token_data['total_supply'],
                issuer_address=issuer.wallet_address,
                price_per_token=token_data['price_per_token'],
                description=token_data['description'],
                ir_agent=token_data['ir_agent'],
                token_agent=token_data['token_agent'],
                claim_topics=token_data['claim_topics'],
                claim_issuer=token_data['claim_issuer']
            )
            
            db.session.add(token)
    
    # Create sample token interests
    investor = User.query.filter_by(user_type='investor', kyc_status='approved').first()
    token = Token.query.first()
    
    if investor and token:
        interest = TokenInterest(
            token_id=token.id,
            investor_id=investor.id,
            amount_requested=1000,
            status='pending'
        )
        db.session.add(interest)
    
    db.session.commit()
    print("  ✅ Sample data added successfully!")

def show_database_stats():
    """Show database statistics"""
    
    print("\n📊 Database Statistics:")
    print(f"  - Users: {User.query.count()}")
    print(f"  - Tokens: {Token.query.count()}")
    print(f"  - Token Interests: {TokenInterest.query.count()}")
    
    # Show users by type
    for user_type in ['admin', 'issuer', 'trusted_issuer', 'investor']:
        count = User.query.filter_by(user_type=user_type).count()
        print(f"    - {user_type.title()}s: {count}")
    
    # Show tokens
    tokens = Token.query.all()
    if tokens:
        print("\n  - Tokens:")
        for token in tokens:
            print(f"    - {token.name} ({token.symbol}) - {token.ir_agent}/{token.token_agent}")

def backup_database():
    """Create a backup of the current database"""
    
    import shutil
    from datetime import datetime
    
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    if os.path.exists(db_path):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"{db_path}.backup_{timestamp}"
        
        shutil.copy2(db_path, backup_path)
        print(f"💾 Database backed up to: {backup_path}")
        return backup_path
    return None

def main():
    """Main function"""
    
    parser = argparse.ArgumentParser(description='Clean Token Platform Database')
    parser.add_argument('--sample-data', action='store_true', 
                       help='Add sample data after cleaning')
    parser.add_argument('--backup', action='store_true',
                       help='Create backup before cleaning')
    parser.add_argument('--force', action='store_true',
                       help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    print("🚀 Token Platform Database Cleaner")
    print("=" * 40)
    
    if not args.force:
        print("\n⚠️  WARNING: This will delete ALL data in the database!")
        print("   Make sure you have a backup if needed.")
        
        response = input("\nDo you want to continue? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Operation cancelled.")
            return
    
    try:
        # Create backup if requested
        if args.backup:
            backup_path = backup_database()
            if backup_path:
                print(f"✅ Backup created: {backup_path}")
        
        # Clean database
        clean_database(add_sample_data=args.sample_data)
        
        print("\n🎉 Database cleaning completed successfully!")
        print("\nNext steps:")
        print("1. Start the application: python app.py")
        print("2. Login with default admin: admin / admin123")
        
        if args.sample_data:
            print("\nSample users created:")
            print("- issuer1 / password123")
            print("- trusted_issuer1 / password123")
            print("- investor1 / password123")
            print("- investor2 / password123")
        
    except Exception as e:
        print(f"❌ Error cleaning database: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 