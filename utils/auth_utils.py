import hashlib
import json
from models import db
from models.user import User

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# Private key encryption/decryption functions removed - using MetaMask instead

def create_default_admin():
    """Create default admin user if none exists"""
    admin = User.query.filter_by(user_type='admin').first()
    if not admin:
        # Use Hardhat account 0 wallet address (private key hardcoded when needed)
        admin_wallet = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
        
        admin = User(
            username='admin',
            email='admin@tokenplatform.com',
            password_hash=hash_password('admin123'),
            wallet_address=admin_wallet,
            # private_key removed - will hardcode Account 0 private key when needed
            user_type='admin',
            kyc_status='approved'
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created (Account 0 wallet, private key hardcoded when needed)")
    
    return admin 