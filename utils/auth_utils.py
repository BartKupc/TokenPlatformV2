import hashlib
import json
from models import db
from models.user import User

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_private_key(private_key, password=""):
    """Store private key directly (no encryption for dev)"""
    return private_key

def decrypt_private_key(encrypted_key, password=""):
    """Return private key directly (no decryption for dev)"""
    return encrypted_key

def create_default_admin():
    """Create default admin user if none exists"""
    admin = User.query.filter_by(user_type='admin').first()
    if not admin:
        # Use Hardhat account 0 private key
        admin_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        admin_wallet = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
        
        admin = User(
            username='admin',
            email='admin@tokenplatform.com',
            password_hash=hash_password('admin123'),
            wallet_address=admin_wallet,
            private_key=admin_private_key,  # Store directly, no encryption
            user_type='admin',
            kyc_status='approved'
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created")
    
    return admin 