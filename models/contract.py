from datetime import datetime
from . import db

class Contract(db.Model):
    """Model to track deployed contracts in the system"""
    id = db.Column(db.Integer, primary_key=True)
    contract_type = db.Column(db.String(50), nullable=False)  # 'TREXFactory', 'IdentityFactory', 'IdentityRegistry', etc.
    contract_address = db.Column(db.String(42), nullable=False, unique=True)
    contract_name = db.Column(db.String(100), nullable=False)  # Human readable name
    deployed_by = db.Column(db.String(42), nullable=False)  # Wallet address that deployed it
    deployed_at = db.Column(db.DateTime, default=datetime.utcnow)
    block_number = db.Column(db.Integer)  # Block where contract was deployed
    transaction_hash = db.Column(db.String(66))  # Transaction hash of deployment
    is_active = db.Column(db.Boolean, default=True)  # Whether contract is still active
    contract_metadata = db.Column(db.Text)  # JSON string for additional contract-specific data
    
    def __repr__(self):
        return f'<Contract {self.contract_name} at {self.contract_address}>' 