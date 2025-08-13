"""
Enhanced Models for Transaction Indexing and OnchainID Management
"""

from models import db
from datetime import datetime

class OnchainIDKey(db.Model):
    """Enhanced OnchainID Key Management"""
    __tablename__ = 'onchainid_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    onchainid_address = db.Column(db.String(42), nullable=False)
    wallet_address = db.Column(db.String(42), nullable=False)
    key_hash = db.Column(db.String(66), nullable=False)
    key_type = db.Column(db.String(20), nullable=False)  # 'management', 'claim_signer'
    role = db.Column(db.String(100), nullable=True)  # Descriptive role name (e.g., 'Trusted Issuer', 'Admin')
    owner_type = db.Column(db.String(20), nullable=False)  # 'issuer', 'investor', 'trusted_issuer', 'admin'
    owner_id = db.Column(db.Integer)  # Reference to user.id if applicable
    transaction_hash = db.Column(db.String(66))  # Blockchain transaction hash when key was added
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Note: No relationship defined to avoid foreign key constraint issues
    # We can query the owner manually when needed
    
    def __repr__(self):
        return f'<OnchainIDKey {self.wallet_address} -> {self.onchainid_address} ({self.key_type})>'

class TokenTransactionEnhanced(db.Model):
    """Enhanced Token Transactions with detailed tracking"""
    __tablename__ = 'token_transactions_enhanced'
    
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # 'mint', 'burn', 'transfer', 'forced_transfer'
    from_address = db.Column(db.String(42))
    to_address = db.Column(db.String(42))
    amount = db.Column(db.BigInteger, nullable=False)
    amount_formatted = db.Column(db.Numeric(20, 8))  # Human readable amount
    transaction_hash = db.Column(db.String(66))
    block_number = db.Column(db.BigInteger)
    gas_used = db.Column(db.BigInteger)
    gas_price = db.Column(db.BigInteger)
    executed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    executed_by_address = db.Column(db.String(42), nullable=False)
    purchase_request_id = db.Column(db.Integer, db.ForeignKey('token_purchase_request.id'))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Note: No relationships defined to avoid foreign key constraint issues
    # We can query related data manually when needed
    
    def __repr__(self):
        return f'<TokenTransactionEnhanced {self.transaction_type} {self.amount} {self.token.symbol if self.token else "Unknown"}>'

class TokenBalanceSnapshot(db.Model):
    """Token Balance Snapshots for verification"""
    __tablename__ = 'token_balance_snapshots'
    
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    wallet_address = db.Column(db.String(42), nullable=False)
    balance_wei = db.Column(db.BigInteger, nullable=False)
    balance_formatted = db.Column(db.Numeric(20, 8), nullable=False)
    snapshot_type = db.Column(db.String(20), nullable=False)  # 'pre_transaction', 'post_transaction', 'manual'
    transaction_id = db.Column(db.Integer, db.ForeignKey('token_transactions_enhanced.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Note: No relationships defined to avoid foreign key constraint issues
    # We can query related data manually when needed
    
    def __repr__(self):
        return f'<TokenBalanceSnapshot {self.wallet_address} {self.balance_formatted} {self.token.symbol if self.token else "Unknown"}>' 

class KYCRequest(db.Model):
    """Multi-lane KYC request system - investor requests KYC from specific trusted issuers"""
    __tablename__ = 'kyc_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    trusted_issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected', 'cancelled'
    kyc_data = db.Column(db.Text)  # JSON string of KYC data
    notes = db.Column(db.Text)  # Notes from trusted issuer
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    investor = db.relationship('User', foreign_keys=[investor_id], backref='kyc_requests')
    trusted_issuer = db.relationship('User', foreign_keys=[trusted_issuer_id], backref='received_kyc_requests')
    
    def __repr__(self):
        return f'<KYCRequest {self.investor.username} -> {self.trusted_issuer.username} ({self.status})>'

class ClaimRequest(db.Model):
    """Specific claim requests within a KYC request"""
    __tablename__ = 'claim_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    kyc_request_id = db.Column(db.Integer, db.ForeignKey('kyc_requests.id'), nullable=False)
    claim_topic = db.Column(db.Integer, nullable=False)  # Claim topic number (1-10 for T-REX standard)
    requested_claim_data = db.Column(db.String(100), nullable=False)  # Requested claim data value
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    approved_claim_data = db.Column(db.String(100), nullable=True)  # Final claim data if approved
    notes = db.Column(db.Text)  # Notes from trusted issuer
    reviewed_at = db.Column(db.DateTime, nullable=True)
    onchain_tx_hash = db.Column(db.String(66), nullable=True)  # Blockchain transaction hash when claim was added
    blockchain_status = db.Column(db.String(20), default='pending')  # 'pending', 'success', 'failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    kyc_request = db.relationship('KYCRequest', backref='claim_requests')
    
    def __repr__(self):
        return f'<ClaimRequest Topic {self.claim_topic}: {self.requested_claim_data} ({self.status})>'

class TrustedIssuerSpecialization(db.Model):
    """What claims each trusted issuer can handle and their expertise"""
    __tablename__ = 'trusted_issuer_specializations'
    
    id = db.Column(db.Integer, primary_key=True)
    trusted_issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claim_topic = db.Column(db.Integer, nullable=False)  # Claim topic number (1-10 for T-REX standard)
    can_handle = db.Column(db.Boolean, default=True)  # Whether they can handle this topic
    expertise_level = db.Column(db.String(20), default='standard')  # 'basic', 'standard', 'expert'
    processing_time_days = db.Column(db.Integer, default=3)  # Estimated processing time
    fee_amount = db.Column(db.Numeric(10, 2), nullable=True)  # Fee for this claim type
    fee_currency = db.Column(db.String(3), default='USD')  # Fee currency
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    trusted_issuer = db.relationship('User', backref='specializations')
    
    def __repr__(self):
        return f'<TrustedIssuerSpecialization {self.trusted_issuer.username} Topic {self.claim_topic} ({self.expertise_level})>' 