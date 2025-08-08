from datetime import datetime
from . import db

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_address = db.Column(db.String(42), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    symbol = db.Column(db.String(10), nullable=False)
    total_supply = db.Column(db.BigInteger, nullable=False)  # Changed to BigInteger for large token supplies
    issuer_address = db.Column(db.String(42), nullable=False)
    deployed_at = db.Column(db.DateTime, default=datetime.utcnow)
    price_per_token = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text, nullable=True)
    
    # Agent Configuration
    ir_agent = db.Column(db.String(20), nullable=False)  # 'issuer', 'admin'
    token_agent = db.Column(db.String(20), nullable=False)  # 'issuer', 'admin'
    
    # Claim Configuration
    claim_topics = db.Column(db.Text)  # JSON array of required claim topics
    claim_issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Specific trusted issuer ID
    claim_issuer_type = db.Column(db.String(20), nullable=False)  # 'issuer', 'trusted_issuer', 'admin'
    
    # Contract Addresses (from TREX Suite deployment)
    identity_registry_address = db.Column(db.String(42), nullable=True)
    compliance_address = db.Column(db.String(42), nullable=True)
    claim_topics_registry_address = db.Column(db.String(42), nullable=True)
    trusted_issuers_registry_address = db.Column(db.String(42), nullable=True)
    
    # Token Status
    is_paused = db.Column(db.Boolean, default=False)
    is_burnable = db.Column(db.Boolean, default=True)
    is_transferable = db.Column(db.Boolean, default=True)

class TokenInterest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount_requested = db.Column(db.BigInteger, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    processed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Identity Registry Status
    ir_status = db.Column(db.String(20), default='pending')  # 'pending', 'added', 'failed'
    ir_added_at = db.Column(db.DateTime)
    ir_added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # KYC Verification
    kyc_verified = db.Column(db.Boolean, default=False)
    kyc_verified_at = db.Column(db.DateTime)
    kyc_verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    token = db.relationship('Token', backref='interests')
    investor = db.relationship('User', foreign_keys=[investor_id], backref='token_interests')
    ir_adder = db.relationship('User', foreign_keys=[ir_added_by], backref='ir_added_interests')
    processor = db.relationship('User', foreign_keys=[processed_by], backref='processed_interests')
    kyc_verifier = db.relationship('User', foreign_keys=[kyc_verified_by], backref='kyc_verified_interests')

class TokenPurchaseRequest(db.Model):
    """Enhanced model for token purchase requests with verification"""
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount_requested = db.Column(db.BigInteger, nullable=False)
    price_per_token = db.Column(db.Float, nullable=False)
    total_value = db.Column(db.Float, nullable=False)  # amount * price
    
    # Request Status
    status = db.Column(db.String(20), default='pending')  # 'pending', 'verified', 'approved', 'rejected', 'completed'
    
    # Identity Registry Status
    ir_status = db.Column(db.String(20), default='pending')  # 'pending', 'added', 'failed'
    ir_added_at = db.Column(db.DateTime)
    ir_added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Verification Details
    verification_status = db.Column(db.String(20), default='pending')  # 'pending', 'verified', 'failed'
    verification_checked_at = db.Column(db.DateTime)
    verification_checked_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    verification_notes = db.Column(db.Text)
    
    # Approval Details
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    approval_notes = db.Column(db.Text)
    
    # Purchase Details
    purchase_completed_at = db.Column(db.DateTime)
    transaction_hash = db.Column(db.String(66))  # Ethereum transaction hash
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    token = db.relationship('Token', backref='purchase_requests')
    investor = db.relationship('User', foreign_keys=[investor_id], backref='purchase_requests')
    ir_adder = db.relationship('User', foreign_keys=[ir_added_by], backref='ir_added_requests')
    verifier = db.relationship('User', foreign_keys=[verification_checked_by], backref='verified_requests')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_requests')

class TokenTransaction(db.Model):
    """Track all token transactions (mint, burn, transfer, purchase)"""
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # 'mint', 'burn', 'transfer', 'purchase'
    
    # Transaction Details
    from_address = db.Column(db.String(42), nullable=True)  # Null for mint
    to_address = db.Column(db.String(42), nullable=True)    # Null for burn
    amount = db.Column(db.BigInteger, nullable=False)
    
    # Purchase Request Reference (if applicable)
    purchase_request_id = db.Column(db.Integer, db.ForeignKey('token_purchase_request.id'), nullable=True)
    
    # Blockchain Details
    transaction_hash = db.Column(db.String(66), nullable=True)
    block_number = db.Column(db.BigInteger, nullable=True)
    
    # Executed by
    executed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    token = db.relationship('Token', backref='transactions')
    purchase_request = db.relationship('TokenPurchaseRequest', backref='transactions')
    executor = db.relationship('User', backref='executed_transactions')

class InvestorVerification(db.Model):
    """Track investor verification status for each token"""
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Verification Status
    is_verified = db.Column(db.Boolean, default=False)
    verification_date = db.Column(db.DateTime)
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Verification Details
    onchain_id_verified = db.Column(db.Boolean, default=False)
    kyc_verified = db.Column(db.Boolean, default=False)
    compliance_verified = db.Column(db.Boolean, default=False)
    
    # Notes
    verification_notes = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    token = db.relationship('Token', backref='investor_verifications')
    investor = db.relationship('User', foreign_keys=[investor_id], backref='verifications')
    verifier = db.relationship('User', foreign_keys=[verified_by], backref='verifications_performed')
    
    # Unique constraint: one verification per investor per token
    __table_args__ = (db.UniqueConstraint('token_id', 'investor_id', name='_token_investor_verification_uc'),) 