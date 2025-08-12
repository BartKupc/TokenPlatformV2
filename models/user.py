from datetime import datetime
from . import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    wallet_address = db.Column(db.String(42), nullable=False)
    private_key = db.Column(db.String(66), nullable=False)  # Encrypted private key (0x + 64 hex chars)
    user_type = db.Column(db.String(20), nullable=False)  # 'admin', 'issuer', 'trusted_issuer', 'investor'
    kyc_status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    kyc_data = db.Column(db.Text)  # JSON string of KYC data
    onchain_id = db.Column(db.String(42))  # OnchainID address if created
    claim_issuer_address = db.Column(db.String(42), nullable=True)  # ClaimIssuer contract address (for trusted issuers)
    kyc_approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Who approved the KYC
    kyc_approved_at = db.Column(db.DateTime)  # When KYC was approved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    kyc_approver_rel = db.relationship('User', foreign_keys=[kyc_approved_by], backref='approved_kyc_users', remote_side=[id])

class TrustedIssuerCapability(db.Model):
    """Model to track what claims a trusted issuer can issue"""
    id = db.Column(db.Integer, primary_key=True)
    trusted_issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claim_topic = db.Column(db.Integer, nullable=False)  # Claim topic number (1-10 for T-REX standard)
    claim_data = db.Column(db.String(100), nullable=False)  # Specific claim data value
    description = db.Column(db.String(200))  # Human readable description
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    trusted_issuer = db.relationship('User', backref='capabilities')

class TrustedIssuerApproval(db.Model):
    """Model to track pending trusted issuer approvals"""
    id = db.Column(db.Integer, primary_key=True)
    trusted_issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_capabilities = db.Column(db.Text)  # JSON string of requested claim capabilities
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    trusted_issuer = db.relationship('User', foreign_keys=[trusted_issuer_id], backref='approval_requests')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_trusted_issuers')

class UserOnchainID(db.Model):
    """Model to track OnchainID creation for all users"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    onchain_id_address = db.Column(db.String(42), nullable=False)  # OnchainID contract address
    management_keys_added = db.Column(db.Boolean, default=False)  # Whether management keys were added
    signing_keys_added = db.Column(db.Boolean, default=False)  # Whether signing keys were added
    claim_issuer_address = db.Column(db.String(42), nullable=True)  # ClaimIssuer contract address (for trusted issuers)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='onchain_id_info')

class UserClaim(db.Model):
    """Model to track claims issued to users by trusted issuers"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claim_topic = db.Column(db.Integer, nullable=False)  # Claim topic number (1-10 for T-REX standard)
    claim_data = db.Column(db.String(100), nullable=False)  # Specific claim data value
    issued_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Trusted issuer who issued the claim
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    onchain_tx_hash = db.Column(db.String(66), nullable=True)  # Transaction hash when claim was added to OnchainID
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='claims')
    trusted_issuer = db.relationship('User', foreign_keys=[issued_by], backref='issued_claims')

class TokenClaimRequirement(db.Model):
    """Model to track what claims are required for each token"""
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    claim_topic = db.Column(db.Integer, nullable=False)  # Required claim topic
    claim_data = db.Column(db.String(100), nullable=False)  # Required claim data value
    is_required = db.Column(db.Boolean, default=True)  # Whether this claim is mandatory
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    token = db.relationship('Token', backref='claim_requirements') 