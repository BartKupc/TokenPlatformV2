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