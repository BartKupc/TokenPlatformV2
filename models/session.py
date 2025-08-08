from datetime import datetime
from . import db

class TabSession(db.Model):
    """Model to track tab-specific sessions"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)  # Tab session identifier
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_type = db.Column(db.String(20), nullable=True)  # 'admin', 'issuer', 'trusted_issuer', 'investor'
    wallet_address = db.Column(db.String(42), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='tab_sessions') 