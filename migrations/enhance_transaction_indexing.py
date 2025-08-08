"""
Migration: Enhance Transaction Indexing and OnchainID Management
Adds comprehensive transaction tracking and improved OnchainID visibility
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Create a minimal Flask app for migrations
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////mnt/ethnode/TokenPlatform/instance/fundraising.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def upgrade():
    """Add new tables for enhanced transaction indexing"""
    
    with db.engine.connect() as conn:
        # 1. Enhanced OnchainID Key Management
        conn.execute(db.text("""
            CREATE TABLE IF NOT EXISTS onchainid_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                onchainid_address VARCHAR(42) NOT NULL,
                wallet_address VARCHAR(42) NOT NULL,
                key_hash VARCHAR(66) NOT NULL,
                key_type VARCHAR(20) NOT NULL,
                owner_type VARCHAR(20) NOT NULL,
                owner_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(onchainid_address, wallet_address, key_type)
            )
        """))
        
        # 2. Enhanced Token Transactions
        conn.execute(db.text("""
            CREATE TABLE IF NOT EXISTS token_transactions_enhanced (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id INTEGER NOT NULL,
                transaction_type VARCHAR(20) NOT NULL,
                from_address VARCHAR(42),
                to_address VARCHAR(42),
                amount BIGINT NOT NULL,
                amount_formatted DECIMAL(20, 8),
                transaction_hash VARCHAR(66),
                block_number BIGINT,
                gas_used BIGINT,
                gas_price BIGINT,
                executed_by INTEGER NOT NULL,
                executed_by_address VARCHAR(42) NOT NULL,
                purchase_request_id INTEGER,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (token_id) REFERENCES token (id),
                FOREIGN KEY (executed_by) REFERENCES user (id),
                FOREIGN KEY (purchase_request_id) REFERENCES token_purchase_request (id)
            )
        """))
        
        # 3. Token Balance Snapshots (for verification)
        conn.execute(db.text("""
            CREATE TABLE IF NOT EXISTS token_balance_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id INTEGER NOT NULL,
                wallet_address VARCHAR(42) NOT NULL,
                balance_wei BIGINT NOT NULL,
                balance_formatted DECIMAL(20, 8) NOT NULL,
                snapshot_type VARCHAR(20) NOT NULL,
                transaction_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (token_id) REFERENCES token (id),
                FOREIGN KEY (transaction_id) REFERENCES token_transactions_enhanced (id)
            )
        """))
        
        # 4. Indexes for better performance
        conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_onchainid_keys_onchainid ON onchainid_keys(onchainid_address)"))
        conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_onchainid_keys_wallet ON onchainid_keys(wallet_address)"))
        conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_token_transactions_token ON token_transactions_enhanced(token_id)"))
        conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_token_transactions_hash ON token_transactions_enhanced(transaction_hash)"))
        conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_token_transactions_type ON token_transactions_enhanced(transaction_type)"))
        conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_balance_snapshots_token ON token_balance_snapshots(token_id)"))
        conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_balance_snapshots_wallet ON token_balance_snapshots(wallet_address)"))
        
        conn.commit()
    
    print("✅ Enhanced transaction indexing tables created successfully!")

def downgrade():
    """Remove the new tables"""
    db.engine.execute("DROP TABLE IF EXISTS token_balance_snapshots")
    db.engine.execute("DROP TABLE IF EXISTS token_transactions_enhanced")
    db.engine.execute("DROP TABLE IF EXISTS onchainid_keys")
    print("✅ Enhanced transaction indexing tables removed!")

if __name__ == '__main__':
    with app.app_context():
        upgrade() 