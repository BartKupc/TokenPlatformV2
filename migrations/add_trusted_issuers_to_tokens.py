#!/usr/bin/env python3
"""
Migration script to add trusted_issuers field to existing tokens
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from models import db
from models.token import Token

def migrate():
    """Add trusted_issuers field to existing tokens"""
    with app.app_context():
        try:
            print("🔧 Starting migration: Adding trusted_issuers field to tokens...")
            
            # Check if the column already exists
            try:
                inspector = db.inspect(db.engine)
                columns = [col['name'] for col in inspector.get_columns('token')]
                
                if 'trusted_issuers' in columns:
                    print("✅ Column 'trusted_issuers' already exists in token table")
                    return
            except Exception as e:
                print(f"⚠️ Could not check existing columns: {e}")
                print("📝 Proceeding to add column...")
            
            # Add the column
            print("📝 Adding trusted_issuers column to token table...")
            with db.engine.connect() as connection:
                connection.execute(db.text("ALTER TABLE token ADD COLUMN trusted_issuers TEXT"))
                connection.commit()
            
            # Update existing tokens to have empty trusted_issuers
            print("🔄 Updating existing tokens...")
            tokens = Token.query.all()
            for token in tokens:
                if not hasattr(token, 'trusted_issuers') or token.trusted_issuers is None:
                    token.trusted_issuers = '[]'  # Empty JSON array
            
            db.session.commit()
            print(f"✅ Successfully updated {len(tokens)} tokens")
            print("🎉 Migration completed successfully!")
            
        except Exception as e:
            print(f"❌ Migration failed: {str(e)}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    migrate() 