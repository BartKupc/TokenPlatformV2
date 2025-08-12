#!/usr/bin/env python3
"""
Migration script to initialize the 'agents' JSON field for existing tokens
with their current ir_agent and token_agent values.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models.token import Token
import json

def migrate():
    """Initialize agents JSON field for existing tokens"""
    with app.app_context():
        try:
            # Get all tokens that don't have agents field populated
            tokens = Token.query.filter(
                (Token.agents.is_(None)) | (Token.agents == '')
            ).all()
            
            if not tokens:
                print("✅ All tokens already have agents field populated")
                return True
            
            print(f"Found {len(tokens)} tokens to migrate...")
            
            for token in tokens:
                print(f"Migrating token {token.symbol} (ID: {token.id})...")
                
                # Create agents JSON from existing fields
                agents_data = {
                    'identity_agents': [token.ir_agent] if token.ir_agent else [],
                    'token_agents': [token.token_agent] if token.token_agent else [],
                    'compliance_agents': []
                }
                
                # Update the token
                token.agents = json.dumps(agents_data)
                print(f"  - Identity agents: {agents_data['identity_agents']}")
                print(f"  - Token agents: {agents_data['token_agents']}")
            
            # Commit all changes
            db.session.commit()
            print(f"✅ Successfully migrated {len(tokens)} tokens")
            
        except Exception as e:
            print(f"❌ Error during migration: {e}")
            db.session.rollback()
            return False
    
    return True

if __name__ == "__main__":
    print("🚀 Starting migration: Initialize agents field for existing tokens")
    success = migrate()
    if success:
        print("🎉 Migration completed successfully!")
    else:
        print("💥 Migration failed!")
        sys.exit(1) 