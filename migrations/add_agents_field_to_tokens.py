#!/usr/bin/env python3
"""
Migration script to add the 'agents' field to the token table.
This field will store multiple agents as JSON for each token.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

def migrate():
    """Add agents field to token table"""
    with app.app_context():
        try:
            # Check if the column already exists
            with db.engine.connect() as connection:
                result = connection.execute(db.text("PRAGMA table_info(token)"))
                columns = [row[1] for row in result]
                
                if 'agents' not in columns:
                    print("Adding 'agents' column to token table...")
                    
                    # Add the new column
                    connection.execute(db.text("ALTER TABLE token ADD COLUMN agents TEXT"))
                    connection.commit()
                    
                    print("✅ Successfully added 'agents' column to token table")
                    
                    # Initialize existing tokens with empty agents JSON
                    print("Initializing existing tokens with empty agents...")
                    connection.execute(db.text("UPDATE token SET agents = '{\"identity_agents\": [], \"token_agents\": [], \"compliance_agents\": []}' WHERE agents IS NULL"))
                    connection.commit()
                    
                    print("✅ Successfully initialized existing tokens with empty agents")
                else:
                    print("✅ 'agents' column already exists in token table")
                
        except Exception as e:
            print(f"❌ Error during migration: {e}")
            return False
    
    return True

if __name__ == "__main__":
    print("🚀 Starting migration: Add agents field to token table")
    success = migrate()
    if success:
        print("🎉 Migration completed successfully!")
    else:
        print("💥 Migration failed!")
        sys.exit(1) 