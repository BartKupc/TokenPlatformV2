#!/usr/bin/env python3
"""
Migration script to add the 'role' field to the onchainid_keys table.
This field will store descriptive role names for OnchainID keys.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from sqlalchemy import text

def migrate():
    """Add role field to onchainid_keys table"""
    with app.app_context():
        try:
            # Check if the column already exists
            with db.engine.connect() as connection:
                result = connection.execute(text("PRAGMA table_info(onchainid_keys)"))
                columns = [row[1] for row in result]
                
                if 'role' not in columns:
                    print("Adding 'role' column to onchainid_keys table...")
                    
                    # Add the new column
                    connection.execute(text("ALTER TABLE onchainid_keys ADD COLUMN role VARCHAR(100)"))
                    connection.commit()
                    
                    print("✅ Successfully added 'role' column to onchainid_keys table")
                else:
                    print("✅ 'role' column already exists in onchainid_keys table")
                    
        except Exception as e:
            print(f"❌ Error during migration: {e}")
            return False
    
    return True

if __name__ == "__main__":
    print("🚀 Starting migration: Add role field to onchainid_keys table")
    success = migrate()
    if success:
        print("🎉 Migration completed successfully!")
    else:
        print("💥 Migration failed!")
        sys.exit(1) 