#!/usr/bin/env python3
"""
Quick script to check what nationality data is stored in the database
"""

from app import app
from models import User
import json

def check_kyc_nationalities():
    """Check what nationality data is stored for investors"""
    with app.app_context():
        print("🔍 CHECKING KYC NATIONALITY DATA")
        print("=" * 40)
        
        investors = User.query.filter_by(user_type='investor').all()
        print(f"Found {len(investors)} investors:")
        
        for investor in investors:
            print(f"\n👤 Investor: {investor.username}")
            print(f"   Wallet: {investor.wallet_address}")
            
            if hasattr(investor, 'kyc_data') and investor.kyc_data:
                try:
                    kyc_data = json.loads(investor.kyc_data) if isinstance(investor.kyc_data, str) else investor.kyc_data
                    nationality = kyc_data.get('nationality', 'Not provided')
                    print(f"   📋 KYC Nationality: '{nationality}'")
                    print(f"   📋 KYC Data: {kyc_data}")
                except Exception as e:
                    print(f"   ❌ Error parsing KYC data: {e}")
            else:
                print(f"   ❌ No KYC data found")
                
            # Check if there's a standardized_nationality field
            if hasattr(investor, 'standardized_nationality'):
                print(f"   📋 Standardized Nationality: '{investor.standardized_nationality}'")

if __name__ == "__main__":
    check_kyc_nationalities()
