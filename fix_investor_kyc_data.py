#!/usr/bin/env python3
"""
Fix investor KYC data by copying from KYCRequest to User table
"""

from app import app
from models.user import User
from models.enhanced_models import KYCRequest
import json

def fix_investor_kyc_data():
    """Copy KYC data from KYCRequest to User table"""
    with app.app_context():
        print("🔧 FIXING INVESTOR KYC DATA")
        print("=" * 40)
        
        investors = User.query.filter_by(user_type='investor').all()
        print(f"Found {len(investors)} investors:")
        
        for investor in investors:
            print(f"\n👤 Investor: {investor.username}")
            print(f"   Wallet: {investor.wallet_address}")
            
            # Check if already has KYC data
            if investor.kyc_data:
                print(f"   ✅ Already has KYC data: {investor.kyc_data}")
                continue
            
            # Look for approved KYC request
            kyc_request = KYCRequest.query.filter_by(
                investor_id=investor.id, 
                status='approved'
            ).first()
            
            if kyc_request and kyc_request.kyc_data:
                print(f"   📋 Found KYC request with data: {kyc_request.kyc_data}")
                
                # Copy KYC data to User
                investor.kyc_data = kyc_request.kyc_data
                print(f"   ✅ Copied KYC data to investor")
                
                # Parse and show nationality
                try:
                    kyc_data = json.loads(kyc_request.kyc_data)
                    nationality = kyc_data.get('nationality', 'Not found')
                    print(f"   🌍 Nationality: {nationality}")
                except Exception as e:
                    print(f"   ⚠️ Could not parse KYC data: {e}")
            else:
                print(f"   ❌ No approved KYC request found")
        
        # Commit changes
        try:
            from models import db
            db.session.commit()
            print(f"\n✅ All changes committed to database")
        except Exception as e:
            print(f"\n❌ Error committing changes: {e}")

if __name__ == "__main__":
    fix_investor_kyc_data()
