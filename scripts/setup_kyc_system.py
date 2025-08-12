#!/usr/bin/env python3
"""
Setup script for the new Multi-Lane KYC System
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models.enhanced_models import TrustedIssuerSpecialization
from models.user import User, TrustedIssuerApproval

def setup_kyc_system():
    """Set up the new KYC system with initial data"""
    with app.app_context():
        print("🔧 Setting up Multi-Lane KYC System...")
        
        # Get all approved trusted issuers
        approved_trusted_issuers = User.query.filter_by(user_type='trusted_issuer').join(
            TrustedIssuerApproval
        ).filter(
            TrustedIssuerApproval.status == 'approved'
        ).all()
        
        if not approved_trusted_issuers:
            print("⚠️  No approved trusted issuers found.")
            return
        
        print(f"✅ Found {len(approved_trusted_issuers)} approved trusted issuers")
        
        # T-REX Standard Claim Topics
        claim_topics = {
            1: 'KYC (Know Your Customer)',
            2: 'AML (Anti-Money Laundering)', 
            3: 'Accredited Investor',
            4: 'EU Nationality Confirmed',
            5: 'US Nationality Confirmed',
            6: 'Blacklist',
            7: 'Residency',
            8: 'Compliance Status',
            9: 'Restricted Status',
            10: 'Whitelisted Status'
        }
        
        for trusted_issuer in approved_trusted_issuers:
            print(f"🔧 Setting up specializations for {trusted_issuer.username}...")
            
            # Check if specializations already exist
            existing_specs = TrustedIssuerSpecialization.query.filter_by(
                trusted_issuer_id=trusted_issuer.id
            ).count()
            
            if existing_specs > 0:
                print(f"   ⚠️  Specializations already exist, skipping...")
                continue
            
            # Create specializations for all 10 topics
            for topic_id, topic_name in claim_topics.items():
                import random
                expertise_levels = ['basic', 'standard', 'expert']
                expertise_level = random.choice(expertise_levels)
                processing_time = random.randint(1, 7)
                
                # Add fees for certain topics
                fee_amount = None
                if topic_id in [1, 2, 3]:
                    fee_amount = random.uniform(50.0, 200.0)
                
                specialization = TrustedIssuerSpecialization(
                    trusted_issuer_id=trusted_issuer.id,
                    claim_topic=topic_id,
                    can_handle=True,
                    expertise_level=expertise_level,
                    processing_time_days=processing_time,
                    fee_amount=fee_amount,
                    fee_currency='USD',
                    is_active=True
                )
                
                db.session.add(specialization)
                print(f"   ✅ Added Topic {topic_id}: {topic_name}")
            
            db.session.commit()
        
        print("\n🎉 Multi-Lane KYC System setup complete!")

if __name__ == '__main__':
    setup_kyc_system() 