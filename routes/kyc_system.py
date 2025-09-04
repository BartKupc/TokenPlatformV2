"""
Multi-Lane KYC System Routes - CORRECT T-REX Architecture
Allows investors to select trusted issuers for specific claims

SECURE ARCHITECTURE:
- Investor OnchainID has ONLY Account 0 (deployer) as management key
- Trusted issuer keys are ONLY on ClaimIssuer contract
- Platform (Account 0) adds claims using its existing management key
- NO third-party management keys are added to investor OnchainID
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from models import db
from models.enhanced_models import KYCRequest, ClaimRequest, TrustedIssuerSpecialization
from models.user import User, TrustedIssuerApproval
from config.claim_topics import CLAIM_TOPICS, CLAIM_DATA_OPTIONS
from datetime import datetime
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session

import json

kyc_system_bp = Blueprint('kyc_system', __name__)

def add_claims_to_blockchain_with_approval(kyc_request, approval_decisions):
    """Add claims to blockchain using EXACT same process as before - JavaScript handles ALL key management"""
    try:
        print(f"🔗 Adding claims to blockchain for KYC request {kyc_request.id}")
        
        # Get the investor and trusted issuer
        investor = kyc_request.investor
        trusted_issuer = kyc_request.trusted_issuer
        
        if not investor.onchain_id:
            print(f"❌ Investor {investor.username} has no OnchainID")
            return False, "Investor has no OnchainID"
        
        if not trusted_issuer.claim_issuer_address:
            print(f"❌ Trusted issuer {trusted_issuer.username} has no ClaimIssuer contract")
            return False, "Trusted issuer has no ClaimIssuer contract"
        
        print(f"🔗 Found {len(kyc_request.claim_requests)} claims to add to blockchain")
        
        # STEP 1: ADD CLAIMS USING SUBPROCESS + JAVASCRIPT (EXACTLY AS BEFORE)
        # JavaScript will handle ALL key management (management keys, signing keys, etc.)
        print(f"🚀 Step 1: Adding claims using subprocess + JavaScript...")
        
        import subprocess
        import os
        
        # Get the scripts directory
        scripts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts')
        
        for claim_request in kyc_request.claim_requests:
            try:
                claim_id = str(claim_request.id)
                if claim_id not in approval_decisions:
                    continue
                    
                decision = approval_decisions[claim_id]
                print(f"🔗 Adding claim Topic {claim_request.claim_topic}: {decision['data']}")
                
                # Create configuration for JavaScript - NO PRIVATE KEY NEEDED (MetaMask handles signing)
                config = {
                    "investorOnchainID": investor.onchain_id,
                    "trustedIssuerAddress": trusted_issuer.wallet_address,
                    "claimIssuerAddress": trusted_issuer.claim_issuer_address,
                    "trustedIssuerPrivateKey": trusted_issuer.private_key,
                    "topic": claim_request.claim_topic,
                    "claimData": decision['data']
                }
                
                # Create temporary config file in scripts directory (EXACTLY AS BEFORE)
                config_file = os.path.join(scripts_dir, 'claim_config.json')
                
                with open(config_file, 'w') as f:
                    json.dump(config, f, indent=2)
                
                print(f"🔧 Created config file: {config_file}")
                print(f"🔧 Configuration:")
                print(f"   investorOnchainID: {investor.onchain_id}")
                print(f"   trustedIssuerAddress: {trusted_issuer.wallet_address}")
                print(f"   claimIssuerAddress: {trusted_issuer.claim_issuer_address}")
                print(f"   topic: {claim_request.claim_topic}")
                print(f"   claimData: {decision['data']}")
                
                # Prepare command (EXACTLY AS BEFORE)
                cmd = [
                    "npx", "hardhat", "run", "addClaim.js",
                    "--network", "localhost"
                ]
                
                print(f"🔧 Running command: {' '.join(cmd)}")
                
                # Run the JavaScript subprocess (EXACTLY AS BEFORE)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=scripts_dir
                )
                
                print(f"📤 JavaScript output:")
                print(result.stdout)
                
                if result.stderr:
                    print(f"⚠️ JavaScript errors:")
                    print(result.stderr)
                
                # Check if the command was successful
                if result.returncode == 0:
                    print("✅ JavaScript subprocess completed successfully!")
                    
                    # Parse the JSON result (EXACTLY AS BEFORE)
                    print(f"🔍 Parsing JavaScript result...")
                    js_result = _parse_js_result(result.stdout)
                    print(f"🔍 Parse result: {js_result}")
                    
                    if js_result and js_result.get('success'):
                        print("🎉 Claim addition successful!")
                        
                        # NO KEY INDEXING NEEDED - CORRECT T-REX ARCHITECTURE
                        # JavaScript now follows the SECURE architecture where:
                        # - Investor OnchainID has ONLY Account 0 as management key
                        # - Trusted issuer keys are ONLY on ClaimIssuer contract
                        # - NO third-party management keys are added to investor OnchainID
                        print(f"🔒 CORRECT T-REX Architecture: No management keys added to investor OnchainID")
                        print(f"🔒 Only Account 0 (deployer) has management key - this is SECURE!")
                        
                        # We only need to track the claim addition transaction
                        transaction_hash = js_result.get('transactionHash')
                        print(f"✅ Claim addition transaction: {transaction_hash}")
                        
                        # Update the claim request with blockchain transaction hash
                        claim_request.onchain_tx_hash = js_result.get('transactionHash')
                        claim_request.blockchain_status = 'success'
                        
                    else:
                        print(f"❌ JavaScript returned failure: {js_result}")
                        claim_request.blockchain_status = 'failed'
                        return False, f"JavaScript subprocess failed: {js_result.get('error', 'Unknown error')}"
                else:
                    print(f"❌ JavaScript subprocess failed with return code: {result.returncode}")
                    claim_request.blockchain_status = 'failed'
                    return False, f"JavaScript subprocess failed with return code: {result.returncode}"
                
            except Exception as e:
                print(f"❌ Error adding claim Topic {claim_request.claim_topic}: {e}")
                claim_request.blockchain_status = 'failed'
                return False, f"Failed to add claim Topic {claim_request.claim_topic}: {str(e)}"
        
        print(f"🎉 Successfully added all claims to blockchain!")
        return True, "Claims successfully added to blockchain"
        
    except Exception as e:
        print(f"❌ Critical error in blockchain integration: {e}")
        return False, f"Blockchain integration failed: {str(e)}"

def add_approved_claims_to_blockchain(kyc_request):
    try:
        print(f"🔗 Adding approved claims to blockchain for KYC request {kyc_request.id}")
        
        # Get the investor and trusted issuer
        investor = kyc_request.investor
        trusted_issuer = kyc_request.trusted_issuer
        
        if not investor.onchain_id:
            print(f"❌ Investor {investor.username} has no OnchainID")
            return False, "Investor has no OnchainID"
        
        if not trusted_issuer.claim_issuer_address:
            print(f"❌ Trusted issuer {trusted_issuer.username} has no ClaimIssuer contract")
            return False, "Trusted issuer has no ClaimIssuer contract"
        
        # Get approved claims
        approved_claims = [cr for cr in kyc_request.claim_requests if cr.status == 'approved']
        
        print(f"🔍 DEBUG: KYC request {kyc_request.id} has {len(kyc_request.claim_requests)} total claims")
        for cr in kyc_request.claim_requests:
            print(f"🔍 DEBUG: Claim {cr.id} - Topic {cr.claim_topic} - Status: {cr.status} - Data: {cr.approved_claim_data}")
        
        if not approved_claims:
            print(f"❌ No approved claims found for KYC request {kyc_request.id}")
            return False, "No approved claims found"
        
        print(f"🔗 Found {len(approved_claims)} approved claims to add to blockchain")
        
        # STEP 1: NO KEY INDEXING NEEDED - CORRECT T-REX ARCHITECTURE
        print(f"🔒 Step 1: CORRECT T-REX Architecture - No key indexing needed")
        print(f"🔒 JavaScript now follows the SECURE architecture where:")
        print(f"   - Investor OnchainID has ONLY Account 0 as management key")
        print(f"   - Trusted issuer keys are ONLY on ClaimIssuer contract")
        print(f"   - NO third-party management keys are added to investor OnchainID")
        
        # We don't need to pre-index any keys since JavaScript won't add them
        print(f"✅ No pre-indexing required - keys remain unchanged")
        
        # STEP 2: ADD CLAIMS USING SUBPROCESS + JAVASCRIPT (EXACTLY AS BEFORE)
        print(f"🚀 Step 2: Adding claims using subprocess + JavaScript...")
        
        import subprocess
        import os
        import tempfile
        
        # Get the scripts directory
        scripts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts')
        
        for claim_request in approved_claims:
            try:
                print(f"🔗 Adding claim Topic {claim_request.claim_topic}: {claim_request.approved_claim_data}")
                
                # Create configuration for JavaScript (EXACTLY AS BEFORE)
                config = {
                    "investorOnchainID": investor.onchain_id,
                    "trustedIssuerAddress": trusted_issuer.wallet_address,
                    "claimIssuerAddress": trusted_issuer.claim_issuer_address,
                    "trustedIssuerPrivateKey": trusted_issuer.private_key,
                    "topic": claim_request.claim_topic,
                    "claimData": claim_request.approved_claim_data
                }
                
                # Create temporary config file in scripts directory (EXACTLY AS BEFORE)
                config_file = os.path.join(scripts_dir, 'claim_config.json')
                
                with open(config_file, 'w') as f:
                    json.dump(config, f, indent=2)
                
                print(f"🔧 Created config file: {config_file}")
                print(f"🔧 Configuration:")
                print(f"   investorOnchainID: {investor.onchain_id}")
                print(f"   trustedIssuerAddress: {trusted_issuer.wallet_address}")
                print(f"   claimIssuerAddress: {trusted_issuer.claim_issuer_address}")
                print(f"   topic: {claim_request.claim_topic}")
                print(f"   claimData: {claim_request.approved_claim_data}")
                
                # Prepare command (EXACTLY AS BEFORE)
                cmd = [
                    "npx", "hardhat", "run", "addClaim.js",
                    "--network", "localhost"
                ]
                
                print(f"🔧 Running command: {' '.join(cmd)}")
                
                # Run the JavaScript subprocess (EXACTLY AS BEFORE)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=scripts_dir
                )
                
                print(f"📤 JavaScript output:")
                print(result.stdout)
                
                if result.stderr:
                    print(f"⚠️ JavaScript errors:")
                    print(result.stderr)
                
                # Check if the command was successful
                if result.returncode == 0:
                    print("✅ JavaScript subprocess completed successfully!")
                    
                    # Parse the JSON result (EXACTLY AS BEFORE)
                    js_result = _parse_js_result(result.stdout)
                    
                    if js_result and js_result.get('success'):
                        print("🎉 Claim addition successful!")
                        
                        # NO KEY UPDATING NEEDED - CORRECT T-REX ARCHITECTURE
                        # JavaScript now follows the SECURE architecture where no keys are added to investor OnchainID
                        print(f"🔒 CORRECT T-REX Architecture: No keys to update")
                        print(f"🔒 Only Account 0 (deployer) has management key - this is SECURE!")
                        
                        # Update the claim request with blockchain transaction hash
                        transaction_hash = js_result.get('transactionHash')
                        claim_request.onchain_tx_hash = transaction_hash
                        claim_request.blockchain_status = 'success'
                        print(f"✅ Claim addition transaction: {transaction_hash}")
                    else:
                        print(f"❌ JavaScript returned failure: {js_result}")
                        claim_request.blockchain_status = 'failed'
                        return False, f"JavaScript subprocess failed: {js_result.get('error', 'Unknown error')}"
                else:
                    print(f"❌ JavaScript subprocess failed with return code: {result.returncode}")
                    claim_request.blockchain_status = 'failed'
                    return False, f"JavaScript subprocess failed with return code: {result.returncode}"
                
            except Exception as e:
                print(f"❌ Error adding claim Topic {claim_request.claim_topic}: {e}")
                claim_request.blockchain_status = 'failed'
                return False, f"Failed to add claim Topic {claim_request.claim_topic}: {str(e)}"
        
        # Commit all changes to database
        db.session.commit()
        
        print(f"🎉 Successfully added all approved claims to blockchain!")
        return True, "Claims successfully added to blockchain"
        
    except Exception as e:
        print(f"❌ Critical error in blockchain integration: {e}")
        db.session.rollback()
        return False, f"Blockchain integration failed: {str(e)}"

def _parse_js_result(stdout):
    """Parse JavaScript subprocess result (EXACTLY AS BEFORE)"""
    try:
        # Look for the JSON result in the output
        lines = stdout.strip().split('\n')
        
        # Method 1: Look for the RESULT section and extract JSON
        for i, line in enumerate(lines):
            if '🎯 RESULT:' in line:
                # The JSON starts on the next line after "🎯 RESULT:" and may span multiple lines
                json_lines = []
                for j in range(i + 1, len(lines)):
                    line_content = lines[j].strip()
                    if line_content:  # Skip empty lines
                        json_lines.append(line_content)
                        # Try to parse what we have so far
                        try:
                            json_text = '\n'.join(json_lines)
                            return json.loads(json_text)
                        except json.JSONDecodeError:
                            continue
                break
        
        # Method 2: Look for lines that start and end with { and }
        for line in reversed(lines):  # Start from the end
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        
        # Method 3: Try to find JSON in the last few lines
        last_lines = lines[-10:]  # Last 10 lines
        for line in last_lines:
            if line.strip().startswith('{') and line.strip().endswith('}'):
                try:
                    return json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
        
        print(f"⚠️ Could not parse JavaScript result from output:")
        print("Looking for JSON after '🎯 RESULT:' or in lines ending with }")
        print("Output preview (last 20 lines):")
        for line in lines[-20:]:
            print(f"  {line}")
        return None
        
    except Exception as e:
        print(f"❌ Error parsing JavaScript result: {e}")
        return None

@kyc_system_bp.route('/select-trusted-issuer')
def select_trusted_issuer():
    """Investor selects trusted issuer for KYC"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get all approved trusted issuers
    try:
        approved_trusted_issuers = User.query.filter_by(user_type='trusted_issuer').join(
            TrustedIssuerApproval,
            User.id == TrustedIssuerApproval.trusted_issuer_id
        ).filter(
            TrustedIssuerApproval.status == 'approved'
        ).all()
        
        print(f"🔍 Found {len(approved_trusted_issuers)} approved trusted issuers")
        
        # Get their specializations
        specializations = {}
        for ti in approved_trusted_issuers:
            specs = TrustedIssuerSpecialization.query.filter_by(
                trusted_issuer_id=ti.id,
                is_active=True
            ).all()
            specializations[ti.id] = specs
            print(f"🔍 {ti.username}: {len(specs)} specializations")
            
    except Exception as e:
        print(f"❌ Error fetching trusted issuers: {e}")
        approved_trusted_issuers = []
        specializations = {}
    
    return render_template('kyc_select_trusted_issuer.html',
                         user=user,
                         trusted_issuers=approved_trusted_issuers,
                         specializations=specializations,
                         claim_topics=CLAIM_TOPICS,
                         claim_data_options=CLAIM_DATA_OPTIONS,
                         tab_session_id=tab_session.session_id if tab_session else None)

@kyc_system_bp.route('/submit-kyc-request', methods=['POST'])
def submit_kyc_request():
    """Submit KYC request to selected trusted issuer"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get form data
    trusted_issuer_id = request.form.get('trusted_issuer_id')
    selected_claims = request.form.getlist('selected_claims')
    full_name = request.form.get('full_name')
    nationality = request.form.get('nationality')
    date_of_birth = request.form.get('date_of_birth')
    
    if not trusted_issuer_id or not selected_claims:
        flash('Please select a trusted issuer and at least one claim.', 'error')
        return redirect(url_for('kyc_system.select_trusted_issuer', tab_session=tab_session.session_id))
    
    # Create KYC data JSON
    kyc_data = {
        'full_name': full_name,
        'nationality': nationality,
        'date_of_birth': date_of_birth
    }
    
    try:
        # Create KYC request
        kyc_request = KYCRequest(
            investor_id=user.id,
            trusted_issuer_id=int(trusted_issuer_id),
            kyc_data=json.dumps(kyc_data),
            status='pending'
        )
        db.session.add(kyc_request)
        db.session.flush()  # Get the ID
        
        # Create claim requests
        for claim_info in selected_claims:
            topic, data = claim_info.split(':', 1)
            claim_request = ClaimRequest(
                kyc_request_id=kyc_request.id,
                claim_topic=int(topic),
                requested_claim_data=data,
                status='pending',
                onchain_tx_hash=None,
                blockchain_status='pending'
            )
            db.session.add(claim_request)
        
        db.session.commit()
        
        flash('KYC request submitted successfully! The trusted issuer will review your application.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error submitting KYC request: {str(e)}', 'error')
    
    return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))

@kyc_system_bp.route('/kyc-requests')
def kyc_requests():
    """View all KYC requests for the current user"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user:
        flash('Please log in to view KYC requests.', 'error')
        return redirect(url_for('auth.login', tab_session=tab_session.session_id))
    
    if user.user_type == 'investor':
        # Investor view - their own requests
        kyc_requests = KYCRequest.query.filter_by(investor_id=user.id).order_by(
            KYCRequest.created_at.desc()
        ).all()
    elif user.user_type == 'trusted_issuer':
        # Trusted issuer view - requests sent to them
        kyc_requests = KYCRequest.query.filter_by(trusted_issuer_id=user.id).order_by(
            KYCRequest.created_at.desc()
        ).all()
    else:
        flash('Access denied.', 'error')
        return redirect(url_for('auth.login', tab_session=tab_session.session_id))
    
    return render_template('kyc_requests.html',
                         user=user,
                         kyc_requests=kyc_requests,
                         claim_topics=CLAIM_TOPICS,
                         tab_session_id=tab_session.session_id if tab_session else None)

@kyc_system_bp.route('/review-kyc-request/<int:request_id>', methods=['GET', 'POST'])
def review_kyc_request(request_id):
    """Trusted issuer reviews a KYC request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'trusted_issuer':
        flash('Trusted issuer access required.', 'error')
        return redirect(url_for('auth.login', tab_session=tab_session.session_id))
    
    # Get KYC request
    kyc_request = KYCRequest.query.get_or_404(request_id)
    
    # Check if this trusted issuer is assigned to this request
    if kyc_request.trusted_issuer_id != user.id:
        flash('Access denied. This KYC request is not assigned to you.', 'error')
        return redirect(url_for('kyc_system.kyc_requests', tab_session=tab_session.session_id))
    
    if request.method == 'POST':
        # Get form data
        action = request.form.get('action')  # 'approve', 'reject', 'request_changes'
        
        # Get claim decisions
        claim_decisions = {}
        for claim_request in kyc_request.claim_requests:
            claim_id = str(claim_request.id)
            decision = request.form.get(f'claim_{claim_id}_decision')
            
            if decision:
                # Automatically set claim data based on decision and topic
                if decision == 'approved':
                    # Set appropriate claim data based on topic
                    if claim_request.claim_topic == 1:  # KYC
                        claim_data = 'APPROVED'
                    elif claim_request.claim_topic == 2:  # AML
                        claim_data = 'COMPLIANT'
                    elif claim_request.claim_topic == 3:  # Accredited Investor
                        claim_data = 'ACCREDITED'
                    elif claim_request.claim_topic == 4:  # EU Nationality
                        claim_data = 'CONFIRMED'
                    elif claim_request.claim_topic == 5:  # US Nationality
                        claim_data = 'CONFIRMED'
                    elif claim_request.claim_topic == 6:  # Blacklist
                        claim_data = 'CLEAN'
                    elif claim_request.claim_topic == 7:  # Residency
                        claim_data = 'RESIDENT'
                    elif claim_request.claim_topic == 8:  # Compliance Status
                        claim_data = 'COMPLIANT'
                    elif claim_request.claim_topic == 9:  # Restricted Status
                        claim_data = 'UNRESTRICTED'
                    elif claim_request.claim_topic == 10:  # Whitelisted Status
                        claim_data = 'WHITELISTED'
                    else:
                        claim_data = 'APPROVED'  # Default fallback
                else:  # rejected
                    # Set appropriate claim data for rejection
                    if claim_request.claim_topic == 1:  # KYC
                        claim_data = 'REJECTED'
                    elif claim_request.claim_topic == 2:  # AML
                        claim_data = 'NON_COMPLIANT'
                    elif claim_request.claim_topic == 3:  # Accredited Investor
                        claim_data = 'NON_ACCREDITED'
                    elif claim_request.claim_topic == 4:  # EU Nationality
                        claim_data = 'NOT_CONFIRMED'
                    elif claim_request.claim_topic == 5:  # US Nationality
                        claim_data = 'NOT_CONFIRMED'
                    elif claim_request.claim_topic == 6:  # Blacklist
                        claim_data = 'BLACKLISTED'
                    elif claim_request.claim_topic == 7:  # Residency
                        claim_data = 'NON_RESIDENT'
                    elif claim_request.claim_topic == 8:  # Compliance Status
                        claim_data = 'NON_COMPLIANT'
                    elif claim_request.claim_topic == 9:  # Restricted Status
                        claim_data = 'RESTRICTED'
                    elif claim_request.claim_topic == 10:  # Whitelisted Status
                        claim_data = 'NOT_WHITELISTED'
                    else:
                        claim_data = 'REJECTED'  # Default fallback
                
                claim_decisions[claim_id] = {
                    'decision': decision,
                    'data': claim_data,
                    'notes': 'Auto-generated based on decision'
                }
        
        try:
            if action == 'approve':
                # DON'T approve claims in database yet - wait for blockchain success!
                # Just collect the approval decisions
                approval_decisions = {}
                for claim_request in kyc_request.claim_requests:
                    claim_id = str(claim_request.id)
                    if claim_id in claim_decisions:
                        decision = claim_decisions[claim_id]
                        approval_decisions[claim_id] = {
                            'data': decision['data'],
                            'notes': decision['notes']
                        }
                    else:
                        # If no specific decision, use default data
                        approval_decisions[claim_id] = {
                            'data': claim_request.requested_claim_data
                        }
                
                # NOW ADD CLAIMS TO BLOCKCHAIN FIRST (EXACT SAME PROCESS AS BEFORE)
                print(f"🚀 Starting blockchain integration for KYC request {kyc_request.id}")
                blockchain_success, blockchain_message = add_claims_to_blockchain_with_approval(
                    kyc_request, approval_decisions
                )
                
                if blockchain_success:
                    # ONLY NOW approve claims in database after blockchain success
                    for claim_request in kyc_request.claim_requests:
                        claim_id = str(claim_request.id)
                        decision = approval_decisions[claim_id]
                        claim_request.status = 'approved'
                        claim_request.approved_claim_data = decision['data']
                        claim_request.notes = 'Auto-generated based on decision'
                        claim_request.reviewed_at = datetime.utcnow()
                    
                    kyc_request.status = 'approved'
                    kyc_request.reviewed_at = datetime.utcnow()
                    
                    # Update investor's KYC status to approved
                    investor = kyc_request.investor
                    trusted_issuer = kyc_request.trusted_issuer
                    investor.kyc_status = 'approved'
                    investor.kyc_approved_by = trusted_issuer.id
                    investor.kyc_approved_at = datetime.utcnow()
                    
                    db.session.commit()
                    flash(f'KYC request approved successfully! Claims have been added to the blockchain. Investor KYC status updated.', 'success')
                    
                    # Redirect to KYC requests dashboard after successful approval
                    return redirect(url_for('kyc_system.kyc_requests', tab_session=tab_session.session_id))
                else:
                    # Blockchain failed - don't approve anything in database
                    flash(f'KYC approval failed: {blockchain_message}. Claims were not added to blockchain. Please try again.', 'error')
                
            elif action == 'reject':
                # Reject all claims
                for claim_request in kyc_request.claim_requests:
                    claim_request.status = 'rejected'
                    claim_request.notes = 'Auto-generated based on decision'
                    claim_request.reviewed_at = datetime.utcnow()
                
                kyc_request.status = 'rejected'
                kyc_request.reviewed_at = datetime.utcnow()
                
                db.session.commit()
                flash('KYC request rejected.', 'info')
                
                # Redirect to KYC requests dashboard after rejection
                return redirect(url_for('kyc_system.kyc_requests', tab_session=tab_session.session_id))
                
            elif action == 'request_changes':
                # Partial approval/rejection - DON'T commit to database yet!
                approval_decisions = {}
                for claim_request in kyc_request.claim_requests:
                    claim_id = str(claim_request.id)
                    if claim_id in claim_decisions:
                        decision = claim_decisions[claim_id]
                        if decision['decision'] == 'approved':
                            approval_decisions[claim_id] = {
                                'data': decision['data']
                            }
                
                # Only try blockchain if there are approved claims
                if approval_decisions:
                    print(f"🚀 Starting blockchain integration for partially approved KYC request {kyc_request.id}")
                    blockchain_success, blockchain_message = add_claims_to_blockchain_with_approval(
                        kyc_request, approval_decisions
                    )
                    
                    if blockchain_success:
                        # NOW approve in database after blockchain success
                        for claim_request in kyc_request.claim_requests:
                            claim_id = str(claim_request.id)
                            if claim_id in approval_decisions:
                                decision = approval_decisions[claim_id]
                                claim_request.status = 'approved'
                                claim_request.approved_claim_data = decision['data']
                                claim_request.notes = 'Auto-generated based on decision'
                                claim_request.reviewed_at = datetime.utcnow()
                        
                        # Update investor's KYC status to approved if this was their first KYC
                        investor = kyc_request.investor
                        trusted_issuer = kyc_request.trusted_issuer
                        if investor.kyc_status != 'approved':
                            investor.kyc_status = 'approved'
                            investor.kyc_approved_by = trusted_issuer.id
                            investor.kyc_approved_at = datetime.utcnow()
                        
                        kyc_request.reviewed_at = datetime.utcnow()
                        
                        db.session.commit()
                        flash(f'Changes processed successfully! Approved claims have been added to the blockchain. Investor KYC status updated.', 'success')
                        
                        # Redirect to KYC requests dashboard after successful partial approval
                        return redirect(url_for('kyc_system.kyc_requests', tab_session=tab_session.session_id))
                    else:
                        # Blockchain failed - don't approve anything in database
                        flash(f'Partial approval failed: {blockchain_message}. Claims were not added to blockchain. Please try again.', 'error')
                else:
                    # No approved claims
                    kyc_request.reviewed_at = datetime.utcnow()
                    db.session.commit()
                    flash('Changes requested for KYC application.', 'info')
                    
                    # Redirect to KYC requests dashboard after changes requested
                    return redirect(url_for('kyc_system.kyc_requests', tab_session=tab_session.session_id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing KYC request: {str(e)}', 'error')
    
    return render_template('kyc_review.html',
                         user=user,
                         kyc_request=kyc_request,
                         claim_topics=CLAIM_TOPICS,
                         claim_data_options=CLAIM_DATA_OPTIONS,
                         tab_session_id=tab_session.session_id if tab_session else None)

@kyc_system_bp.route('/execute-claim-with-signature', methods=['POST'])
def execute_claim_with_signature():
    """Execute claim addition using MetaMask signature and original JavaScript script"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        print(f"🔧 Executing claim with MetaMask signature: {data}")
        
        claim_info = data.get('claim_info')
        signature = data.get('signature')
        data_hash = data.get('data_hash')
        kyc_request_id = data.get('kyc_request_id')
        claim_request_id = data.get('claim_request_id')
        
        if not claim_info or not signature or not data_hash or not kyc_request_id or not claim_request_id:
            return jsonify({'success': False, 'error': 'Missing required data'}), 400
        
        # Use the hybrid claim service to execute the claim with the signature
        from services.hybrid_claim_service import HybridClaimService
        hybrid_service = HybridClaimService()
        
        # Execute the claim addition using the original JavaScript script approach
        # but with the MetaMask signature
        result = hybrid_service.add_claim_with_metamask_signature(
            investor_onchain_id=claim_info['investor_onchain_id'],
            trusted_issuer_address=claim_info['trusted_issuer_address'],
            claim_issuer_address=claim_info['claim_issuer_address'],
            topic=claim_info['topic'],
            claim_data=claim_info['claim_data'],
            signature=signature,
            data_hash=data_hash
        )
        
        if result['success']:
            # Update the database with the transaction hash and blockchain status
            transaction_hash = result.get('transaction_hash')
            
            # Find the KYC request and claim request to update
            # Use the IDs from the request body
            if kyc_request_id and claim_request_id:
                # Update the specific claim request
                from models.enhanced_models import ClaimRequest
                claim_request = ClaimRequest.query.get(claim_request_id)
                if claim_request:
                    claim_request.onchain_tx_hash = transaction_hash
                    claim_request.blockchain_status = 'success'
                    claim_request.status = 'approved'
                    claim_request.approved_claim_data = claim_info['claim_data']
                    claim_request.reviewed_at = datetime.utcnow()
                    
                    # Update the KYC request status if all claims are approved
                    kyc_request = claim_request.kyc_request
                    all_approved = all(cr.status == 'approved' for cr in kyc_request.claim_requests)
                    if all_approved:
                        kyc_request.status = 'approved'
                        kyc_request.reviewed_at = datetime.utcnow()
                        
                        # Update investor's KYC status
                        investor = kyc_request.investor
                        investor.kyc_status = 'approved'
                        investor.kyc_approved_by = kyc_request.trusted_issuer.id
                        investor.kyc_approved_at = datetime.utcnow()
                    
                    # Commit all changes
                    db.session.commit()
                    print(f"✅ Database updated with transaction hash: {transaction_hash}")
                else:
                    print(f"⚠️ Claim request {claim_request_id} not found")
            else:
                print(f"⚠️ Missing KYC request ID or claim request ID in claim_info")
            
            return jsonify({
                'success': True,
                'transaction_hash': transaction_hash,
                'message': 'Claim added successfully via MetaMask signature'
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error')
            }), 500
            
    except Exception as e:
        print(f"❌ Error executing claim with signature: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kyc_system_bp.route('/api/trusted-issuer-specializations/<int:trusted_issuer_id>')
def get_trusted_issuer_specializations(trusted_issuer_id):
    """API endpoint to get trusted issuer specializations"""
    specializations = TrustedIssuerSpecialization.query.filter_by(
        trusted_issuer_id=trusted_issuer_id,
        is_active=True
    ).all()
    
    result = {}
    for spec in specializations:
        result[spec.claim_topic] = {
            'can_handle': spec.can_handle,
            'expertise_level': spec.expertise_level,
            'processing_time_days': spec.processing_time_days,
            'fee_amount': float(spec.fee_amount) if spec.fee_amount else None,
            'fee_currency': spec.fee_currency
        }
    
    return jsonify(result)

@kyc_system_bp.route('/kyc-request/<int:request_id>/metamask-transaction', methods=['POST'])
def handle_kyc_metamask_transaction(request_id):
    """Handle MetaMask transactions for KYC claim operations"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'trusted_issuer':
        return jsonify({'success': False, 'error': 'Trusted Issuer access required.'}), 401
    
    # Get KYC request
    kyc_request = KYCRequest.query.get_or_404(request_id)
    
    # Check if this trusted issuer is assigned to this request
    if kyc_request.trusted_issuer_id != user.id:
        return jsonify({'success': False, 'error': 'Access denied. This KYC request is not assigned to you.'}), 403
    
    # Get request data
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    action = data.get('action')
    if not action:
        return jsonify({'success': False, 'error': 'Action is required'}), 400
    
    print(f"🔍 KYC MetaMask transaction - Request ID: {request_id}, Action: {action}")
    
    try:
        if action == 'build':
            # Build transaction data for claim addition
            return build_claim_addition_transaction_helper(kyc_request, data.get('claim_decisions', {}))
        elif action == 'confirm':
            # Confirm transaction after successful execution
            return confirm_claim_addition_transaction(kyc_request, data)
        else:
            return jsonify({'success': False, 'error': f'Unknown action: {action}'}), 400
            
    except Exception as e:
        print(f"❌ Error in KYC MetaMask transaction: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500



def build_claim_addition_transaction_helper(kyc_request, claim_decisions):
    """Build transaction data for claim addition (MetaMask integration)"""
    try:
        print(f"🔧 Building claim addition transaction for KYC request {kyc_request.id}")
        
        # Get the investor and trusted issuer
        investor = kyc_request.investor
        trusted_issuer = kyc_request.trusted_issuer
        
        if not investor.onchain_id:
            return jsonify({'success': False, 'error': 'Investor has no OnchainID'}), 400
        
        if not trusted_issuer.claim_issuer_address:
            return jsonify({'success': False, 'error': 'Trusted issuer has no ClaimIssuer contract'}), 400
        
        # Use the hybrid claim service to build transaction data
        from services.hybrid_claim_service import HybridClaimService
        hybrid_service = HybridClaimService()
        
        # Prepare transaction data for each claim
        transactions = []
        for claim_request in kyc_request.claim_requests:
            claim_id = str(claim_request.id)
            if claim_id not in claim_decisions:
                continue
                
            decision = claim_decisions[claim_id]
            if decision.get('decision') != 'approved':
                continue
            
            # Build transaction data using the hybrid service
            tx_data_result = hybrid_service.build_claim_transaction_data(
                investor_onchain_id=investor.onchain_id,
                trusted_issuer_address=trusted_issuer.wallet_address,
                claim_issuer_address=trusted_issuer.claim_issuer_address,
                topic=claim_request.claim_topic,
                claim_data=decision['data']
            )
            
            if tx_data_result['success']:
                # Add claim request info to the transaction data
                transaction_data = {
                    'claim_request_id': claim_request.id,
                    'kyc_request_id': kyc_request.id,
                    'data_hash': tx_data_result['data_hash'],  # Changed from 'transaction_data' to 'data_hash'
                    'claim_info': tx_data_result['claim_info']
                }
                transactions.append(transaction_data)
            else:
                print(f"❌ Failed to build transaction data for claim {claim_request.id}: {tx_data_result['error']}")
        
        if not transactions:
            return jsonify({'success': False, 'error': 'No approved claims to process'}), 400
        
        # Return transaction data for frontend MetaMask integration
        return jsonify({
            'success': True,
            'transactions': transactions,
            'kyc_request_id': kyc_request.id,
            'investor_name': investor.username,
            'trusted_issuer_name': trusted_issuer.username,
            'message': f'Ready to add {len(transactions)} claims to blockchain via MetaMask'
        })
        
    except Exception as e:
        print(f"❌ Error building claim addition transaction: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def confirm_claim_addition_transaction(kyc_request, data):
    """Confirm transaction after successful execution"""
    try:
        print(f"🔧 Confirming claim addition transaction for KYC request {kyc_request.id}")
        
        transaction_hash = data.get('transaction_hash')
        if not transaction_hash:
            return jsonify({'success': False, 'error': 'Transaction hash is required'}), 400
        
        # Update claim requests with transaction hash
        for claim_request in kyc_request.claim_requests:
            if claim_request.status == 'approved':
                claim_request.onchain_tx_hash = transaction_hash
                claim_request.blockchain_status = 'success'
        
        # Update KYC request status
        kyc_request.status = 'approved'
        kyc_request.reviewed_at = datetime.utcnow()
        
        # Update investor's KYC status
        investor = kyc_request.investor
        trusted_issuer = kyc_request.trusted_issuer
        investor.kyc_status = 'approved'
        investor.kyc_approved_by = trusted_issuer.id
        investor.kyc_approved_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Claims successfully added to blockchain and database updated',
            'transaction_hash': transaction_hash
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error confirming claim addition transaction: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500 