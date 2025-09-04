from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from models import db
from models.user import User, TrustedIssuerApproval, UserOnchainID, UserClaim
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session
from utils.auth_utils import hash_password
from services.onchainid_service import OnchainIDService
from services.web3_service import Web3Service
from config.claim_topics import get_all_topics
import json
from datetime import datetime
from services.onchainid_key_manager import OnchainIDKeyManager
from services.transaction_indexer import TransactionIndexer
from models.enhanced_models import OnchainIDKey

# Import the shared MetaMask handler
from utils.metamask_handler import handle_metamask_transaction_core

def standardize_nationality(nationality_input):
    """Standardize nationality input to blockchain-compatible values"""
    if not nationality_input:
        return "UNKNOWN"
    
    # Convert to lowercase for comparison
    nationality_lower = nationality_input.lower().strip()
    
    # US variations
    if nationality_lower in ['us', 'usa', 'united states', 'united states of america', 'america']:
        return "US"
    
    # EU variations
    elif nationality_lower in ['eu', 'europe', 'european union', 'european']:
        return "EU"
    
    # Asia variations
    elif nationality_lower in ['asia', 'asian', 'as']:
        return "ASIA"
    
    # UK variations
    elif nationality_lower in ['uk', 'united kingdom', 'britain', 'british', 'england']:
        return "UK"
    
    # Canada
    elif nationality_lower in ['ca', 'canada', 'canadian']:
        return "CA"
    
    # Australia
    elif nationality_lower in ['au', 'australia', 'australian']:
        return "AU"
    
    # Default to US for now (you can expand this list)
    else:
        return "US"

trusted_issuer_bp = Blueprint('trusted_issuer', __name__, url_prefix='/trusted-issuer')

@trusted_issuer_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Trusted Issuer login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('trusted_issuer_login.html')
        
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Check credentials
        user = User.query.filter_by(username=username, user_type='trusted_issuer').first()
        if user and user.password_hash == hash_password(password):
            from utils.session_utils import login_user_to_tab_session
            login_user_to_tab_session(tab_session.session_id, user)
            flash('Login successful!', 'success')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        else:
            flash('Invalid credentials.', 'error')
    
    return render_template('trusted_issuer_login.html')

@trusted_issuer_bp.route('/dashboard')
def dashboard():
    """Trusted Issuer dashboard"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'trusted_issuer':
        flash('Trusted Issuer access required.', 'error')
        return redirect(url_for('trusted_issuer.login', tab_session=tab_session.session_id))
    
    # Get pending KYC requests
    pending_kyc = User.query.filter_by(user_type='investor', kyc_status='pending').all()
    
    # Get user's approval status
    approval = TrustedIssuerApproval.query.filter_by(trusted_issuer_id=user.id).first()
    
    # Add standardized nationality for each pending KYC
    for investor in pending_kyc:
        if investor.kyc_data:
            try:
                kyc_data = json.loads(investor.kyc_data)
                investor.standardized_nationality = standardize_nationality(kyc_data.get('nationality', ''))
            except:
                investor.standardized_nationality = "US"
        else:
            investor.standardized_nationality = "US"
    
    return render_template('trusted_issuer_dashboard.html',
                         user=user,
                         pending_kyc=pending_kyc,
                         approval=approval,
                         tab_session_id=tab_session.session_id)

# Legacy KYC approval route removed - now using kyc_system.review_kyc_request

@trusted_issuer_bp.route('/step1-add-issuer/<int:user_id>', methods=['POST'])
def step1_add_issuer(user_id):
    """Step 1: Add Claim Issuer to investor's OnchainID"""
    print(f"🚀 Step 1: Adding Claim Issuer to investor's OnchainID for user_id: {user_id}")
    
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    trusted_issuer = get_current_user_from_tab_session(tab_session.session_id)
    
    if not trusted_issuer or trusted_issuer.user_type != 'trusted_issuer':
        flash('Trusted Issuer access required.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    # Check if trusted issuer is approved
    approval = TrustedIssuerApproval.query.filter_by(trusted_issuer_id=trusted_issuer.id).first()
    if not approval or approval.status != 'approved':
        flash('Your trusted issuer capabilities must be approved by admin first.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get investor
    investor = User.query.get_or_404(user_id)
    print(f"🔍 Investor: {investor.username} (type: {investor.user_type})")
    
    if investor.user_type != 'investor':
        error_msg = f"❌ Only investors can have KYC approved. User type: {investor.user_type}"
        print(error_msg)
        flash('Only investors can have KYC approved.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    try:
        # Check if investor has OnchainID
        print(f"🔍 Investor OnchainID: {investor.onchain_id}")
        
        if not investor.onchain_id:
            error_msg = f"❌ Investor {investor.username} does not have an OnchainID"
            print(error_msg)
            flash(f'Investor {investor.username} does not have an OnchainID. Please ensure registration completed successfully.', 'error')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        
        # Check if trusted issuer has OnchainID
        print(f"🔍 Trusted Issuer OnchainID: {trusted_issuer.onchain_id}")
        
        if not trusted_issuer.onchain_id:
            error_msg = f"❌ Trusted Issuer {trusted_issuer.username} does not have an OnchainID"
            print(error_msg)
            flash(f'Trusted Issuer {trusted_issuer.username} does not have an OnchainID. Please contact admin.', 'error')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        
        # Initialize services
        from services.onchainid_service import OnchainIDService
        from services.web3_service import Web3Service
        from eth_account import Account
        
        # Use Account 0 (admin/deployer) to add keys - this account has management permissions
        account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        account_0_wallet = Account.from_key(account_0_private_key)
        
        print(f"🔧 Using Account 0 (admin) to add keys: {account_0_wallet.address}")
        
        # Create Web3Service with Account 0's key
        web3_service = Web3Service(private_key=account_0_private_key)
        
        # Create OnchainIDService
        onchainid_service = OnchainIDService(web3_service)
        
        # CORRECT T-REX ARCHITECTURE: NO MANAGEMENT KEYS ADDED TO INVESTOR ONCHAINID
        print(f"🔒 CORRECT T-REX Architecture: No management keys added to investor OnchainID")
        print(f"🔒 Only Account 0 (deployer) has management key - this is SECURE!")
        
        # Verify Account 0 has management key (should exist from OnchainID creation)
        print(f"🔍 Verifying Account 0 has management key on investor's OnchainID...")
        signer_key_hash = web3_service.w3.keccak(
            web3_service.w3.codec.encode(['address'], [account_0_wallet.address])
        )
        print(f"🔍 Account 0 key hash: {signer_key_hash.hex()}")
        
        try:
            signer_key = web3_service.call_contract_function(
                'Identity',
                investor.onchain_id,
                'getKey',
                signer_key_hash
            )
            purposes = signer_key[0] if isinstance(signer_key[0], list) else [signer_key[0]]
            has_management_key = 1 in purposes
            print(f"🔍 Account 0 has management key: {has_management_key}")
            
            if not has_management_key:
                error_msg = f"❌ SECURITY VIOLATION: Account 0 (deployer) must have management key on investor OnchainID!"
                print(error_msg)
                flash('Security violation: Account 0 must have management key on investor OnchainID.', 'error')
                return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
            else:
                print(f"✅ Account 0 has management key - SECURE!")
                
        except Exception as e:
            error_msg = f"❌ Error verifying Account 0 management key: {e}"
            print(error_msg)
            flash('Error verifying Account 0 management key.', 'error')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        
        # CORRECT T-REX ARCHITECTURE: NO MANAGEMENT KEYS ADDED TO INVESTOR ONCHAINID
        print(f"🔒 SECURITY: Investor OnchainID will ONLY have Account 0 as management key")
        print(f"🔒 Trusted issuer keys are ONLY on ClaimIssuer contract")
        print(f"🔒 Platform (Account 0) will add claims using existing management key")
        
        # Redirect to the new multi-lane KYC system
        print(f"🔄 Redirecting to new multi-lane KYC system...")
        flash(f'✅ Account 0 management key verified for {investor.username}. Please use the new multi-lane KYC system to add claims.', 'success')
        
        # Redirect to the new KYC system
        return redirect(url_for('kyc_system.select_trusted_issuer', tab_session=tab_session.session_id))
        
    except Exception as e:
        print(f"❌ Error in Step 1: {str(e)}")
        flash(f'Error in Step 1: {str(e)}', 'error')
    
    return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))

@trusted_issuer_bp.route('/step2-add-claims/<int:user_id>', methods=['POST'])
def step2_add_claims(user_id):
    """Step 2: Add claims to investor's OnchainID - CORRECT T-REX Architecture
    
    This function now redirects to the new multi-lane KYC system which follows the SECURE architecture:
    - Investor OnchainID has ONLY Account 0 (deployer) as management key
    - Trusted issuer keys are ONLY on ClaimIssuer contract
    - NO third-party management keys are added to investor OnchainID
    """
    print(f"🚀 Step 2: Redirecting to new multi-lane KYC system for user_id: {user_id}")
    
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    trusted_issuer = get_current_user_from_tab_session(tab_session.session_id)
    
    if not trusted_issuer or trusted_issuer.user_type != 'trusted_issuer':
        flash('Trusted Issuer access required.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    # Check if trusted issuer is approved
    approval = TrustedIssuerApproval.query.filter_by(trusted_issuer_id=trusted_issuer.id).first()
    if not approval or approval.status != 'approved':
        flash('Your trusted issuer capabilities must be approved by admin first.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get investor
    investor = User.query.get_or_404(user_id)
    print(f"🔍 Investor: {investor.username} (type: {investor.user_type})")
    
    if investor.user_type != 'investor':
        error_msg = f"❌ Only investors can have KYC approved. User type: {investor.user_type}"
        print(error_msg)
        flash('Only investors can have KYC approved.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    # CORRECT T-REX ARCHITECTURE: Redirect to new multi-lane KYC system
    print(f"🔒 CORRECT T-REX Architecture: Redirecting to new multi-lane KYC system")
    print(f"🔒 This ensures SECURE architecture with NO third-party management keys on investor OnchainID")
    
    flash(f'✅ Redirecting to new multi-lane KYC system for {investor.username}. This ensures SECURE architecture.', 'success')
    
    # Redirect to the new KYC system
    return redirect(url_for('kyc_system.select_trusted_issuer', tab_session=tab_session.session_id))


@trusted_issuer_bp.route('/kyc-reject/<int:user_id>')
def reject_kyc(user_id):
    """Reject investor KYC"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    trusted_issuer = get_current_user_from_tab_session(tab_session.session_id)
    
    if not trusted_issuer or trusted_issuer.user_type != 'trusted_issuer':
        flash('Trusted Issuer access required.', 'error')
        return redirect(url_for('trusted_issuer.login', tab_session=tab_session.session_id))
    
    # Get investor
    investor = User.query.get_or_404(user_id)
    if investor.user_type != 'investor':
        flash('Only investors can have KYC rejected.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    try:
        # Update KYC status
        investor.kyc_status = 'rejected'
        investor.kyc_approved_by = trusted_issuer.id
        investor.kyc_approved_at = db.func.now()
        db.session.commit()
        
        flash(f'KYC rejected for {investor.username}.', 'success')
        
    except Exception as e:
        flash(f'Error rejecting KYC: {str(e)}', 'error')
    
    return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))

@trusted_issuer_bp.route('/onchainid/<int:user_id>')
def view_onchainid(user_id):
    """View user's OnchainID"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    trusted_issuer = get_current_user_from_tab_session(tab_session.session_id)
    
    if not trusted_issuer or trusted_issuer.user_type != 'trusted_issuer':
        flash('Trusted Issuer access required.', 'error')
        return redirect(url_for('trusted_issuer.login', tab_session=tab_session.session_id))
    
    # Get user
    user = User.query.get_or_404(user_id)
    
    # Get OnchainID info
    onchain_id_info = UserOnchainID.query.filter_by(user_id=user_id).first()
    
    # Get user's claims
    user_claims = UserClaim.query.filter_by(user_id=user_id, is_active=True).all()
    
    return render_template('trusted_issuer_onchainid.html',
                         user=user,
                         onchain_id_info=onchain_id_info,
                         user_claims=user_claims,
                         claim_topics=get_all_topics(),
                         tab_session_id=tab_session.session_id)

@trusted_issuer_bp.route('/add-claim/<int:user_id>', methods=['POST'])
def add_claim(user_id):
    """Add claim to user's OnchainID"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    trusted_issuer = get_current_user_from_tab_session(tab_session.session_id)
    
    if not trusted_issuer or trusted_issuer.user_type != 'trusted_issuer':
        flash('Trusted Issuer access required.', 'error')
        return redirect(url_for('trusted_issuer.login', tab_session=tab_session.session_id))
    
    # Check if trusted issuer is approved
    approval = TrustedIssuerApproval.query.filter_by(trusted_issuer_id=trusted_issuer.id).first()
    if not approval or approval.status != 'approved':
        flash('Your trusted issuer capabilities must be approved by admin first.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get user
    user = User.query.get_or_404(user_id)
    
    # Get form data
    claim_topic = request.form.get('claim_topic')
    claim_data = request.form.get('claim_data')
    
    if not claim_topic or not claim_data:
        flash('Claim topic and data are required.', 'error')
        return redirect(url_for('trusted_issuer.view_onchainid', user_id=user_id, tab_session=tab_session.session_id))
    
    try:
        # Check if trusted issuer has capability for this topic
        from models.user import TrustedIssuerCapability
        capability = TrustedIssuerCapability.query.filter_by(
            trusted_issuer_id=trusted_issuer.id,
            claim_topic=int(claim_topic),
            is_active=True
        ).first()
        
        if not capability:
            flash(f'You are not authorized to issue claims for topic {claim_topic}.', 'error')
            return redirect(url_for('trusted_issuer.view_onchainid', user_id=user_id, tab_session=tab_session.session_id))
        
        # Add claim to database
        claim = UserClaim(
            user_id=user_id,
            claim_topic=int(claim_topic),
            claim_data=claim_data,
            issued_by=trusted_issuer.id
        )
        db.session.add(claim)
        
        # Add claim to OnchainID on-chain
        if user.onchain_id:
            from services.hybrid_claim_service import HybridClaimService
            hybrid_service = HybridClaimService()
            
            result = hybrid_service.add_claim(
                investor_user_id=user_id,
                trusted_issuer_user_id=trusted_issuer.id,
                topic=int(claim_topic),
                data=claim_data
            )
            
            if result['success']:
                claim.onchain_tx_hash = result['transaction_hash']
            else:
                flash(f'Warning: Claim added to database but failed on-chain: {result["error"]}', 'warning')
        
        db.session.commit()
        flash(f'Claim added successfully for topic {claim_topic}.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding claim: {str(e)}', 'error')
    
    return redirect(url_for('trusted_issuer.view_onchainid', user_id=user_id, tab_session=tab_session.session_id))

@trusted_issuer_bp.route('/remove-claim/<int:user_id>', methods=['POST'])
def remove_claim(user_id):
    """Remove claim from user's OnchainID"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    trusted_issuer = get_current_user_from_tab_session(tab_session.session_id)
    
    if not trusted_issuer or trusted_issuer.user_type != 'trusted_issuer':
        flash('Trusted Issuer access required.', 'error')
        return redirect(url_for('trusted_issuer.login', tab_session=tab_session.session_id))
    
    # Get user
    user = User.query.get_or_404(user_id)
    
    # Get claim ID
    claim_id = request.form.get('claim_id')
    if not claim_id:
        flash('Claim ID is required.', 'error')
        return redirect(url_for('trusted_issuer.view_onchainid', user_id=user_id, tab_session=tab_session.session_id))
    
    try:
        # Get claim
        claim = UserClaim.query.get_or_404(claim_id)
        
        # Verify ownership
        if claim.issued_by != trusted_issuer.id:
            flash('You can only remove claims that you issued.', 'error')
            return redirect(url_for('trusted_issuer.view_onchainid', user_id=user_id, tab_session=tab_session.session_id))
        
        # Deactivate claim
        claim.is_active = False
        db.session.commit()
        
        flash('Claim removed successfully.', 'success')
        
    except Exception as e:
        flash(f'Error removing claim: {str(e)}', 'error')
    
    return redirect(url_for('trusted_issuer.view_onchainid', user_id=user_id, tab_session=tab_session.session_id)) 

@trusted_issuer_bp.route('/token/<int:token_id>/metamask-transaction', methods=['POST'])
def handle_trusted_issuer_metamask_transaction(token_id):
    """MetaMask transaction handler for trusted issuer operations"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'trusted_issuer':
        return jsonify({'success': False, 'error': 'Trusted Issuer access required.'}), 401
    
    return handle_metamask_transaction_core(token_id, 'trusted_issuer', user)

def execute_claim_addition_with_metamask_approval(kyc_request, claim_decisions):
    """Execute claim addition using JavaScript script after MetaMask approval"""
    try:
        print(f"🚀 Executing claim addition with MetaMask approval for KYC request {kyc_request.id}")
        
        # Get the investor and trusted issuer
        investor = kyc_request.investor
        trusted_issuer = kyc_request.trusted_issuer
        
        if not investor.onchain_id:
            return {'success': False, 'error': 'Investor has no OnchainID'}
        
        if not trusted_issuer.claim_issuer_address:
            return {'success': False, 'error': 'Trusted issuer has no ClaimIssuer contract'}
        
        # Use the existing hybrid claim service to execute claims
        from services.hybrid_claim_service import HybridClaimService
        hybrid_service = HybridClaimService()
        
        successful_claims = []
        failed_claims = []
        
        for claim_request in kyc_request.claim_requests:
            claim_id = str(claim_request.id)
            if claim_id not in claim_decisions:
                continue
                
            decision = claim_decisions[claim_id]
            if decision.get('decision') != 'approved':
                continue
            
            # Execute claim addition using existing JavaScript script
            result = hybrid_service.add_claim(
                investor_user_id=investor.id,
                trusted_issuer_user_id=trusted_issuer.id,
                topic=claim_request.claim_topic,
                data=decision['data']
            )
            
            if result['success']:
                successful_claims.append({
                    'claim_request_id': claim_request.id,
                    'topic': claim_request.claim_topic,
                    'data': decision['data'],
                    'transaction_hash': result.get('transaction_hash')
                })
            else:
                failed_claims.append({
                    'claim_request_id': claim_request.id,
                    'topic': claim_request.claim_topic,
                    'error': result.get('error')
                })
        
        if failed_claims:
            return {
                'success': False,
                'error': f'Some claims failed: {len(failed_claims)} failed, {len(successful_claims)} successful',
                'successful_claims': successful_claims,
                'failed_claims': failed_claims
            }
        
        return {
            'success': True,
            'message': f'Successfully added {len(successful_claims)} claims to blockchain',
            'successful_claims': successful_claims,
            'transaction_hashes': [claim['transaction_hash'] for claim in successful_claims]
        }
        
    except Exception as e:
        print(f"❌ Error executing claim addition with MetaMask approval: {e}")
        return {'success': False, 'error': str(e)}

def build_claim_verification_data(kyc_request):
    """Build data needed for claim verification before execution"""
    try:
        print(f"🔧 Building claim verification data for KYC request {kyc_request.id}")
        
        # Get the investor and trusted issuer
        investor = kyc_request.investor
        trusted_issuer = kyc_request.trusted_issuer
        
        verification_data = {
            'kyc_request_id': kyc_request.id,
            'investor': {
                'id': investor.id,
                'username': investor.username,
                'wallet_address': investor.wallet_address,
                'onchain_id': investor.onchain_id
            },
            'trusted_issuer': {
                'id': trusted_issuer.id,
                'username': trusted_issuer.username,
                'wallet_address': trusted_issuer.wallet_address,
                'claim_issuer_address': trusted_issuer.claim_issuer_address
            },
            'claim_requests': []
        }
        
        for claim_request in kyc_request.claim_requests:
            claim_data = {
                'id': claim_request.id,
                'topic': claim_request.claim_topic,
                'requested_data': claim_request.requested_claim_data,
                'status': claim_request.status
            }
            verification_data['claim_requests'].append(claim_data)
        
        return verification_data
        
    except Exception as e:
        print(f"❌ Error building claim verification data: {e}")
        return None 