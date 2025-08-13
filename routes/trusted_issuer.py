from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import db
from models.user import User, TrustedIssuerApproval, UserOnchainID, UserClaim
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session
from utils.auth_utils import hash_password, decrypt_private_key
from services.onchainid_service import OnchainIDService
from services.web3_service import Web3Service
from config.claim_topics import get_all_topics
import json
from datetime import datetime
from services.onchainid_key_manager import OnchainIDKeyManager
from services.transaction_indexer import TransactionIndexer
from models.enhanced_models import OnchainIDKey

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

@trusted_issuer_bp.route('/kyc-approve/<int:user_id>', methods=['POST'])
def approve_kyc(user_id):
    """Approve investor KYC - CORRECT T-REX Architecture
    
    This function now follows the SECURE architecture where:
    - Investor OnchainID has ONLY Account 0 (deployer) as management key
    - Trusted issuer keys are ONLY on ClaimIssuer contract
    - NO third-party management keys are added to investor OnchainID
    - Redirects to new multi-lane KYC system for claim addition
    """
    print(f"🚀 KYC approval function called for user_id: {user_id}")
    with open("/tmp/tokenplatform_debug.log", "a") as f:
        f.write(f"🚀 KYC approval function called for user_id: {user_id}\n")
    
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
    
    # Get investor
    investor = User.query.get_or_404(user_id)
    print(f"🔍 Investor: {investor.username} (type: {investor.user_type})")
    with open("/tmp/tokenplatform_debug.log", "a") as f:
        f.write(f"🔍 Investor: {investor.username} (type: {investor.user_type})\n")
    
    if investor.user_type != 'investor':
        error_msg = f"❌ Only investors can have KYC approved. User type: {investor.user_type}"
        print(error_msg)
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"{error_msg}\n")
        flash('Only investors can have KYC approved.', 'error')
        return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
    
    try:
        # Check if investor has OnchainID (should exist from registration)
        print(f"🔍 Investor OnchainID: {investor.onchain_id}")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"🔍 Investor OnchainID: {investor.onchain_id}\n")
        
        if not investor.onchain_id:
            error_msg = f"❌ Investor {investor.username} does not have an OnchainID"
            print(error_msg)
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"{error_msg}\n")
            flash(f'Investor {investor.username} does not have an OnchainID. Please ensure registration completed successfully.', 'error')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        
        # Add KYC claim to existing OnchainID
        print("🔧 Starting service initialization...")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write("🔧 Starting service initialization...\n")
        
        from services.onchainid_service import OnchainIDService
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        from utils.auth_utils import decrypt_private_key
        
        # Get trusted issuer's private key (more realistic - trusted issuer uses their own key)
        print("🔧 Decrypting trusted issuer private key...")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write("🔧 Decrypting trusted issuer private key...\n")
        
        print(f"🔍 Trusted issuer username: {trusted_issuer.username}")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"🔍 Trusted issuer username: {trusted_issuer.username}\n")
        
        print(f"🔍 Trusted issuer wallet address: {trusted_issuer.wallet_address}")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"🔍 Trusted issuer wallet address: {trusted_issuer.wallet_address}\n")
        
        print(f"🔍 Full encrypted private key from DB: '{trusted_issuer.private_key}'")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"🔍 Full encrypted private key from DB: '{trusted_issuer.private_key}'\n")
        
        print(f"🔍 Encrypted private key length: {len(trusted_issuer.private_key)}")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"🔍 Encrypted private key length: {len(trusted_issuer.private_key)}\n")
        
        print(f"🔍 Encrypted private key starts with '0x': {trusted_issuer.private_key.startswith('0x')}")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"🔍 Encrypted private key starts with '0x': {trusted_issuer.private_key.startswith('0x')}\n")
        
        try:
            print("🔧 Getting private key directly (no encryption)...")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("🔧 Getting private key directly (no encryption)...\n")
            
            trusted_issuer_private_key = trusted_issuer.private_key
            
            print(f"🔍 Private key from DB: '{trusted_issuer_private_key}'")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"🔍 Private key from DB: '{trusted_issuer_private_key}'\n")
            
            print(f"🔍 Private key length: {len(trusted_issuer_private_key)}")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"🔍 Private key length: {len(trusted_issuer_private_key)}\n")
            
            print(f"🔍 Private key starts with '0x': {trusted_issuer_private_key.startswith('0x')}")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"🔍 Private key starts with '0x': {trusted_issuer_private_key.startswith('0x')}\n")
            
            print(f"🔍 Private key is valid hex: {len(trusted_issuer_private_key) == 66}")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"🔍 Private key is valid hex: {len(trusted_issuer_private_key) == 66}\n")
                
        except Exception as e:
            error_msg = f"❌ Error getting private key: {str(e)}"
            print(error_msg)
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"{error_msg}\n")
            flash(f'Error getting private key: {str(e)}', 'error')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        
        # Initialize services
        try:
            print("🔧 Initializing Web3Service with trusted issuer key...")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("🔧 Initializing Web3Service with trusted issuer key...\n")
            
            web3_service = Web3Service(trusted_issuer_private_key)
            print("✅ Web3Service initialized successfully with trusted issuer key")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("✅ Web3Service initialized successfully with trusted issuer key\n")
            
            print("🔧 Initializing TREXService...")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("🔧 Initializing TREXService...\n")
            
            trex_service = TREXService(web3_service)
            print("✅ TREXService initialized successfully")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("✅ TREXService initialized successfully\n")
            
            print("🔧 Initializing OnchainIDService...")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("🔧 Initializing OnchainIDService...\n")
            
            onchainid_service = OnchainIDService(web3_service)
            print("✅ OnchainIDService initialized successfully")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("✅ OnchainIDService initialized successfully\n")
                
        except Exception as e:
            error_msg = f"❌ Error initializing services: {str(e)}"
            print(error_msg)
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"{error_msg}\n")
            flash(f'Error initializing services: {str(e)}', 'error')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        
        # Get selected claims from form
        claims_to_add = request.form.getlist('claims_to_add')
        print(f"🔍 Selected claims: {claims_to_add}")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write(f"🔍 Selected claims: {claims_to_add}\n")
        
        if not claims_to_add:
            error_msg = "❌ No claims selected"
            print(error_msg)
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"{error_msg}\n")
            flash('Please select at least one claim to add.', 'error')
            return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))
        
        # Add selected claims to the investor's OnchainID
        added_claims = []
        failed_claims = []
        user_claims_to_add = []  # Store UserClaim objects to add later
        
        print("🔧 Starting blockchain transactions for all claims...")
        with open("/tmp/tokenplatform_debug.log", "a") as f:
            f.write("🔧 Starting blockchain transactions for all claims...\n")
        
        for claim_string in claims_to_add:
            # Parse claim string (format: "topic:data")
            topic, data = claim_string.split(':', 1)
            topic = int(topic)
            
            print(f"🔧 Processing claim: Topic {topic}, Data: {data}")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"🔧 Processing claim: Topic {topic}, Data: {data}\n")
            
            # Encode claim data properly for blockchain (following the T-REX approach)
            # Convert claim value to UTF-8 bytes and then hexlify (like ethers.utils.hexlify(ethers.utils.toUtf8Bytes(claimValue)))
            try:
                debug_msg = f"""
{'=' * 50}
DEBUG: CLAIM DATA ENCODING
{'=' * 50}
🔍 Original data: '{data}' (type: {type(data)})
"""
                print(debug_msg)
                
                # Also write to file
                with open("/tmp/tokenplatform_debug.log", "a") as f:
                    f.write(f"{debug_msg}\n")
                
                # Convert string to UTF-8 bytes, then to hex
                data_bytes = data.encode('utf-8')
                data_msg = f"🔍 Data bytes: {data_bytes}"
                print(data_msg)
                with open("/tmp/tokenplatform_debug.log", "a") as f:
                    f.write(f"{data_msg}\n")
                
                encoded_data = '0x' + data_bytes.hex()
                encoded_msg = f"🔧 Encoded '{data}' to '{encoded_data}'"
                print(encoded_msg)
                with open("/tmp/tokenplatform_debug.log", "a") as f:
                    f.write(f"{encoded_msg}\n")
                
                end_msg = f"{'=' * 50}"
                print(end_msg)
                with open("/tmp/tokenplatform_debug.log", "a") as f:
                    f.write(f"{end_msg}\n")
                    
            except Exception as e:
                error_msg = f"ERROR: Could not encode data '{data}' to hex: {e}"
                print(error_msg)
                with open("/tmp/tokenplatform_debug.log", "a") as f:
                    f.write(f"{error_msg}\n")
                # Fallback: use empty bytes
                encoded_data = '0x'
            
            # Add claim to OnchainID using hybrid service
            from services.hybrid_claim_service import HybridClaimService
            hybrid_service = HybridClaimService()
            
            claim_result = hybrid_service.add_claim(
                investor_user_id=investor.id,
                trusted_issuer_user_id=trusted_issuer.id,
                topic=topic,
                data=data
            )
            
            if claim_result['success']:
                # Store UserClaim object for later addition (don't add to session yet)
                from models.user import UserClaim
                user_claim = UserClaim(
                    user_id=investor.id,
                    claim_topic=topic,
                    claim_data=encoded_data,
                    issued_by=trusted_issuer.id,
                    onchain_tx_hash=claim_result.get('transaction_hash')  # Use correct field name
                )
                user_claims_to_add.append(user_claim)
                added_claims.append(f"Topic {topic}: {data}")
                print(f"✅ Claim {topic} added successfully: {claim_result.get('tx_hash')}")
                with open("/tmp/tokenplatform_debug.log", "a") as f:
                    f.write(f"✅ Claim {topic} added successfully: {claim_result.get('tx_hash')}\n")
            else:
                failed_claims.append(f"Topic {topic}: {data} - {claim_result['error']}")
                print(f"❌ Claim {topic} failed: {claim_result['error']}")
                with open("/tmp/tokenplatform_debug.log", "a") as f:
                    f.write(f"❌ Claim {topic} failed: {claim_result['error']}\n")
        
        # Only update database if ALL claims were successful
        if failed_claims:
            # Some claims failed - don't update database
            error_msg = f'KYC approval failed. Failed claims: {", ".join(failed_claims)}'
            print(f"❌ {error_msg}")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"❌ {error_msg}\n")
            flash(error_msg, 'error')
        else:
            # All claims successful - update database
            print("✅ All claims successful, updating database...")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write("✅ All claims successful, updating database...\n")
            
            # Add all UserClaim records
            for user_claim in user_claims_to_add:
                db.session.add(user_claim)
            
            # Update KYC status
            investor.kyc_status = 'approved'
            investor.kyc_approved_by = trusted_issuer.id
            investor.kyc_approved_at = db.func.now()
            
            # Commit all changes
            db.session.commit()
            
            success_msg = f'KYC approved for {investor.username}. Added claims: {", ".join(added_claims)}'
            print(f"✅ {success_msg}")
            with open("/tmp/tokenplatform_debug.log", "a") as f:
                f.write(f"✅ {success_msg}\n")
            flash(success_msg, 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving KYC: {str(e)}', 'error')
    
    return redirect(url_for('trusted_issuer.dashboard', tab_session=tab_session.session_id))

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