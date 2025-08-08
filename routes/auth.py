from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from models.user import User, TrustedIssuerApproval, db
from utils.auth_utils import hash_password, encrypt_private_key, decrypt_private_key
from utils.session_utils import get_or_create_tab_session, login_user_to_tab_session, logout_user_from_tab_session
from utils.contract_utils import get_contract_address
import json

auth_bp = Blueprint('auth', __name__)

def create_user_onchainid(user_id, wallet_address, user_type, password):
    """Create OnchainID for a user using T-REX Factory"""
    try:
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        # Get user and decrypt their private key
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        user_private_key = decrypt_private_key(user.private_key, password)
        
        # Initialize Web3 service with user's private key
        web3_service = Web3Service(user_private_key)
        
        # Initialize TREX service with Web3 service
        trex_service = TREXService(web3_service)
        
        # Get Identity Factory address from database
        identity_factory_address = get_contract_address('IdentityFactory')
        if not identity_factory_address:
            return False, "Identity Factory not deployed. Please deploy T-REX factory first."
        
        # Create OnchainID using T-REX Factory pattern
        print(f"🎯 Creating OnchainID for user: {wallet_address}")
        
        # Check if OnchainID already exists
        existing_onchain_id = trex_service.get_identity(wallet_address, identity_factory_address)
        if existing_onchain_id and existing_onchain_id != '0x0000000000000000000000000000000000000000':
            onchain_id_address = existing_onchain_id
            is_new_onchain_id = False
            transaction_hash = None
            print(f"✅ Using existing OnchainID: {onchain_id_address}")
        else:
            # Create new OnchainID
            result = trex_service.create_identity(wallet_address, identity_factory_address)
            if not result['success']:
                return False, f"Failed to create OnchainID: {result['error']}"
            
            onchain_id_address = result['onchain_id_address']
            transaction_hash = result['transaction_hash']
            is_new_onchain_id = True
            print(f"✅ Created new OnchainID: {onchain_id_address}")
        
        # Create database entry
        from models.user import UserOnchainID
        onchain_id_entry = UserOnchainID(
            user_id=user_id,
            onchain_id_address=onchain_id_address,
            management_keys_added=True,  # T-REX factory adds management keys
            signing_keys_added=False,  # Will be added later if needed
            claim_issuer_address=None  # Will be set later for trusted issuers
        )
        
        db.session.add(onchain_id_entry)
        db.session.commit()
        
        # Update user's onchain_id field
        user = User.query.get(user_id)
        if user:
            user.onchain_id = onchain_id_address
            db.session.commit()
        
        success_msg = f"OnchainID {'created' if is_new_onchain_id else 'found'} at {onchain_id_address}"
        if transaction_hash:
            success_msg += f" (tx: {transaction_hash})"
        
        return True, onchain_id_address
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating OnchainID: {str(e)}")
        return False, str(e)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Unified registration page for all user types"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        wallet_address = request.form.get('wallet_address')
        user_type = request.form.get('user_type')
        
        # Validation
        if not all([username, password, wallet_address, user_type]):
            flash('All fields are required.', 'error')
            return render_template('register.html', tab_session_id=request.args.get('tab_session'))
        
        if user_type not in ['admin', 'issuer', 'trusted_issuer', 'investor']:
            flash('Invalid user type.', 'error')
            return render_template('register.html', tab_session_id=request.args.get('tab_session'))
        
        # Check if user already exists
        existing_user = User.query.filter(
            (User.wallet_address == wallet_address) | 
            (User.username == username)
        ).first()
        
        if existing_user:
            flash('User already exists with this wallet address or username.', 'error')
            return render_template('register.html', tab_session_id=request.args.get('tab_session'))
        
        # Get private key from form
        private_key = request.form.get('private_key')
        if not private_key:
            flash('Private key is required for blockchain interactions.', 'error')
            return render_template('register.html', tab_session_id=request.args.get('tab_session'))
        
        # Validate private key format
        if not private_key.startswith('0x') or len(private_key) != 66:
            flash('Invalid private key format. Must start with 0x and be 66 characters long.', 'error')
            return render_template('register.html', tab_session_id=request.args.get('tab_session'))
        
        # Create new user
        new_user = User(
            username=username,
            email=None,  # No email required
            password_hash=hash_password(password),
            wallet_address=wallet_address,
            private_key=private_key,  # Store directly, no encryption
            user_type=user_type,
            kyc_status='approved' if user_type in ['admin', 'issuer', 'trusted_issuer'] else 'not_submitted'
        )
        
        db.session.add(new_user)
        db.session.flush()  # Get the ID
        
        # Create OnchainID for the user
        onchainid_success, onchainid_result = create_user_onchainid(
            new_user.id, 
            wallet_address, 
            user_type,
            password
        )
        
        if not onchainid_success:
            db.session.rollback()
            flash(f'Error creating OnchainID: {onchainid_result}', 'error')
            return render_template('register.html', tab_session_id=request.args.get('tab_session'))
        
        # For trusted issuers, also create ClaimIssuer contract
        if user_type == 'trusted_issuer':
            print(f"🏭 Creating ClaimIssuer contract for trusted issuer: {wallet_address}")
            
            # Create ClaimIssuer contract
            claimissuer_success, claimissuer_result = create_claimissuer_contract(
                new_user.id,
                wallet_address,
                password
            )
            
            if not claimissuer_success:
                db.session.rollback()
                flash(f'Error creating ClaimIssuer contract: {claimissuer_result}', 'error')
                return render_template('register.html', tab_session_id=request.args.get('tab_session'))
            
            print(f"✅ ClaimIssuer contract created: {claimissuer_result}")
            
            # Create approval request
            claim_capabilities = request.form.getlist('claim_capabilities')
            approval_request = TrustedIssuerApproval(
                trusted_issuer_id=new_user.id,
                requested_capabilities=json.dumps(claim_capabilities),
                status='pending'
            )
            db.session.add(approval_request)
        
        db.session.commit()
        
        if user_type == 'trusted_issuer':
            flash(f'{user_type.title()} registered successfully! Your capabilities will be reviewed by an admin. You will be notified when approved.', 'success')
        else:
            flash(f'{user_type.title()} registered successfully! OnchainID created. Please login.', 'success')
        
        # Get tab session ID for redirects
        tab_session_id = request.args.get('tab_session')
        
        # Redirect to appropriate login page
        if user_type == 'admin':
            return redirect(url_for('admin.login', tab_session=tab_session_id))
        elif user_type == 'issuer':
            return redirect(url_for('issuer.login', tab_session=tab_session_id))
        elif user_type == 'trusted_issuer':
            return redirect(url_for('trusted_issuer.login', tab_session=tab_session_id))
        else:  # investor
            return redirect(url_for('investor.login', tab_session=tab_session_id))
    
    return render_template('register.html', tab_session_id=request.args.get('tab_session'))

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout user from current tab session"""
    tab_session_id = request.args.get('tab_session')
    
    print(f"🔍 Logout route debug:")
    print(f"  Tab session ID: {tab_session_id}")
    print(f"  Request method: {request.method}")
    
    if tab_session_id:
        logout_user_from_tab_session(tab_session_id)
        print(f"  ✅ Logged out user from session: {tab_session_id}")
    else:
        print(f"  ⚠️  No tab session ID provided")
    
    flash('Successfully logged out!', 'success')
    return redirect(url_for('home', tab_session=tab_session_id))

def create_claimissuer_contract(user_id, wallet_address, password):
    """Create ClaimIssuer contract for a trusted issuer"""
    try:
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        # Get user and decrypt their private key
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        user_private_key = decrypt_private_key(user.private_key, password)
        
        # Initialize Web3 service with user's private key
        web3_service = Web3Service(user_private_key)
        
        # Initialize TREX service with Web3 service
        trex_service = TREXService(web3_service)
        
        print(f"🎯 Creating ClaimIssuer contract for trusted issuer: {wallet_address}")
        
        # Deploy ClaimIssuer contract
        result = trex_service.deploy_claimissuer_contract(wallet_address)
        
        if not result['success']:
            return False, f"Failed to deploy ClaimIssuer contract: {result['error']}"
        
        claimissuer_address = result['claimissuer_address']
        transaction_hash = result['transaction_hash']
        
        print(f"✅ ClaimIssuer contract deployed: {claimissuer_address}")
        
        # Update user's claim_issuer_address field
        user = User.query.get(user_id)
        if user:
            user.claim_issuer_address = claimissuer_address
            db.session.commit()
        
        return True, claimissuer_address
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating ClaimIssuer contract: {str(e)}")
        return False, str(e) 