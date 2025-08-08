from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import db
from models.user import User, TrustedIssuerApproval
from models.token import Token
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session
from utils.claims_utils import get_user_missing_claims, get_trusted_issuers
from services.onchain_claims_service import OnchainClaimsService
from services.web3_service import Web3Service
from utils.contract_utils import get_contract_address
import json

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('admin_login.html')
        
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Check credentials (hardcoded for now)
        if username == 'admin' and password == 'admin123':
            from utils.session_utils import login_user_to_tab_session
            from utils.auth_utils import create_default_admin
            
            # Ensure admin user exists
            admin_user = create_default_admin()
            
            # Login to tab session
            login_user_to_tab_session(tab_session.session_id, admin_user)
            
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin.dashboard', tab_session=tab_session.session_id))
        else:
            flash('Invalid credentials.', 'error')
    
    return render_template('admin_login.html')

@admin_bp.route('/dashboard')
def dashboard():
    """Admin dashboard"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    # Get all users who need claims verification
    # This includes investors who need claims for tokens, and trusted issuers pending approval
    all_investors = User.query.filter_by(user_type='investor').all()
    pending_trusted_issuers = User.query.filter_by(user_type='trusted_issuer', kyc_status='pending').all()
    
    # Filter investors who need claims for any token
    investors_needing_claims = []
    for investor in all_investors:
        missing_claims = get_user_missing_claims(investor.id)
        if missing_claims:  # If investor is missing claims for any token
            investors_needing_claims.append(investor)
    
    pending_kyc = investors_needing_claims + pending_trusted_issuers
    
    # Get pending trusted issuer approvals
    pending_approvals = TrustedIssuerApproval.query.filter_by(status='pending').all()
    
    # Get all tokens
    tokens = Token.query.all()
    
    return render_template('admin_dashboard.html', 
                         pending_kyc=pending_kyc,
                         pending_approvals=pending_approvals,
                         tokens=tokens,
                         tab_session_id=tab_session.session_id)

@admin_bp.route('/claims-verification/<int:user_id>')
def claims_verification(user_id):
    """Admin view of user's claims verification status"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    target_user = User.query.get_or_404(user_id)
    
    # Get user's current claims
    from models.user import UserClaim
    user_claims = UserClaim.query.filter_by(user_id=user_id, is_active=True).all()
    
    # Get missing claims for all tokens
    missing_claims = get_user_missing_claims(user_id)
    
    # Get all tokens
    all_tokens = Token.query.all()
    
    return render_template('admin_claims_verification.html', 
                         target_user=target_user,
                         user_claims=user_claims,
                         missing_claims=missing_claims,
                         all_tokens=all_tokens,
                         tab_session_id=tab_session.session_id)


@admin_bp.route('/onchain-claims-check/<int:user_id>')
def onchain_claims_check(user_id):
    """Admin on-chain claims verification for a user"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    target_user = User.query.get_or_404(user_id)
    
    # Initialize on-chain claims service
    claims_service = OnchainClaimsService()
    
    # Get all tokens for comprehensive check
    all_tokens = Token.query.all()
    onchain_results = {}
    
    try:
        # Load deployment details (you'll need to implement this based on your deployment structure)
        deployment_details = {}  # This should load from your deployment.json or database
        
        for token in all_tokens:
            if token.contract_address:
                # Perform on-chain claims check for this token
                result = claims_service.comprehensive_claims_check(
                    target_user.wallet_address,
                    token.contract_address,
                    deployment_details
                )
                onchain_results[token.id] = result
        
        # Also get user's OnchainID claims directly
        if target_user.onchain_id:
            onchainid_claims = claims_service.get_onchainid_claims(target_user.onchain_id)
        else:
            onchainid_claims = {'success': False, 'error': 'No OnchainID found'}
        
        return render_template('admin_onchain_claims_check.html',
                             target_user=target_user,
                             onchain_results=onchain_results,
                             onchainid_claims=onchainid_claims,
                             all_tokens=all_tokens,
                             tab_session_id=tab_session.session_id)
                             
    except Exception as e:
        flash(f'Error performing on-chain claims check: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard', tab_session=tab_session.session_id))

@admin_bp.route('/kyc-approve/<int:user_id>')
def approve_kyc(user_id):
    """Admin function to approve KYC (manual for now) - DEPRECATED"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    target_user = User.query.get_or_404(user_id)
    if target_user.user_type != 'investor':
        flash('Only investors can have KYC approved.', 'error')
        return redirect(url_for('admin.dashboard', tab_session=tab_session.session_id))
    
    try:
        # Update KYC status
        target_user.kyc_status = 'approved'
        db.session.commit()
        flash(f'KYC approved for {target_user.wallet_address}', 'success')
            
    except Exception as e:
        flash(f'Error approving KYC: {str(e)}', 'error')
    
    return redirect(url_for('admin.dashboard', tab_session=tab_session.session_id))

@admin_bp.route('/trusted-issuer-approvals')
def trusted_issuer_approvals():
    """Admin view of pending trusted issuer approvals"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    # Get pending approvals
    pending_approvals = TrustedIssuerApproval.query.filter_by(status='pending').all()
    
    return render_template('admin_trusted_issuer_approvals.html',
                         pending_approvals=pending_approvals,
                         tab_session_id=tab_session.session_id)

@admin_bp.route('/approve-trusted-issuer/<int:approval_id>', methods=['POST'])
def approve_trusted_issuer(approval_id):
    """Admin approve trusted issuer capabilities"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    approval = TrustedIssuerApproval.query.get_or_404(approval_id)
    
    if approval.status != 'pending':
        flash('Approval has already been processed.', 'error')
        return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
    
    try:
        # Get selected capabilities from form
        approved_capabilities = request.form.getlist('approved_capabilities')
        additional_capabilities = request.form.getlist('additional_capabilities')
        
        # Combine all approved capabilities
        all_capabilities = approved_capabilities + additional_capabilities
        
        if not all_capabilities:
            flash('Please select at least one capability to approve.', 'error')
            return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
        
        # Create capabilities for the trusted issuer
        from models.user import TrustedIssuerCapability
        
        for capability_string in all_capabilities:
            # Parse capability string (format: "topic:data")
            topic, data = capability_string.split(':', 1)
            
            capability = TrustedIssuerCapability(
                trusted_issuer_id=approval.trusted_issuer_id,
                claim_topic=int(topic),
                claim_data=data,
                description=f"Topic {topic}: {data}"
            )
            db.session.add(capability)
        
        # Update approval status
        approval.status = 'approved'
        approval.approved_by = user.id
        approval.approved_at = db.func.now()
        approval.requested_capabilities = json.dumps({
            'approved_capabilities': all_capabilities
        })
        
        # Update trusted issuer status
        trusted_issuer = User.query.get(approval.trusted_issuer_id)
        if trusted_issuer:
            trusted_issuer.kyc_status = 'approved'
        
        # Add trusted issuer to TrustedIssuersRegistry (TIR) on blockchain
        try:
            
            # Get TrustedIssuersRegistry address
            trusted_issuers_registry_address = get_contract_address('TrustedIssuersRegistry')
            
            if trusted_issuers_registry_address and trusted_issuer.onchain_id:
                # Use Account 0 (admin/deployer) to add trusted issuer to TIR
                account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
                web3_service = Web3Service(private_key=account_0_private_key)
                
                # Verify we're using the correct Account 0
                expected_account_0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
                actual_account = web3_service.account.address
                print(f"🔍 Expected Account 0: {expected_account_0}")
                print(f"🔍 Actual Account: {actual_account}")
                
                if actual_account.lower() != expected_account_0.lower():
                    print(f"❌ Account mismatch! Expected {expected_account_0}, got {actual_account}")
                    flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities! (TIR registration failed: Wrong account)', 'warning')
                    db.session.commit()
                    return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
                
                                # Check who the owner of TrustedIssuersRegistry is
                try:
                    owner = web3_service.call_contract_function(
                        'TrustedIssuersRegistry',
                        trusted_issuers_registry_address,
                        'owner'
                    )
                    print(f"🔍 TrustedIssuersRegistry owner: {owner}")
                    print(f"🔍 Account 0 address: {web3_service.account.address}")
                    
                    if owner.lower() != web3_service.account.address.lower():
                        print(f"❌ Account 0 is not the owner of TrustedIssuersRegistry")
                        print(f"❌ Owner: {owner}")
                        print(f"❌ Account 0: {web3_service.account.address}")
                        flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities! (TIR registration failed: Account 0 is not the owner)', 'warning')
                        db.session.commit()
                        return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
                        
                except Exception as owner_error:
                    print(f"❌ Error checking TrustedIssuersRegistry owner: {owner_error}")
                    flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities! (TIR owner check failed: {str(owner_error)})', 'warning')
                    db.session.commit()
                    return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
                
                # Extract claim topics from approved capabilities
                claim_topics = []
                for capability_string in all_capabilities:
                    topic, _ = capability_string.split(':', 1)
                    claim_topics.append(int(topic))
                
                # Remove duplicates and sort
                claim_topics = sorted(list(set(claim_topics)))
                
                print(f"🔧 Adding trusted issuer {trusted_issuer.onchain_id} to TIR {trusted_issuers_registry_address}")
                print(f"🔧 Claim topics: {claim_topics}")
                
                # Use ClaimIssuer contract address, not OnchainID
                claim_issuer_address = trusted_issuer.claim_issuer_address
                if not claim_issuer_address:
                    print(f"❌ Trusted issuer {trusted_issuer.username} does not have a ClaimIssuer contract address")
                    flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities! (TIR registration failed: No ClaimIssuer contract)', 'warning')
                    db.session.commit()
                    return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
                
                print(f"🔧 Using ClaimIssuer contract address for TIR registration: {claim_issuer_address}")
                
                # Check if already registered
                is_already_trusted = web3_service.is_trusted_issuer(
                    trusted_issuers_registry_address, 
                    claim_issuer_address
                )
                
                if is_already_trusted:
                    print(f"ℹ️ Trusted issuer {claim_issuer_address} already registered in TIR")
                    flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities! (Already registered in TIR)', 'success')
                else:
                    # Add to TrustedIssuersRegistry
                    tx_hash = web3_service.add_trusted_issuer_to_registry(
                        trusted_issuers_registry_address,
                        claim_issuer_address,  # Use ClaimIssuer contract address
                        claim_topics
                    )
                    
                    print(f"✅ Successfully added trusted issuer to TIR. Transaction hash: {tx_hash}")
                    flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities and registered in TIR!', 'success')
            else:
                print(f"⚠️ Missing TrustedIssuersRegistry address or user OnchainID")
                flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities! (TIR registration skipped - missing contract address)', 'warning')
                
        except Exception as e:
            print(f"❌ Error adding trusted issuer to TIR: {e}")
            flash(f'Trusted issuer approved with {len(all_capabilities)} capabilities! (TIR registration failed: {str(e)})', 'warning')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving trusted issuer: {str(e)}', 'error')
    
    return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))

@admin_bp.route('/reject-trusted-issuer/<int:approval_id>', methods=['POST'])
def reject_trusted_issuer(approval_id):
    """Admin reject trusted issuer capabilities"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    approval = TrustedIssuerApproval.query.get_or_404(approval_id)
    
    if approval.status != 'pending':
        flash('Approval has already been processed.', 'error')
        return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
    
    try:
        # Update approval status
        approval.status = 'rejected'
        approval.approved_by = user.id
        approval.approved_at = db.func.now()
        
        db.session.commit()
        flash('Trusted issuer capabilities rejected.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting trusted issuer: {str(e)}', 'error')
    
    return redirect(url_for('admin.trusted_issuer_approvals', tab_session=tab_session.session_id))
@admin_bp.route('/blockchain-verification')
def blockchain_verification():
    """Admin blockchain verification page"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    try:
        # Initialize Web3 service
        web3_service = Web3Service()
        
        # Get system status
        try:
            print("🔍 Testing Web3 connection...")
            # Test connection first
            web3_service.w3.eth.get_block_number()
            print("✅ get_block_number() succeeded")
            
            current_block = web3_service.w3.eth.block_number
            print(f"✅ Current block: {current_block}")
            
            network_id = web3_service.w3.eth.chain_id
            print(f"✅ Network ID: {network_id}")
            
            gas_price = web3_service.w3.eth.gas_price
            print(f"✅ Gas price: {gas_price}")
            
            system_status = {
                'connected': True,
                'current_block': current_block,
                'network_id': network_id,
                'gas_price': gas_price,
                'error': None
            }
            print(f"✅ Blockchain connected: Block {current_block}, Network {network_id}, Gas {gas_price}")
        except Exception as e:
            print(f"❌ Blockchain connection failed: {e}")
            import traceback
            traceback.print_exc()
            system_status = {
                'connected': False,
                'current_block': None,
                'network_id': None,
                'gas_price': None,
                'error': str(e)
            }
        
        # Get all contracts from database (these are contract implementations)
        from models.contract import Contract
        contracts = Contract.query.all()
        
        # Get all actual deployed tokens from database
        from models.token import Token
        tokens = Token.query.all()
        
        # Verify contracts on-chain (contract implementations)
        contract_verifications = []
        
        for contract in contracts:
            try:
                # Check if contract exists on-chain
                code = web3_service.w3.eth.get_code(contract.contract_address)
                exists = code != b''
                
                # All contracts in Contract model are implementations, not actual tokens
                if exists:
                    # Get additional contract info
                    try:
                        code_size = len(web3_service.w3.eth.get_code(contract.contract_address))
                        balance_wei = web3_service.w3.eth.get_balance(contract.contract_address)
                        balance_eth = web3_service.w3.from_wei(balance_wei, 'ether')
                        current_block = web3_service.w3.eth.block_number
                    except:
                        code_size = 0
                        balance_eth = 0
                        current_block = 0
                else:
                    code_size = 0
                    balance_eth = 0
                    current_block = 0
                
                contract_verifications.append({
                    'name': contract.contract_name,
                    'address': contract.contract_address,
                    'type': contract.contract_type,
                    'info': {
                        'exists': exists,
                        'status': 'success' if exists else 'not_found',
                        'code_size': code_size,
                        'balance_eth': balance_eth,
                        'current_block': current_block
                    }
                })
                    
            except Exception as e:
                contract_verifications.append({
                    'name': contract.contract_name,
                    'address': contract.contract_address,
                    'type': contract.contract_type,
                    'info': {
                        'exists': False,
                        'status': 'error',
                        'error': str(e),
                        'code_size': 0,
                        'balance_eth': 0,
                        'current_block': 0
                    }
                })
        
        # Verify actual deployed tokens on-chain
        token_verifications = []
        
        for token in tokens:
            try:
                # Check if token exists on-chain
                code = web3_service.w3.eth.get_code(token.token_address)
                exists = code != b''
                
                # Get token info from blockchain if it exists
                if exists:
                    try:
                        # Try to get token info from blockchain
                        token_contract = web3_service.w3.eth.contract(
                            address=token.token_address,
                            abi=web3_service.get_contract_abi('Token')
                        )
                        onchain_name = token_contract.functions.name().call()
                        onchain_symbol = token_contract.functions.symbol().call()
                        onchain_total_supply = token_contract.functions.totalSupply().call()
                        onchain_decimals = token_contract.functions.decimals().call()
                    except:
                        # Fallback to database values
                        onchain_name = token.name
                        onchain_symbol = token.symbol
                        onchain_total_supply = str(token.total_supply)
                        onchain_decimals = 18
                else:
                    onchain_name = token.name
                    onchain_symbol = token.symbol
                    onchain_total_supply = str(token.total_supply)
                    onchain_decimals = 18
                
                token_verifications.append({
                    'token': {
                        'id': token.id,
                        'name': token.name,
                        'symbol': token.symbol,
                        'token_address': token.token_address
                    },
                    'verification': {
                        'valid': exists,
                        'token_info': {
                            'name': onchain_name,
                            'symbol': onchain_symbol,
                            'totalSupply': str(onchain_total_supply),
                            'decimals': onchain_decimals
                        },
                        'error': None if exists else 'Token not found on blockchain'
                    }
                })
                    
            except Exception as e:
                token_verifications.append({
                    'token': {
                        'id': token.id,
                        'name': token.name,
                        'symbol': token.symbol,
                        'token_address': token.token_address
                    },
                    'verification': {
                        'valid': False,
                        'token_info': {
                            'name': token.name,
                            'symbol': token.symbol,
                            'totalSupply': str(token.total_supply),
                            'decimals': 18
                        },
                        'error': str(e)
                    }
                })
        
        # Structure verification results as expected by template
        verification_results = {
            'system_status': system_status,
            'contracts': contract_verifications,
            'tokens': token_verifications,
            'deployed_contracts': contract_verifications,  # Use same data for deployed contracts
            'users': []  # Empty for now, can be expanded later
        }
        
        return render_template('admin_blockchain_verification.html',
                             verification_results=verification_results,
                             tab_session_id=tab_session.session_id)
                             
    except Exception as e:
        flash(f'Error connecting to blockchain: {str(e)}', 'error')
        verification_results = {
            'system_status': {
                'connected': False,
                'current_block': None,
                'network_id': None,
                'gas_price': None,
                'error': str(e)
            },
            'contracts': [],
            'tokens': [],
            'deployed_contracts': [],
            'users': []
        }
        return render_template('admin_blockchain_verification.html',
                             verification_results=verification_results,
                             tab_session_id=tab_session.session_id)



@admin_bp.route('/transaction-history')
def transaction_history():
    """Admin transaction history page - shows recent blocks like Hardhat"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('admin.login', tab_session=tab_session.session_id))
    
    try:
        # Initialize Web3 service
        web3_service = Web3Service()
        
        # Get current block
        current_block = web3_service.w3.eth.block_number
        
        # Get all blocks (like Hardhat shows)
        blocks = []
        total_transactions = 0
        
        print(f"Processing blocks 0 to {current_block}")
        
        # Start from block 0 and go up to current block
        for i in range(0, current_block + 1):
            try:
                block = web3_service.w3.eth.get_block(i, full_transactions=True)
                print(f"Processing block {i}: {len(block.transactions)} transactions")
                block_transactions = []
                
                for tx in block.transactions:
                    # Get transaction receipt to check status
                    try:
                        receipt = web3_service.w3.eth.get_transaction_receipt(tx.hash)
                        status = 'success' if receipt.status == 1 else 'failed'
                        gas_used = receipt.gasUsed
                    except:
                        status = 'unknown'
                        gas_used = 0
                    
                    # Calculate ETH value
                    eth_value = web3_service.w3.from_wei(tx.value, 'ether')
                    
                    # Determine transaction type
                    if tx.to is None:
                        tx_type = "Contract Creation"
                    elif tx.value > 0:
                        tx_type = "ETH Transfer"
                    else:
                        tx_type = "Contract Call"
                    
                    # Calculate effective gas price and total cost
                    effective_gas_price = receipt.effectiveGasPrice if receipt and hasattr(receipt, 'effectiveGasPrice') else tx.gasPrice
                    total_cost_eth = web3_service.w3.from_wei(receipt.gasUsed * effective_gas_price, 'ether') if receipt else 0
                    
                    block_transactions.append({
                        'hash': tx.hash.hex(),
                        'from': tx['from'],
                        'to': tx['to'],
                        'value': eth_value,
                        'value_eth': eth_value,
                        'gas_used': gas_used,
                        'gas_limit': tx.gas,
                        'gas_price': web3_service.w3.from_wei(tx.gasPrice, 'gwei'),
                        'effective_gas_price': web3_service.w3.from_wei(effective_gas_price, 'gwei'),
                        'total_cost_eth': total_cost_eth,
                        'status': status,
                        'type': tx_type,
                        'contract_address': receipt.contractAddress if receipt and receipt.contractAddress else None
                    })
                
                blocks.append({
                    'number': block.number,
                    'hash': block.hash.hex(),
                    'timestamp': block.timestamp,
                    'transactions': block_transactions,
                    'transaction_count': len(block_transactions)
                })
                
                total_transactions += len(block_transactions)
                
            except Exception as e:
                print(f"Error getting block {i}: {e}")
                # Add empty block instead of skipping
                blocks.append({
                    'number': i,
                    'hash': '0x' + '0' * 64,
                    'timestamp': 0,
                    'transactions': [],
                    'transaction_count': 0,
                    'error': str(e)
                })
                continue
        
        # Sort blocks by number (newest first)
        blocks.sort(key=lambda x: x['number'], reverse=True)
        
        print(f"Processed {current_block + 1} blocks, found {len(blocks)} valid blocks with {total_transactions} total transactions")
        
        # Create data structure for template
        transaction_data = {
            'summary': {
                'current_block': current_block,
                'total_blocks': len(blocks),
                'total_transactions': total_transactions
            },
            'blocks': blocks
        }
        
        return render_template('admin_transaction_history.html',
                             transaction_data=transaction_data,
                             tab_session_id=tab_session.session_id)
                             
    except Exception as e:
        flash(f'Error connecting to blockchain: {str(e)}', 'error')
        transaction_data = {
            'summary': {
                'current_block': 0,
                'total_blocks': 0,
                'total_transactions': 0
            },
            'blocks': []
        }
        return render_template('admin_transaction_history.html',
                             transaction_data=transaction_data,
                             tab_session_id=tab_session.session_id)

@admin_bp.route('/onchainid-dashboard')
def onchainid_dashboard():
    """Admin OnchainID dashboard with dropdown to select different OnchainIDs"""
    try:
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        print(f"🔍 OnchainID Dashboard - Tab session ID: {tab_session_id}")
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        print(f"🔍 OnchainID Dashboard - Tab session created: {tab_session.session_id}")
        
        # Get current user from tab session
        user = get_current_user_from_tab_session(tab_session.session_id)
        print(f"🔍 OnchainID Dashboard - Current user: {user.username if user else 'None'} (type: {user.user_type if user else 'None'})")
        
        if not user or user.user_type != 'admin':
            print(f"❌ OnchainID Dashboard - Access denied for user: {user.username if user else 'None'}")
            flash('Admin access required.', 'error')
            return redirect(url_for('admin.login', tab_session=tab_session.session_id))
        
        # Get selected OnchainID from query parameter
        selected_onchainid = request.args.get('onchainid')
        
        # Get all users with OnchainIDs
        users_with_onchainids = User.query.filter(User.onchain_id.isnot(None)).all()
        
        # Create list of OnchainIDs with role names
        onchainid_list = []
        for user_obj in users_with_onchainids:
            onchainid_list.append({
                'address': user_obj.onchain_id,
                'role': user_obj.user_type,
                'username': user_obj.username,
                'wallet': user_obj.wallet_address
            })
        
        # Get details for selected OnchainID
        onchainid_details = None
        if selected_onchainid:
            try:
                print(f"🔍 Loading OnchainID details for: {selected_onchainid}")
                from services.onchainid_service import OnchainIDService
                from services.web3_service import Web3Service
                
                # Use Account 0 for admin access
                account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
                web3_service = Web3Service(private_key=account_0_private_key)
                onchainid_service = OnchainIDService(web3_service)
                
                onchainid_details = onchainid_service.get_onchainid_details(selected_onchainid)
                print(f"✅ OnchainID details loaded successfully")
            except Exception as e:
                print(f"❌ Error loading OnchainID details: {str(e)}")
                flash(f'Error loading OnchainID details: {str(e)}', 'error')
        
        return render_template('admin_onchainid_dashboard.html', 
                             onchainid_list=onchainid_list,
                             selected_onchainid=selected_onchainid,
                             onchainid_details=onchainid_details,
                             tab_session_id=tab_session.session_id)
    except Exception as e:
        print(f"❌ OnchainID Dashboard - Unexpected error: {str(e)}")
        flash(f'Unexpected error: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard', tab_session=tab_session_id))


