from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from models import db
from models.user import User
from models.token import Token, TokenInterest, TokenPurchaseRequest, InvestorVerification
from services.web3_service import Web3Service
from services.trex_service import TREXService
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session
from utils.auth_utils import hash_password
from datetime import datetime
from utils.claims_utils import get_user_missing_claims

# Import the shared MetaMask handler
from utils.metamask_handler import handle_metamask_transaction_core

investor_bp = Blueprint('investor', __name__, url_prefix='/investor')

@investor_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Investor login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('investor_login.html')
        
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Check credentials
        user = User.query.filter_by(username=username, user_type='investor').first()
        if user and user.password_hash == hash_password(password):
            from utils.session_utils import login_user_to_tab_session
            login_user_to_tab_session(tab_session.session_id, user)
            flash('Login successful!', 'success')
            return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
        else:
            flash('Invalid credentials.', 'error')
    
    return render_template('investor_login.html')

@investor_bp.route('/dashboard')
def dashboard():
    """Investor dashboard"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get all available tokens
    tokens = Token.query.all()
    
    # Get user's missing claims for each token
    missing_claims = get_user_missing_claims(user.id)
    
    # Get user's interest requests
    interest_requests = TokenInterest.query.filter_by(investor_id=user.id).all()
    
    # Get user's purchase requests
    purchase_requests = TokenPurchaseRequest.query.filter_by(investor_id=user.id).all()
    
    # Compute on-chain verification for completed purchases to ensure web3 truth
    purchase_verifications = {}
    try:
        web3_service_v = Web3Service()
        trex_service_v = TREXService(web3_service_v)
        for pr in purchase_requests:
            try:
                if pr.status == 'completed' and pr.token and getattr(pr.token, 'token_address', None):
                    v = trex_service_v.check_user_verification(token_address=pr.token.token_address, user_address=user.wallet_address)
                    if v.get('success'):
                        purchase_verifications[pr.id] = 'verified' if v.get('verified') else 'failed'
            except Exception:
                continue
    except Exception:
        pass
    
    # Compute on-chain holdings for this investor (web3-based)
    my_holdings = []
    try:
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        for t in tokens:
            if not getattr(t, 'token_address', None):
                continue
            try:
                balance_wei = web3_service.call_contract_function('Token', t.token_address, 'balanceOf', user.wallet_address)
                try:
                    balance = web3_service.format_units(balance_wei, 18)
                except Exception:
                    balance = float(balance_wei) / (10 ** 18)
                if balance and balance > 0:
                    # Web3 verification via Identity Registry isVerified
                    verification = trex_service.check_user_verification(token_address=t.token_address, user_address=user.wallet_address)
                    my_holdings.append({
                        'token': t,
                        'balance': balance,
                        'verified': verification.get('verified', False)
                    })
            except Exception:
                continue
    except Exception:
        my_holdings = []
    
    return render_template('investor_dashboard.html',
                         user=user,
                         available_tokens=tokens,
                         missing_claims=missing_claims,
                         user_interests=interest_requests,
                         purchase_requests=purchase_requests,
                         purchase_verifications=purchase_verifications,
                         my_holdings=my_holdings,
                         tab_session_id=tab_session.session_id)

@investor_bp.route('/express-interest/<int:token_id>', methods=['POST'])
def express_interest(token_id):
    """Express interest in a token"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Check if user already has interest request for this token
    existing_interest = TokenInterest.query.filter_by(
        token_id=token_id,
        investor_id=user.id
    ).first()
    
    if existing_interest:
        flash('You have already expressed interest in this token.', 'info')
        return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
    
    try:
        # Create interest request (no amount needed yet)
        interest = TokenInterest(
            token_id=token_id,
            investor_id=user.id,
            amount_requested=0,  # Will be set when purchase is requested
            status='pending'
        )
        db.session.add(interest)
        db.session.commit()
        
        flash(f'Interest expressed in {token.symbol}! Waiting for issuer approval.', 'success')
        
    except Exception as e:
        flash(f'Error expressing interest: {str(e)}', 'error')
    
    return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))

@investor_bp.route('/kyc-submission', methods=['POST'])
def kyc_submission():
    """Submit KYC information"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get form data
    full_name = request.form.get('full_name')
    nationality = request.form.get('nationality')
    date_of_birth = request.form.get('date_of_birth')
    
    if not all([full_name, nationality, date_of_birth]):
        flash('All fields are required.', 'error')
        return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
    
    try:
        # Store KYC data as JSON
        import json
        kyc_data = {
            'full_name': full_name,
            'nationality': nationality,
            'date_of_birth': date_of_birth,
            'submitted_at': datetime.utcnow().isoformat()
        }
        
        # Update user with KYC information
        user.full_name = full_name
        user.nationality = nationality
        user.date_of_birth = date_of_birth
        user.kyc_data = json.dumps(kyc_data)
        user.kyc_status = 'pending'
        
        db.session.commit()
        
        flash('KYC information submitted successfully! Your application will be reviewed by a trusted issuer.', 'success')
        
    except Exception as e:
        flash(f'Error submitting KYC information: {str(e)}', 'error')
    
    return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))

@investor_bp.route('/status')
def status():
    """Check investor KYC status"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    # If no user in session, check if wallet address is provided in query params
    if not user:
        wallet_address = request.args.get('wallet_address')
        if wallet_address:
            user = User.query.filter_by(wallet_address=wallet_address, user_type='investor').first()
    
    return render_template('investor_status.html',
                         user=user,
                         tab_session_id=tab_session.session_id if tab_session else None)

@investor_bp.route('/request-purchase/<int:token_id>', methods=['GET', 'POST'])
def request_purchase(token_id):
    """Request to purchase tokens"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Check if user has approved interest for this token
    approved_interest = TokenInterest.query.filter_by(
        token_id=token_id,
        investor_id=user.id,
        status='approved'
    ).first()
    
    if not approved_interest:
        flash('You need to have approved interest in this token before requesting purchase.', 'error')
        return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
    
    if request.method == 'POST':
        # Get form data
        amount_requested = request.form.get('amount_requested')
        price_per_token = token.price_per_token
        
        if not amount_requested:
            flash('Amount requested is required.', 'error')
            return redirect(url_for('investor.request_purchase', token_id=token_id, tab_session=tab_session.session_id))
        
        try:
            amount_requested = int(amount_requested)
            if amount_requested <= 0:
                flash('Amount must be greater than 0.', 'error')
                return redirect(url_for('investor.request_purchase', token_id=token_id, tab_session=tab_session.session_id))
            
            # Calculate total value
            total_value = amount_requested * price_per_token
            
            # Create purchase request
            purchase_request = TokenPurchaseRequest(
                token_id=token_id,
                investor_id=user.id,
                amount_requested=amount_requested,
                price_per_token=price_per_token,
                total_value=total_value,
                status='pending'
            )
            db.session.add(purchase_request)
            db.session.commit()
            
            flash(f'Purchase request submitted for {amount_requested} {token.symbol}!', 'success')
            return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
            
        except ValueError:
            flash('Invalid amount.', 'error')
            return redirect(url_for('investor.request_purchase', token_id=token_id, tab_session=tab_session.session_id))
    
    return render_template('investor_request_purchase.html',
                         user=user,
                         token=token,
                         tab_session_id=tab_session.session_id)

@investor_bp.route('/purchase-requests')
def purchase_requests():
    """View all purchase requests for the investor"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get all purchase requests for this user
    purchase_requests = TokenPurchaseRequest.query.filter_by(investor_id=user.id).order_by(TokenPurchaseRequest.created_at.desc()).all()
    
    return render_template('investor_purchase_requests.html',
                         user=user,
                         purchase_requests=purchase_requests,
                         tab_session_id=tab_session.session_id)

@investor_bp.route('/execute-purchase/<int:request_id>', methods=['POST'])
def execute_purchase(request_id):
    """Execute an approved purchase request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        flash('Investor access required.', 'error')
        return redirect(url_for('investor.login', tab_session=tab_session.session_id))
    
    # Get purchase request
    purchase_request = TokenPurchaseRequest.query.get_or_404(request_id)
    
    # Verify ownership
    if purchase_request.investor_id != user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
    
    # Check if request is approved
    if purchase_request.status != 'approved':
        flash('Only approved purchase requests can be executed.', 'error')
        return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
    
    try:
        # Mark as completed
        purchase_request.status = 'completed'
        purchase_request.purchase_completed_at = datetime.utcnow()
        db.session.commit()
        
        flash(f'Purchase completed for {purchase_request.amount_requested} {purchase_request.token.symbol}!', 'success')
        
    except Exception as e:
        flash(f'Error executing purchase: {str(e)}', 'error')
    
    return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))

@investor_bp.route('/transfer-tokens', methods=['GET', 'POST'])
def transfer_tokens():
    """Transfer tokens to another address (form-based)"""
    try:
        print(f"DEBUG: transfer_tokens called with method: {request.method}")
        
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Get current user from tab session
        user = get_current_user_from_tab_session(tab_session.session_id)
        
        if not user or user.user_type != 'investor':
            flash('Investor access required.', 'error')
            return redirect(url_for('investor.login', tab_session=tab_session.session_id))
        
        if request.method == 'GET':
            return "Transfer form - GET method working", 200
            
        if request.method == 'POST':
            # Handle form-based transfer (legacy)
            flash('Transfer functionality is being updated. Please use the new transfer interface.', 'info')
            return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))
    
    except Exception as e:
        print(f"DEBUG: Unexpected error in transfer_tokens: {str(e)}")
        flash(f'Unexpected error: {str(e)}', 'error')
        return redirect(url_for('investor.dashboard', tab_session=tab_session.session_id))

@investor_bp.route('/build-transfer-transaction', methods=['POST'])
def build_transfer_transaction():
    """Build transfer transaction for MetaMask signing (JSON-based)"""
    try:
        print(f"DEBUG: build_transfer_transaction called")
        
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Get current user from tab session
        user = get_current_user_from_tab_session(tab_session.session_id)
        
        if not user or user.user_type != 'investor':
            return jsonify({'success': False, 'error': 'Investor access required.'}), 401
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data received.'}), 400
        
        print(f"DEBUG: JSON data received: {data}")
        token_id = data.get('token_id')
        to_address = data.get('to_address')
        amount = data.get('amount')
        
        print(f"DEBUG: Data received - token_id: {token_id}, to_address: {to_address}, amount: {amount}")
        
        if not all([token_id, to_address, amount]):
            return jsonify({'success': False, 'error': 'All fields are required.'}), 400
        
        try:
            token_id = int(token_id)
            amount = int(amount)
            
            if amount <= 0:
                return jsonify({'success': False, 'error': 'Amount must be greater than 0.'}), 400
            
            # Validate Ethereum address format
            if not to_address.startswith('0x') or len(to_address) != 42:
                return jsonify({'success': False, 'error': 'Invalid Ethereum address format.'}), 400
            
            # Get token
            token = Token.query.get_or_404(token_id)
            print(f"DEBUG: Token found: {token.name} at {token.token_address}")
            
            # Check if user has sufficient balance
            try:
                from services.web3_service import Web3Service
                web3_service = Web3Service()
                balance_wei = web3_service.call_contract_function('Token', token.token_address, 'balanceOf', user.wallet_address)
                balance = web3_service.format_units(balance_wei, 18)
                print(f"DEBUG: User balance: {balance} {token.symbol}")
                
                if balance < amount:
                    return jsonify({'success': False, 'error': f'Insufficient balance. You have {balance:,.0f} {token.symbol}, trying to transfer {amount:,.0f}.'}), 400
                    
            except Exception as e:
                print(f"DEBUG: Error checking balance: {str(e)}")
                return jsonify({'success': False, 'error': f'Error checking balance: {str(e)}'}), 500
            
            # Check if recipient is verified
            try:
                from services.trex_service import TREXService
                trex_service = TREXService(web3_service)
                verification_result = trex_service.check_user_verification(
                    token_address=token.token_address,
                    user_address=to_address
                )
                print(f"DEBUG: Verification result: {verification_result}")
                
                if not verification_result.get('success') or not verification_result.get('verified'):
                    return jsonify({'success': False, 'error': f'Recipient address {to_address} is not verified for this token. Transfer will fail.'}), 400
                    
            except Exception as e:
                print(f"DEBUG: Error checking recipient verification: {str(e)}")
                return jsonify({'success': False, 'error': f'Error checking recipient verification: {str(e)}'}), 500
            
            # Build transfer transaction for MetaMask
            try:
                print(f"DEBUG: Building transfer transaction for MetaMask...")
                
                # Use read-only Web3 service to build transaction
                web3_service = Web3Service()  # No private key needed for building transactions
                trex_service = TREXService(web3_service)
                
                # Build the transfer transaction
                transfer_result = trex_service.build_transfer_transaction(
                    token_address=token.token_address,
                    from_address=user.wallet_address,
                    to_address=to_address,
                    amount=amount,
                    user_address_for_gas=user.wallet_address
                )
                
                if not transfer_result.get('success'):
                    print(f"DEBUG: Failed to build transfer transaction: {transfer_result.get('error')}")
                    return jsonify({'success': False, 'error': f'Failed to build transfer transaction: {transfer_result.get("error")}'}), 500
                
                print(f"DEBUG: Transfer transaction built successfully")
                
                # Return transaction data to frontend for MetaMask signing
                return jsonify({
                    'success': True,
                    'message': f'Ready to transfer {amount:,.0f} {token.symbol} to {to_address}',
                    'transaction': transfer_result['transaction'],
                    'token_id': token_id,
                    'amount': amount,
                    'to_address': to_address,
                    'token_symbol': token.symbol
                })
                    
            except Exception as e:
                print(f"DEBUG: Error building transfer transaction: {str(e)}")
                import traceback
                traceback.print_exc()
                return jsonify({'success': False, 'error': f'Error building transfer transaction: {str(e)}'}), 500
                
        except ValueError as ve:
            print(f"DEBUG: ValueError parsing token_id or amount: {str(ve)}")
            return jsonify({'success': False, 'error': 'Invalid amount or token ID.'}), 400
        except Exception as e:
            print(f"DEBUG: Unexpected error in processing: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': f'Error processing transfer: {str(e)}'}), 500
    
    except Exception as e:
        print(f"DEBUG: Unexpected error in build_transfer_transaction: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'}), 500

@investor_bp.route('/check-verification', methods=['POST'])
def check_verification():
    """Check if an address is verified for a specific token using the same logic as issuer KYC verification"""
    print("DEBUG: check_verification route called!")
    print("DEBUG: request.method:", request.method)
    print("DEBUG: request.headers:", dict(request.headers))
    print("DEBUG: request.get_json():", request.get_json())
    
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    print("DEBUG: tab_session_id from args:", tab_session_id)
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    print("DEBUG: tab_session:", tab_session)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    print("DEBUG: user:", user)
    
    if not user or user.user_type != 'investor':
        print("DEBUG: User validation failed - user:", user, "user_type:", getattr(user, 'user_type', 'None') if user else 'None')
        return jsonify({'success': False, 'error': 'Investor access required.'})
    
    try:
        data = request.get_json()
        token_id = data.get('token_id')
        address_to_check = data.get('address')
        
        if not token_id or not address_to_check:
            return jsonify({'success': False, 'error': 'Token ID and address to check are required.'})
        
        # Get the token to find its address and Identity Registry
        from models.token import Token
        token = Token.query.get(token_id)
        
        if not token:
            return jsonify({'success': False, 'error': 'Token not found.'})
        
        if not token.token_address:
            return jsonify({'success': False, 'error': 'Token has no blockchain address.'})
        
        # Use the same logic as issuer KYC verification
        from services.web3_service import Web3Service
        from services.trex_service import TREXService
        
        # Check if token has Identity Registry configured
        if not token.identity_registry_address:
            return jsonify({'success': False, 'error': 'Token has no Identity Registry configured'})
        
        # Use read-only Web3 service (no private key needed for verification checks)
        web3_service = Web3Service()  # No private key for read-only calls
        trex_service = TREXService(web3_service)
        
        # Check if user is verified using Identity Registry's isVerified() method
        # First check if user has an OnchainID registered
        onchain_id_address = web3_service.call_contract_function(
            'IdentityRegistry',
            token.identity_registry_address,
            'identity',
            address_to_check
        )
        
        if onchain_id_address == '0x0000000000000000000000000000000000000000':
            return jsonify({
                'success': True,
                'verified': False,
                'reason': 'User has no OnchainID registered',
                'address': address_to_check,
                'token_name': token.name,
                'token_symbol': token.symbol
            })
        
        # Check if user is verified using Identity Registry's isVerified() method
        is_verified = web3_service.call_contract_function(
            'IdentityRegistry',
            token.identity_registry_address,
            'isVerified',
            address_to_check
        )
        
        if is_verified:
            return jsonify({
                'success': True,
                'verified': True,
                'reason': 'User is verified',
                'address': address_to_check,
                'token_name': token.name,
                'token_symbol': token.symbol
            })
        else:
            return jsonify({
                'success': True,
                'verified': False,
                'reason': 'User is not verified by Identity Registry',
                'address': address_to_check,
                'token_name': token.name,
                'token_symbol': token.symbol
            })
        

            
    except Exception as e:
        print(f"DEBUG: Error in check_verification: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Error checking verification: {str(e)}'})

@investor_bp.route('/token/<int:token_id>/metamask-transaction', methods=['POST'])
def handle_investor_metamask_transaction(token_id):
    """MetaMask transaction handler for investor operations"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        return jsonify({'success': False, 'error': 'Investor access required.'}), 401
    
    return handle_metamask_transaction_core(token_id, 'investor', user)

@investor_bp.route('/execute-transfer', methods=['POST'])
def execute_transfer():
    """Execute transfer after MetaMask signing"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'investor':
        return jsonify({'success': False, 'error': 'Investor access required.'}), 401
    
    try:
        data = request.get_json()
        token_id = data.get('token_id')
        amount = data.get('amount')
        to_address = data.get('to_address')
        tx_hash = data.get('tx_hash')
        
        if not all([token_id, amount, to_address, tx_hash]):
            return jsonify({'success': False, 'error': 'Missing required data'})
        
        # Get token
        token = Token.query.get_or_404(token_id)
        
        # Create transaction record
        from models.token import TokenTransaction
        transaction = TokenTransaction(
            token_id=token_id,
            transaction_type='transfer',
            from_address=user.wallet_address,
            to_address=to_address,
            amount=amount,
            executed_by=user.id,
            transaction_hash=tx_hash
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully transferred {amount} {token.symbol} to {to_address}!',
            'tx_hash': tx_hash
        })
        
    except Exception as e:
        print(f"DEBUG: Error executing transfer: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Error executing transfer: {str(e)}'})