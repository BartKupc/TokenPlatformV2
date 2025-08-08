from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import db
from models.user import User
from models.token import Token, TokenInterest, TokenPurchaseRequest, InvestorVerification
from services.web3_service import Web3Service
from services.trex_service import TREXService
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session
from utils.auth_utils import hash_password
from datetime import datetime
from utils.claims_utils import get_user_missing_claims

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
                    balance = web3_service.from_units(balance_wei, 18)
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