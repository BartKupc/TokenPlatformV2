from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from models import db
from models.user import User, TrustedIssuerCapability
from models.token import Token, TokenInterest, TokenPurchaseRequest, TokenTransaction, InvestorVerification
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session
from utils.auth_utils import hash_password, encrypt_private_key, decrypt_private_key
from services.trex_service import TREXService
from services.web3_service import Web3Service
from services.transaction_indexer import TransactionIndexer
from utils.contract_utils import store_contract
import json

issuer_bp = Blueprint('issuer', __name__, url_prefix='/issuer')

@issuer_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Issuer login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('issuer_login.html')
        
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Check credentials
        user = User.query.filter_by(username=username, user_type='issuer').first()
        if user and user.password_hash == hash_password(password):
            from utils.session_utils import login_user_to_tab_session
            login_user_to_tab_session(tab_session.session_id, user)
            flash('Login successful!', 'success')
            return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
        else:
            flash('Invalid credentials.', 'error')
    
    return render_template('issuer_login.html')

@issuer_bp.route('/dashboard')
def dashboard():
    """Issuer dashboard"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get all tokens (for browsing) and user's own tokens (for management)
    tokens = Token.query.all()  # Show all tokens for browsing
    user_tokens = Token.query.filter_by(issuer_address=user.wallet_address).all()
    
    # Get selected token if token_id is provided
    selected_token = None
    token_id = request.args.get('token_id')
    if token_id:
        try:
            selected_token = Token.query.get(int(token_id))
            # Allow viewing any token (for potential purchase)
            if not selected_token:
                flash('Token not found.', 'error')
                return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
        except (ValueError, TypeError):
            flash('Invalid token ID.', 'error')
            return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    return render_template('issuer_dashboard.html',
                         user=user,
                         tokens=tokens,  # All tokens for browsing
                         user_tokens=user_tokens,  # User's own tokens for management
                         selected_token=selected_token,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/token/<int:token_id>/view')
def view_token(token_id):
    """View any token (for browsing/potential purchase)"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    return render_template('issuer_token_view.html',
                         token=token,
                         user=user,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/deploy-token', methods=['GET'])
def deploy_token():
    """Deploy a new token page - now uses MetaMask flow"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # MetaMask deployment is now handled by the general MetaMask route
    # This page just displays the deployment form
    if False:  # request.method == 'POST':  # Disabled - now uses MetaMask
        try:
            print("🔍 DEBUG: Form data received")
            print(f"   token_name: {request.form.get('token_name')}")
            print(f"   token_symbol: {request.form.get('token_symbol')}")
            print(f"   total_supply: {request.form.get('total_supply')}")
            print(f"   claim_issuer_id: {request.form.get('claim_issuer_id')}")
            print(f"   claim_topics: {request.form.getlist('claim_topics')}")
            print(f"   description: {request.form.get('description')}")
            print(f"   price_per_token: {request.form.get('price_per_token')}")
            print(f"   ir_agent: issuer (auto-set)")
            print(f"   token_agent: issuer (auto-set)")
            
            # Get form data
            token_name = request.form.get('token_name')
            token_symbol = request.form.get('token_symbol')
            total_supply = request.form.get('total_supply')
            claim_issuer_id = request.form.get('claim_issuer_id')
            claim_topics = request.form.getlist('claim_topics')
            description = request.form.get('description', '')
            price_per_token = request.form.get('price_per_token', '1.00')
            
            # Set initial agents to the issuer's wallet address
            ir_agent = user.wallet_address
            token_agent = user.wallet_address
            
            # Validation
            if not all([token_name, token_symbol, total_supply, claim_issuer_id]):
                flash('All required fields must be filled.', 'error')
                return render_template('deploy_token.html', 
                                     trusted_issuers=get_trusted_issuers(),
                                     tab_session_id=tab_session.session_id)
            
            if not claim_topics:
                flash('At least one claim topic is required.', 'error')
                return render_template('deploy_token.html', 
                                     trusted_issuers=get_trusted_issuers(),
                                     tab_session_id=tab_session.session_id)
            
            # For now, use the user's private key directly (no password required)
            # In production, you might want to add password confirmation
            private_key = user.private_key
            
            # Initialize services
            web3_service = Web3Service(private_key)
            trex_service = TREXService(web3_service)
            
            # Validate that the trusted issuer exists and has a ClaimIssuer contract
            trusted_issuer = User.query.get(claim_issuer_id)
            if not trusted_issuer or not trusted_issuer.claim_issuer_address:
                flash('Selected trusted issuer does not have a ClaimIssuer contract.', 'error')
                return render_template('deploy_token.html', 
                                     trusted_issuers=get_trusted_issuers(),
                                     tab_session_id=tab_session.session_id)
            
            # Deploy token using the Python script
            print("🚀 Starting token deployment...")
            print(f"   Issuer: {user.wallet_address}")
            print(f"   Token: {token_name} ({token_symbol})")
            print(f"   Supply: {total_supply}")
            print(f"   Claim Topics: {claim_topics}")
            print(f"   Trusted Issuer ID: {claim_issuer_id}")
            
            print(f"🔍 DEBUG: claim_topics from form: {claim_topics}")
            print(f"🔍 DEBUG: claim_topics type: {type(claim_topics)}")
            claim_topics_int = [int(topic) for topic in claim_topics]
            print(f"🔍 DEBUG: claim_topics_int: {claim_topics_int}")
            
            result = trex_service.deploy_token(
                issuer_address=user.wallet_address,
                token_name=token_name,
                token_symbol=token_symbol,
                total_supply=int(total_supply),
                ir_agent=ir_agent,
                token_agent=token_agent,
                claim_topics=claim_topics_int,
                claim_issuer_type='trusted_issuer',
                claim_issuer_id=claim_issuer_id
            )
            
            print(f"🎯 Deployment result: {result}")
            
            if result['success']:
                # Store token in database
                token = Token(
                    token_address=result['token_address'],
                    name=token_name,
                    symbol=token_symbol,
                    total_supply=int(total_supply),
                    issuer_address=user.wallet_address,
                    description=description,
                    price_per_token=float(price_per_token) if price_per_token else 1.00,
                    ir_agent=ir_agent,
                    token_agent=token_agent,
                    claim_topics=','.join(map(str, claim_topics)),
                    claim_issuer_id=claim_issuer_id,
                    claim_issuer_type='trusted_issuer',
                    identity_registry_address=result['identity_registry'],
                    compliance_address=result['compliance'],
                    claim_topics_registry_address=result['claim_topics_registry'],
                    trusted_issuers_registry_address=result['trusted_issuers_registry'],
                    agents=json.dumps({
                        'identity_agents': [ir_agent],
                        'token_agents': [token_agent],
                        'compliance_agents': []
                    })
                )
                db.session.add(token)
                db.session.commit()
                
                flash(f'Token {token_symbol} deployed successfully!', 'success')
                # Redirect to dashboard with the newly created token selected
                return redirect(url_for('issuer.dashboard', token_id=token.id, tab_session=tab_session.session_id))
            else:
                flash(f'Token deployment failed: {result["error"]}', 'error')
                
        except Exception as e:
            flash(f'Error deploying token: {str(e)}', 'error')
    
    # Get available agents and trusted issuers for form
    from utils.claims_utils import get_trusted_issuers
    trusted_issuers = get_trusted_issuers()
    
    return render_template('deploy_token.html',
                         trusted_issuers=trusted_issuers,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/token/<int:token_id>/actions')
def token_actions(token_id):
    """Token actions page"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get all user's tokens for the dropdown
    tokens = Token.query.filter_by(issuer_address=user.wallet_address).all()

    # Get real blockchain pause status
    blockchain_paused = False
    try:
        web3_service = Web3Service(user.private_key)
        # Convert token address to checksum format
        checksum_token_address = web3_service.w3.to_checksum_address(token.token_address)
        print(f"🔍 Checking pause status for token:")
        print(f"   Original address: {token.token_address}")
        print(f"   Checksum address: {checksum_token_address}")
        blockchain_paused = web3_service.call_contract_function('Token', checksum_token_address, 'paused')
    except Exception as e:
        print(f"Error getting blockchain pause status: {e}")
        blockchain_paused = token.is_paused  # Fallback to database status

    # Build investors list: investors who are KYC verified OR have completed purchases
    investors = []
    try:
        from models.user import User as DbUser
        from models.token import TokenPurchaseRequest, TokenInterest
        
        # Get all completed purchase requests for this token
        completed_requests = TokenPurchaseRequest.query.filter_by(
            token_id=token_id,
            status='completed'
        ).all()
        
        # Get all KYC verified interest requests for this token
        kyc_verified_interests = TokenInterest.query.filter_by(
            token_id=token_id,
            kyc_verified=True
        ).all()
        
        # Get unique investors from completed requests
        approved_investor_ids = set()
        for purchase_request in completed_requests:
            approved_investor_ids.add(purchase_request.investor_id)
        
        # Get unique investors from KYC verified interests
        for interest in kyc_verified_interests:
            approved_investor_ids.add(interest.investor_id)
        
        # Get investor details for approved investors
        for investor_id in approved_investor_ids:
            investor = DbUser.query.get(investor_id)
            if investor and investor.user_type == 'investor':
                investors.append(investor)
                
    except Exception as e:
        print(f"Error getting approved investors: {e}")
        investors = []
    
    return render_template('issuer_token_actions.html',
                         token=token,
                         tokens=tokens,
                         investors=investors,
                         blockchain_paused=blockchain_paused,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/token/<int:token_id>/agents')
def token_agents(token_id):
    """Token agents management"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get current agents from token configuration
    # Parse agents from JSON if they exist, otherwise use legacy single agent fields
    raw_agents = {
        'identity_agents': [],
        'token_agents': [],
        'compliance_agents': []  # Not implemented yet
    }
    
    # Check if token has the new JSON agents field
    if hasattr(token, 'agents') and token.agents:
        try:
            agents_data = json.loads(token.agents)
            raw_agents['identity_agents'] = agents_data.get('identity_agents', [])
            raw_agents['token_agents'] = agents_data.get('token_agents', [])
            raw_agents['compliance_agents'] = agents_data.get('compliance_agents', [])
        except (json.JSONDecodeError, TypeError):
            # Fallback to legacy single agent fields
            if token.ir_agent:
                raw_agents['identity_agents'] = [token.ir_agent]
            if token.token_agent:
                raw_agents['token_agents'] = [token.token_agent]
    else:
        # Legacy: use single agent fields
        if token.ir_agent:
            raw_agents['identity_agents'] = [token.ir_agent]
        if token.token_agent:
            raw_agents['token_agents'] = [token.token_agent]
    
    # Convert agent addresses to user information
    agents = {
        'identity_agents': [],
        'token_agents': [],
        'compliance_agents': []
    }
    
    # Helper function to get agent info
    def get_agent_info(agent_address):
        if not agent_address:
            return None
        
        # Check if it's a wallet address
        user = User.query.filter_by(wallet_address=agent_address).first()
        if user:
            return {
                'address': agent_address,
                'username': user.username,
                'role': user.user_type,
                'wallet_address': user.wallet_address
            }
        
        # Check if it's a role string (legacy)
        if agent_address in ['issuer', 'admin']:
            return {
                'address': agent_address,
                'username': f'{agent_address.title()} Account',
                'role': agent_address,
                'wallet_address': 'Role-based permission'
            }
        
        # Fallback
        return {
            'address': agent_address,
            'username': 'Unknown',
            'role': 'Unknown',
            'wallet_address': agent_address
        }
    
    # Convert each agent list
    for agent_type in ['identity_agents', 'token_agents', 'compliance_agents']:
        for agent_address in raw_agents[agent_type]:
            agent_info = get_agent_info(agent_address)
            if agent_info:
                agents[agent_type].append(agent_info)
    
    # Get trusted issuers already assigned to this token with their capabilities
    trusted_issuers = []
    if token.trusted_issuers:
        try:
            trusted_issuer_ids = json.loads(token.trusted_issuers)
            # Get trusted issuers with their capabilities
            trusted_issuers_data = db.session.query(
                User, 
                db.func.group_concat(TrustedIssuerCapability.claim_topic).label('claim_topics')
            ).outerjoin(
                TrustedIssuerCapability, 
                User.id == TrustedIssuerCapability.trusted_issuer_id
            ).filter(
                User.id.in_(trusted_issuer_ids),
                User.user_type == 'trusted_issuer'
            ).group_by(User.id).all()
            
            # Convert to list of dicts for template
            for user, claim_topics in trusted_issuers_data:
                trusted_issuers.append({
                    'id': user.id,
                    'username': user.username,
                    'wallet_address': user.wallet_address,
                    'claim_topics': [int(topic) for topic in claim_topics.split(',')] if claim_topics else []
                })
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Error parsing trusted_issuers: {e}")
            trusted_issuers = []
    
    # Get all available trusted issuers for selection with their capabilities
    available_trusted_issuers_data = db.session.query(
        User, 
        db.func.group_concat(TrustedIssuerCapability.claim_topic).label('claim_topics')
    ).outerjoin(
        TrustedIssuerCapability, 
        User.id == TrustedIssuerCapability.trusted_issuer_id
    ).filter(
        User.user_type == 'trusted_issuer'
    ).group_by(User.id).all()
    
    # Convert to list of dicts for template
    available_trusted_issuers = []
    for user, claim_topics in available_trusted_issuers_data:
        available_trusted_issuers.append({
            'id': user.id,
            'username': user.username,
            'wallet_address': user.wallet_address,
            'claim_issuer_address': user.claim_issuer_address,  # ← Add ClaimIssuer contract address!
            'capabilities_json': json.dumps([int(topic) for topic in claim_topics.split(',')] if claim_topics else [])
        })
    
    # Get all user's tokens for the dropdown
    tokens = Token.query.filter_by(issuer_address=user.wallet_address).all()
    
    
    
    return render_template('issuer_token_agents.html',
                         token=token,
                         agents=agents,
                         tokens=tokens,
                         trusted_issuers=trusted_issuers,
                         available_trusted_issuers=available_trusted_issuers,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/token/<int:token_id>/debug-ownership')
def debug_token_ownership(token_id):
    """Debug route to check who owns the token's contracts"""
    try:
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Get current user from tab session
        user = get_current_user_from_tab_session(tab_session.session_id)
        
        if not user or user.user_type != 'issuer':
            return jsonify({'success': False, 'error': 'Issuer access required'}), 403
        
        # Get token
        token = Token.query.get_or_404(token_id)
        
        # Verify ownership
        if token.issuer_address != user.wallet_address:
            return jsonify({'success': False, 'error': 'Access denied. You can only manage your own tokens.'}), 403
        
        # Initialize services with Account 0
        account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        web3_service = Web3Service(private_key=account_0_private_key)
        trex_service = TREXService(web3_service)
        
        debug_info = {
            'token_address': token.token_address,
            'issuer_address': user.wallet_address,
            'account_0_address': web3_service.account.address,
            'contracts': {}
        }
        
        try:
            # Get token info
            token_info = trex_service.get_token_info(token.token_address)
            if token_info.get('success') and token_info.get('token_info'):
                debug_info['contracts']['token_info'] = token_info['token_info']
                
                # Check Identity Registry ownership
                if token_info['token_info'].get('identity_registry'):
                    ir_address = token_info['token_info']['identity_registry']
                    debug_info['contracts']['identity_registry'] = {
                        'address': ir_address,
                        'owner': web3_service.call_contract_function('IdentityRegistry', ir_address, 'owner')
                    }
                    
                    # Check TrustedIssuersRegistry ownership
                    try:
                        tir_address = web3_service.call_contract_function('IdentityRegistry', ir_address, 'issuersRegistry')
                        debug_info['contracts']['trusted_issuers_registry'] = {
                            'address': tir_address,
                            'owner': web3_service.call_contract_function('TrustedIssuersRegistry', tir_address, 'owner')
                        }
                    except Exception as e:
                        debug_info['contracts']['trusted_issuers_registry'] = {'error': str(e)}
                
                # Check Token contract ownership
                if token_info['token_info'].get('token'):
                    token_contract_address = token_info['token_info']['token']
                    debug_info['contracts']['token_contract'] = {
                        'address': token_contract_address,
                        'owner': web3_service.call_contract_function('Token', token_contract_address, 'owner')
                    }
                    
        except Exception as e:
            debug_info['error'] = str(e)
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@issuer_bp.route('/token/<int:token_id>/remove-trusted-issuer', methods=['POST'])
def remove_trusted_issuer_from_token(token_id):
    """Remove a trusted issuer from a token's Identity Registry"""
    try:
        # Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        trusted_issuer_id = data.get('trusted_issuer_id')
        
        if not trusted_issuer_id:
            return jsonify({'success': False, 'error': 'Missing trusted issuer ID'}), 400
        
        # Get tab session ID from request
        tab_session_id = data.get('tab_session')
        if not tab_session_id:
            return jsonify({'success': False, 'error': 'No tab session provided'}), 400
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Get current user from tab session
        user = get_current_user_from_tab_session(tab_session.session_id)
        
        if not user or user.user_type != 'issuer':
            return jsonify({'success': False, 'error': 'Issuer access required'}), 403
        
        # Get token
        token = Token.query.get_or_404(token_id)
        
        # Verify ownership
        if token.issuer_address != user.wallet_address:
            return jsonify({'success': False, 'error': 'Access denied. You can only manage your own tokens.'}), 403
        
        # Get trusted issuer
        trusted_issuer = User.query.get_or_404(trusted_issuer_id)
        
        # CRITICAL FIX: Use ClaimIssuer contract address, not wallet address!
        claim_issuer_address = trusted_issuer.claim_issuer_address
        print(f"🔗 Removing trusted issuer {trusted_issuer.username} from token {token.name}")
        print(f"   Trusted Issuer Wallet: {trusted_issuer.wallet_address}")
        print(f"🔗 ClaimIssuer Contract: {claim_issuer_address}")
        
        # Remove trusted issuer from token's Identity Registry via blockchain
        try:
            from services.trex_service import TREXService
            from services.web3_service import Web3Service
            
            # Initialize services
            # IMPORTANT: For trusted issuer management, we need to use Account 0 (platform)
            # because Account 0 owns the TrustedIssuersRegistry
            account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
            web3_service = Web3Service(private_key=account_0_private_key)
            trex_service = TREXService(web3_service)
            
            # Call the token's Identity Registry to remove trusted issuer
            print(f"🚀 Calling blockchain to remove trusted issuer from TIR...")
            
            # DEBUG: Check who owns the TrustedIssuersRegistry
            print(f"🔍 DEBUG: Checking TIR ownership for removal...")
            try:
                # Get the token's Identity Registry address first
                token_info = trex_service.get_token_info(token.token_address)
                if token_info.get('success') and token_info.get('token_info'):
                    identity_registry_address = token_info['token_info'].get('identity_registry')
                    print(f"🔍 DEBUG: Identity Registry address: {identity_registry_address}")
                    
                    if identity_registry_address:
                        # Get the TrustedIssuersRegistry address
                        trusted_issuers_registry_address = web3_service.call_contract_function(
                            'IdentityRegistry', 
                            identity_registry_address, 
                            'issuersRegistry'
                        )
                        print(f"🔍 DEBUG: TrustedIssuersRegistry address: {trusted_issuers_registry_address}")
                        
                        # Check who owns the TrustedIssuersRegistry
                        tir_owner = web3_service.call_contract_function(
                            'TrustedIssuersRegistry', 
                            trusted_issuers_registry_address, 
                            'owner'
                        )
                        print(f"🔍 DEBUG: TIR owner: {tir_owner}")
                        print(f"🔍 DEBUG: Account 0 address: {web3_service.account.address}")
                        print(f"🔍 DEBUG: Owner match: {tir_owner.lower() == web3_service.account.address.lower()}")
                        
                        # Also check if the issuer has any special permissions
                        print(f"🔍 DEBUG: Issuer address: {user.wallet_address}")
                        
                        # Check if issuer is the owner
                        if tir_owner.lower() == user.wallet_address.lower():
                            print(f"🔍 DEBUG: ISSUER is the owner of TIR!")
                            # Use issuer's private key since they own the TIR
                            print(f"🔑 Using ISSUER's private key for TIR management")
                            web3_service = Web3Service(private_key=user.private_key)
                            trex_service = TREXService(web3_service)
                        elif tir_owner.lower() == web3_service.account.address.lower():
                            print(f"🔍 DEBUG: ACCOUNT 0 is the owner of TIR!")
                            # Already using Account 0's key, no need to change
                            print(f"🔑 Using ACCOUNT 0's private key for TIR management")
                        else:
                            print(f"🔍 DEBUG: Neither issuer nor Account 0 owns TIR. Owner: {tir_owner}")
                            # Fallback to issuer's key
                            print(f"🔑 Using ISSUER's private key as fallback")
                            web3_service = Web3Service(private_key=user.private_key)
                            trex_service = TREXService(web3_service)
                            
            except Exception as debug_error:
                print(f"🔍 DEBUG: Error checking ownership: {debug_error}")
                # Fallback to issuer's key
                print(f"🔑 Using ISSUER's private key as fallback")
                web3_service = Web3Service(private_key=user.private_key)
                trex_service = TREXService(web3_service)
            
            # CRITICAL FIX: Pass ClaimIssuer contract address, not wallet address!
            result = trex_service.remove_trusted_issuer_from_token(
                token_address=token.token_address,
                trusted_issuer_address=claim_issuer_address  # ← Use ClaimIssuer contract address!
            )
            
            if result['success']:
                print(f"✅ Successfully removed trusted issuer from blockchain")
                
                # Update token in database to remove this trusted issuer
                current_trusted_issuers = []
                if token.trusted_issuers:
                    try:
                        current_trusted_issuers = json.loads(token.trusted_issuers)
                    except (json.JSONDecodeError, TypeError):
                        current_trusted_issuers = []
                
                if trusted_issuer_id in current_trusted_issuers:
                    current_trusted_issuers.remove(trusted_issuer_id)
                    token.trusted_issuers = json.dumps(current_trusted_issuers)
                    db.session.commit()
                    print(f"✅ Updated token database - removed trusted issuer")
                
                return jsonify({
                    'success': True, 
                    'message': f'Trusted issuer {trusted_issuer.username} removed successfully from token {token.name}'
                })
            else:
                print(f"❌ Blockchain call failed: {result['error']}")
                return jsonify({'success': False, 'error': f'Blockchain integration failed: {result["error"]}'}), 500
                
        except Exception as e:
            print(f"❌ Error removing trusted issuer from blockchain: {str(e)}")
            return jsonify({'success': False, 'error': f'Blockchain integration error: {str(e)}'}), 500
        
    except Exception as e:
        print(f"❌ Error in remove_trusted_issuer_from_token: {str(e)}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500

@issuer_bp.route('/token/<int:token_id>/transactions')
def token_transactions(token_id):
    """Token transactions history"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get all user's tokens for the dropdown
    tokens = Token.query.filter_by(issuer_address=user.wallet_address).all()
    
    # Get blockchain transactions
    try:
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        # Initialize services
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        # Get all transactions from blockchain
        print(f"🔍 Getting transactions for token: {token.token_address}")
        all_transactions = trex_service.get_token_transactions(
            token_address=token.token_address,
            limit=100  # Get more transactions for pagination
        )
        
        # get_token_transactions returns a list directly, not a dict
        if isinstance(all_transactions, list):
            transactions = all_transactions
            print(f"✅ Found {len(transactions)} blockchain transactions")
        else:
            print(f"❌ Error getting blockchain transactions: {all_transactions}")
            transactions = []
            
    except Exception as e:
        print(f"❌ Error initializing services: {str(e)}")
        transactions = []
    
    # No database transactions fallback - just use blockchain data
    db_transactions = []
    
    return render_template('issuer_token_transactions.html',
                         token=token,
                         tokens=tokens,
                         transactions=transactions,
                         db_transactions=db_transactions,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/token/<int:token_id>/requests')
def token_requests(token_id):
    """Token interest requests"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get pending interest requests
    pending_interests = TokenInterest.query.filter_by(
        token_id=token_id,
        status='pending'
    ).all()
    
    # Get approved interest requests
    approved_interests = TokenInterest.query.filter_by(
        token_id=token_id,
        status='approved'
    ).all()
    
    # Get purchase requests (all statuses, newest first)
    purchase_requests = TokenPurchaseRequest.query.filter_by(
        token_id=token_id
    ).order_by(TokenPurchaseRequest.created_at.desc()).all()

    # Get all user's tokens for the dropdown
    tokens = Token.query.filter_by(issuer_address=user.wallet_address).all()
    
    return render_template('issuer_token_requests.html',
                         token=token,
                         tokens=tokens,
                         pending_interests=pending_interests,
                         approved_interests=approved_interests,
                         purchase_requests=purchase_requests,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/token/<int:token_id>/approve-interest/<int:interest_id>')
def approve_token_interest(token_id, interest_id):
    """Approve token interest request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token and interest
    token = Token.query.get_or_404(token_id)
    interest = TokenInterest.query.get_or_404(interest_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Verify interest belongs to this token
    if interest.token_id != token_id:
        flash('Invalid interest request.', 'error')
        return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        # Update interest status
        interest.status = 'approved'
        interest.processed_at = db.func.now()
        interest.processed_by = user.id
        db.session.commit()
        
        flash('Interest request approved!', 'success')
        
    except Exception as e:
        flash(f'Error approving interest: {str(e)}', 'error')
    
    return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))

@issuer_bp.route('/token/<int:token_id>/reject-interest/<int:interest_id>')
def reject_token_interest(token_id, interest_id):
    """Reject token interest request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token and interest
    token = Token.query.get_or_404(token_id)
    interest = TokenInterest.query.get_or_404(interest_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Verify interest belongs to this token
    if interest.token_id != token_id:
        flash('Invalid interest request.', 'error')
        return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        # Update interest status
        interest.status = 'rejected'
        interest.processed_at = db.func.now()
        interest.processed_by = user.id
        db.session.commit()
        
        flash('Interest request rejected.', 'success')
        
    except Exception as e:
        flash(f'Error rejecting interest: {str(e)}', 'error')
    
    return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))

@issuer_bp.route('/token/<int:token_id>/verify-kyc-interest/<int:interest_id>', methods=['POST'])
def verify_kyc_interest(token_id, interest_id):
    """Verify KYC for an interest request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token and interest
    token = Token.query.get_or_404(token_id)
    interest = TokenInterest.query.get_or_404(interest_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Verify interest belongs to this token
    if interest.token_id != token_id:
        flash('Invalid interest request.', 'error')
        return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    # Check if investor has been added to Identity Registry first
    if interest.ir_status != 'added':
        flash('Investor must be added to Identity Registry before KYC verification.', 'warning')
        return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        # Check if investor has OnchainID and KYC claims
        investor = interest.investor
        
        if not investor.onchain_id:
            flash(f'Investor {investor.username} does not have an OnchainID.', 'error')
            return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
        
        # Use the T-REX approach: Check Identity Registry isVerified() method
        try:
            from services.trex_service import TREXService
            from services.web3_service import Web3Service
            
            # Use issuer's private key (who has Agent role)
            private_key = user.private_key
            web3_service = Web3Service(private_key)
            trex_service = TREXService(web3_service)
            
            # Get the token's Identity Registry
            if not token.identity_registry_address:
                flash(f'Token {token.name} has no Identity Registry configured.', 'error')
                return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
            
            # Check if investor is verified using Identity Registry
            verification_result = trex_service.check_user_verification(
                token_address=token.token_address,
                user_address=investor.wallet_address
            )
            
            print(f"🔍 KYC Verification Result: {verification_result}")
            
            if verification_result['success'] and verification_result['verified']:
                # KYC verification successful
                interest.kyc_verified = True
                interest.kyc_verified_at = db.func.now()
                interest.kyc_verified_by = user.id
                db.session.commit()
                
                flash(f'KYC verified for {investor.username}!', 'success')
            else:
                reason = verification_result.get('reason', 'User not verified')
                flash(f'KYC verification failed for {investor.username}: {reason}', 'error')
                return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
                
        except Exception as e:
            flash(f'Error during KYC verification: {str(e)}', 'error')
        
    except Exception as e:
        flash(f'Error verifying KYC: {str(e)}', 'error')
    
    return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))

@issuer_bp.route('/token/<int:token_id>/investors')
def investors_list(token_id):
    """List of investors for a specific token"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get all investors
    investors = User.query.filter_by(user_type='investor').all()
    
    # Get all user's tokens for the dropdown
    tokens = Token.query.filter_by(issuer_address=user.wallet_address).all()
    
    return render_template('issuer_investors_list.html',
                         token=token,
                         investors=investors,
                         tokens=tokens,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/api/token/<int:token_id>/investor/<int:investor_id>')
def api_investor_details(token_id, investor_id):
    """Return real on-chain + DB details for an investor for a specific token"""
    tab_session_id = request.args.get('tab_session')
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    if not user or user.user_type != 'issuer':
        return jsonify({'success': False, 'error': 'Issuer access required'}), 403

    token = Token.query.get_or_404(token_id)
    if token.issuer_address != user.wallet_address:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    investor = User.query.get_or_404(investor_id)

    try:
        # Use issuer's private key for any privileged calls (read calls are fine too)
        web3_service = Web3Service(user.private_key)
        trex_service = TREXService(web3_service)

        # Balance
        balance_wei = web3_service.call_contract_function(
            'Token', token.token_address, 'balanceOf', investor.wallet_address
        )
        # Web3Service likely has from_units, if not, return raw and human as string assuming 18 decimals
        try:
            balance = web3_service.format_units(balance_wei, 18)
        except Exception:
            # Fallback manual conversion
            balance = float(balance_wei) / (10 ** 18)

        # Identity Registry status
        token_info = trex_service.get_token_info(token.token_address)
        identity_registry_address = None
        if token_info.get('success') and token_info.get('token_info'):
            identity_registry_address = token_info['token_info'].get('identity_registry') or token.identity_registry_address

        onchain_id_in_registry = None
        if identity_registry_address:
            onchain_id_in_registry = web3_service.call_contract_function(
                'IdentityRegistry', identity_registry_address, 'identity', investor.wallet_address
            )
        ir_added = bool(onchain_id_in_registry and onchain_id_in_registry != '0x0000000000000000000000000000000000000000')

        # On-chain verification for this token
        verification = trex_service.check_user_verification(token_address=token.token_address, user_address=investor.wallet_address)

        data = {
            'success': True,
            'investor': {
                'id': investor.id,
                'username': investor.username,
                'email': investor.email,
                'wallet_address': investor.wallet_address,
                'onchain_id': investor.onchain_id,
                'kyc_status': investor.kyc_status,
                'created_at': investor.created_at.isoformat() if investor.created_at else None,
            },
            'balance': balance,
            'balance_wei': str(balance_wei),
            'ir_added': ir_added,
            'verified': verification.get('verified', False),
            'verification_reason': verification.get('reason')
        }
        return jsonify(data)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@issuer_bp.route('/api/token/<int:token_id>/investor/<int:investor_id>/check-verification', methods=['POST'])
def api_check_investor_verification(token_id, investor_id):
    """Check on-chain verification (isVerified) for investor for this token"""
    tab_session_id = request.args.get('tab_session')
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    if not user or user.user_type != 'issuer':
        return jsonify({'success': False, 'error': 'Issuer access required'}), 403

    token = Token.query.get_or_404(token_id)
    if token.issuer_address != user.wallet_address:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    investor = User.query.get_or_404(investor_id)
    try:
        web3_service = Web3Service(user.private_key)
        trex_service = TREXService(web3_service)
        verification = trex_service.check_user_verification(token_address=token.token_address, user_address=investor.wallet_address)
        return jsonify({'success': True, **verification})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500



@issuer_bp.route('/token/<int:token_id>/purchase-requests')
def purchase_requests(token_id):
    """Deprecated view; redirect to unified Requests tab"""
    tab_session_id = request.args.get('tab_session')
    return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session_id))

# Import the shared MetaMask handler
from utils.metamask_handler import handle_metamask_transaction_core

@issuer_bp.route('/token/<int:token_id>/metamask-transaction', methods=['POST'])
def handle_metamask_transaction(token_id):
    """Handle MetaMask transactions for issuer operations using TransactionIndexer"""
    try:
        # Get tab session ID from URL parameter
        tab_session_id = request.args.get('tab_session')
        
        # Get or create tab session
        tab_session = get_or_create_tab_session(tab_session_id)
        
        # Get current user from tab session
        user = get_current_user_from_tab_session(tab_session.session_id)
        
        if not user or user.user_type != 'issuer':
            return jsonify({'success': False, 'error': 'Issuer access required.'}), 401
        
        # For deployment (token_id = 0), we don't have a token yet
        if token_id == 0:
            token = None
        else:
            # Get token
            token = Token.query.get_or_404(token_id)
            
            # Verify ownership
            if token.issuer_address != user.wallet_address:
                return jsonify({'success': False, 'error': 'Access denied. You can only manage your own tokens.'}), 403
        
        # Get JSON data from request
        data = request.get_json()
        print(f"🔍 DEBUG: Main route - data received: {data}")
        print(f"🔍 DEBUG: Main route - data type: {type(data)}")
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        operation = data.get('operation')  # 'mint', 'burn', 'pause', etc.
        action = data.get('action')        # 'build' or 'confirm'
        target_type = data.get('target_type')  # 'interest', 'purchase', or 'actions'
        target_id = data.get('target_id')      # interest_id, request_id, or 0 for actions
        
        # For actions tab operations, target_id can be 0
        if operation in ['mint', 'burn', 'pause', 'unpause', 'transfer', 'force_transfer', 'add_ir_agent', 'add_token_agent', 'add_trusted_issuer', 'deploy_token']:
            if not all([operation, action, target_type]):
                return jsonify({'success': False, 'error': f'Missing required parameters for {operation}'}), 400
        else:
            if not all([operation, action, target_type, target_id]):
                return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        # Initialize services
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        transaction_indexer = TransactionIndexer(web3_service)
        
        # Route to appropriate handler based on operation and action
        if action == 'build':
            # Use dedicated handler for token deployment
            if operation == 'deploy_token':
                print(f"🔍 DEBUG: Routing deploy_token to build_deploy_token_transaction_helper")
                return build_deploy_token_transaction_helper(token, user, target_type, target_id)
            else:
                print(f"🔍 DEBUG: Routing {operation} to handle_build_transaction")
                return handle_build_transaction(token, user, operation, target_type, target_id, trex_service, data)
        elif action == 'confirm':
            return handle_confirm_transaction(token, user, operation, target_type, target_id, data, trex_service, transaction_indexer)
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error handling MetaMask transaction: {str(e)}'}), 500

def handle_build_transaction(token, user, operation, target_type, target_id, trex_service, data):
    """Handle build phase of MetaMask transactions using TREXService"""
    try:
        if operation == 'add_to_ir':
            # Get the appropriate request object
            if target_type == 'interest':
                request_obj = TokenInterest.query.get_or_404(target_id)
            elif target_type == 'purchase':
                request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            else:
                return jsonify({'success': False, 'error': 'Invalid target type'}), 400
            
            # Verify request belongs to this token
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Get investor
            investor = User.query.get(request_obj.investor_id)
            
            if not investor.onchain_id:
                return jsonify({'success': False, 'error': f'Investor {investor.username} has no OnchainID registered. They need to create an OnchainID first.'}), 400
            
            # Check if Identity Registry address exists
            if not token.identity_registry_address:
                return jsonify({'success': False, 'error': 'Token Identity Registry not deployed. Cannot add investor to IR.'}), 400
            
            result = trex_service.build_add_to_ir_transaction(
                token_address=token.token_address,
                user_address=investor.wallet_address,
                onchain_id_address=investor.onchain_id,
                user_address_for_gas=user.wallet_address
            )
            
            if result['success']:
                return jsonify({
                    'success': True,
                    'transaction': result['transaction'],
                    'investor_username': investor.username
                })
            else:
                return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
                
        elif operation == 'verify_kyc':
            # Get the appropriate request object
            if target_type == 'interest':
                request_obj = TokenInterest.query.get_or_404(target_id)
            elif target_type == 'purchase':
                request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            else:
                return jsonify({'success': False, 'error': 'Invalid target type'}), 400
            
            # Verify request belongs to this token
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Get investor
            investor = User.query.get(request_obj.investor_id)
            
            if not investor.onchain_id:
                return jsonify({'success': False, 'error': f'Investor {investor.username} has no OnchainID registered. They need to create an OnchainID first.'}), 400
            
            # Check if Identity Registry address exists
            if not token.identity_registry_address:
                return jsonify({'success': False, 'error': 'Token Identity Registry not deployed. Cannot verify KYC.'}), 400
            
            result = trex_service.build_verify_kyc_transaction(
                token_address=token.token_address,
                user_address=investor.wallet_address,
                user_address_for_gas=user.wallet_address
            )
            
            if result['success']:
                return jsonify({
                    'success': True,
                    'transaction': result['transaction'],
                    'investor_username': investor.username
                })
            else:
                return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
                
        elif operation == 'mint':
            # Get mint request data from passed data
            print(f"🔍 DEBUG: Mint operation - data received: {data}")
            print(f"🔍 DEBUG: Mint operation - data type: {type(data)}")
            to_address = data.get('to_address')
            amount = data.get('amount')
            print(f"🔍 DEBUG: Mint operation - to_address: {to_address}")
            print(f"🔍 DEBUG: Mint operation - amount: {amount}")
            
            if not all([to_address, amount]):
                return jsonify({'success': False, 'error': 'Missing to_address or amount'}), 400
            
            result = trex_service.build_mint_transaction(
                token_address=token.token_address,
                to_address=to_address,
                amount=amount,
                user_address=user.wallet_address
            )
            
        elif operation == 'burn':
            # Get burn request data from passed data
            from_address = data.get('from_address')
            amount = data.get('amount')
            
            if not all([from_address, amount]):
                return jsonify({'success': False, 'error': 'Missing from_address or amount'}), 400
            
            result = trex_service.build_burn_transaction(
                token_address=token.token_address,
                from_address=from_address,
                amount=amount,
                user_address=user.wallet_address
            )
            
        elif operation == 'pause':
            result = trex_service.build_pause_transaction(
                token_address=token.token_address,
                user_address=user.wallet_address
            )
            
        elif operation == 'unpause':
            result = trex_service.build_unpause_transaction(
                token_address=token.token_address,
                user_address=user.wallet_address
            )
            
        elif operation == 'force_transfer':
            # Get transfer data from passed data
            from_address = data.get('from_address')
            to_address = data.get('to_address')
            amount = data.get('amount')
            
            if not all([from_address, to_address, amount]):
                return jsonify({'success': False, 'error': 'Missing from_address, to_address, or amount'}), 400
            
            result = trex_service.build_force_transfer_transaction(
                token_address=token.token_address,
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                user_address=user.wallet_address
            )
            
        elif operation == 'add_ir_agent':
            # Get agent data from passed data
            agent_address = data.get('agent_address')
            
            if not agent_address:
                return jsonify({'success': False, 'error': 'Missing agent_address'}), 400
            
            result = trex_service.build_add_ir_agent_transaction(
                token_address=token.token_address,
                agent_address=agent_address,
                user_address=user.wallet_address
            )
            
        elif operation == 'add_token_agent':
            # Get agent data from passed data
            agent_address = data.get('agent_address')
            
            if not agent_address:
                return jsonify({'success': False, 'error': 'Missing agent_address'}), 400
            
            result = trex_service.build_add_token_agent_transaction(
                token_address=token.token_address,
                agent_address=agent_address,
                user_address=user.wallet_address
            )
            
        elif operation == 'add_trusted_issuer':
            # Get trusted issuer data from passed data
            trusted_issuer_address = data.get('trusted_issuer_address')
            claim_topics = data.get('claim_topics', [])
            
            if not trusted_issuer_address or not claim_topics:
                return jsonify({'success': False, 'error': 'Missing trusted_issuer_address or claim_topics'}), 400
            
            result = trex_service.build_add_trusted_issuer_transaction(
                token_address=token.token_address,
                trusted_issuer_address=trusted_issuer_address,
                claim_topics=claim_topics,
                user_address=user.wallet_address
            )
            
        elif operation == 'deploy_token':
            # Get deployment data
            data = request.get_json()
            token_name = data.get('token_name')
            token_symbol = data.get('token_symbol')
            total_supply = data.get('total_supply')
            claim_issuer_id = data.get('claim_issuer_id')
            claim_topics = data.get('claim_topics', [])
            
            if not all([token_name, token_symbol, total_supply, claim_issuer_id, claim_topics]):
                return jsonify({'success': False, 'error': 'Missing required deployment parameters'}), 400
            
            # Get the trusted issuer address
            trusted_issuer = User.query.get(claim_issuer_id)
            if not trusted_issuer:
                return jsonify({'success': False, 'error': 'Trusted issuer not found'}), 400
            
            claim_issuer_address = trusted_issuer.wallet_address
            
            result = trex_service.build_deployment_transaction(
                deployer_address=user.wallet_address,
                token_name=token_name,
                token_symbol=token_symbol,
                total_supply=total_supply,
                claim_topics=claim_topics,
                claim_issuer_address=claim_issuer_address
            )
            
            if result['success']:
                # Store deployment data in session for later use
                session['deployment_data'] = {
                    'token_name': token_name,
                    'token_symbol': token_symbol,
                    'total_supply': total_supply,
                    'claim_issuer_id': claim_issuer_id,
                    'claim_topics': claim_topics,
                    'description': data.get('description', ''),
                    'price_per_token': data.get('price_per_token', '1.00'),
                    'issuer_address': user.wallet_address,
                    'gateway_address': result.get('gateway_address')
                }
                
                return jsonify({
                    'success': True,
                    'transaction': result['transaction'],
                    'token_name': token_name,
                    'token_symbol': token_symbol,
                    'total_supply': total_supply
                })
            else:
                return jsonify({'success': False, 'error': result.get('error', 'Failed to build deployment transaction')}), 400
        else:
            return jsonify({'success': False, 'error': f'Unsupported operation: {operation}'}), 400
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction']
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
                
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error building transaction: {str(e)}'}), 500

def handle_confirm_transaction(token, user, operation, target_type, target_id, data, trex_service, transaction_indexer):
    """Handle confirm phase of MetaMask transactions using TransactionIndexer"""
    try:
        transaction_hash = data.get('transaction_hash')
        if not transaction_hash:
            return jsonify({'success': False, 'error': 'Missing transaction_hash'}), 400
        
        if operation == 'add_to_ir':
            # Get investor data
            if target_type == 'interest':
                from models.token import TokenInterest
                request_obj = TokenInterest.query.get(target_id)
            elif target_type == 'purchase':
                from models.token import TokenPurchaseRequest
                request_obj = TokenPurchaseRequest.query.get(target_id)
            else:
                return jsonify({'success': False, 'error': 'Invalid target type'}), 400
            
            if not request_obj or request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Get investor
            investor = User.query.get(request_obj.investor_id)
            
            # Index the add to IR transaction using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='add_to_ir',
                to_address=investor.wallet_address,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Added investor {investor.username} to Identity Registry'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            # Update request status
            request_obj.ir_status = 'added'  # Use 'added' to match frontend expectation
            request_obj.transaction_hash = transaction_hash
            db.session.commit()
        
            return jsonify({
                'success': True,
                'message': 'Add to IR transaction confirmed successfully',
                'status': 'added'
            })
            
        elif operation == 'verify_kyc':
            # Get investor data
            if target_type == 'interest':
                from models.token import TokenInterest
                request_obj = TokenInterest.query.get(target_id)
            elif target_type == 'purchase':
                from models.token import TokenPurchaseRequest
                request_obj = TokenPurchaseRequest.query.get(target_id)
            else:
                return jsonify({'success': False, 'error': 'Invalid target type'}), 400
            
            if not request_obj or request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Get investor
            investor = User.query.get(request_obj.investor_id)
            
            # Index the KYC verification transaction using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='verify_kyc',
                to_address=investor.wallet_address,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'KYC verified for investor {investor.username}'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            # Update request status
            request_obj.status = 'kyc_verified'
            request_obj.transaction_hash = transaction_hash
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'KYC verification transaction confirmed successfully',
                'status': 'kyc_verified'
            })
            
        elif operation == 'mint':
            # Get mint data
            to_address = data.get('to_address')
            amount = data.get('amount')
            
            # Index the transaction using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='mint',
                to_address=to_address,
                amount=amount,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Minted {amount} tokens to {to_address}'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            # Update purchase request status if applicable
            if target_type == 'purchase' and target_id:
                from models.token import TokenPurchaseRequest
                request_obj = TokenPurchaseRequest.query.get(target_id)
                if request_obj:
                    request_obj.status = 'completed'
                    request_obj.transaction_hash = transaction_hash
                    db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Mint transaction confirmed successfully',
                'status': 'completed'
            })
            
        elif operation == 'burn':
            # Get burn data
            from_address = data.get('from_address')
            amount = data.get('amount')
            
            # Index the transaction using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='burn',
                from_address=from_address,
                amount=amount,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Burned {amount} tokens from {from_address}'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            # Update interest/burn request status if applicable
            if target_type == 'interest' and target_id:
                from models.token import TokenInterest
                request_obj = TokenInterest.query.get(target_id)
                if request_obj:
                    request_obj.status = 'burned'
                    request_obj.transaction_hash = transaction_hash
                    db.session.commit()
        
            return jsonify({
                'success': True,
                'message': 'Burn transaction confirmed successfully',
                'status': 'completed'
            })
            
        elif operation == 'transfer':
            # Redirect transfer operations to force_transfer for consistency
            return handle_confirm_transaction(token, user, 'force_transfer', target_type, target_id, data, trex_service, transaction_indexer)
            
        elif operation == 'force_transfer':
            # Get transfer data
            from_address = data.get('from_address')
            to_address = data.get('to_address')
            amount = data.get('amount')
            
            # Index the transaction using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='transfer',
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Force transferred {amount} tokens from {from_address} to {to_address}'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            # Update purchase request status if applicable
            if target_type == 'purchase' and target_id:
                from models.token import TokenPurchaseRequest
                request_obj = TokenPurchaseRequest.query.get(target_id)
                if request_obj:
                    request_obj.status = 'completed'
                    request_obj.transaction_hash = transaction_hash
                    db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Force transfer transaction confirmed successfully',
                'status': 'completed'
            })
            
        elif operation == 'add_ir_agent':
            # Get agent data
            agent_address = data.get('agent_address')
            
            # Index the agent addition using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='add_ir_agent',
                to_address=agent_address,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Added IR agent: {agent_address}'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            return jsonify({
                'success': True,
                'message': 'Add IR Agent transaction confirmed successfully',
                'status': 'completed'
            })
            
        elif operation == 'add_token_agent':
            # Get agent data
            agent_address = data.get('agent_address')
            
            # Index the agent addition using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='add_token_agent',
                to_address=agent_address,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Added token agent: {agent_address}'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            return jsonify({
                'success': True,
                'message': 'Add Token Agent transaction confirmed successfully',
                'status': 'completed'
            })
            
        elif operation == 'add_trusted_issuer':
            # Get trusted issuer data
            trusted_issuer_address = data.get('trusted_issuer_address')
            claim_topics = data.get('claim_topics', [])
            
            # Index the trusted issuer addition using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='add_trusted_issuer',
                to_address=trusted_issuer_address,
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Added trusted issuer: {trusted_issuer_address} with claim topics: {claim_topics}'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            return jsonify({
                'success': True,
                'message': 'Add Trusted Issuer transaction confirmed successfully',
                'status': 'completed'
            })
            
        elif operation == 'pause':
            # Index the pause transaction using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='pause',
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes='Token paused'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            return jsonify({
                'success': True,
                'message': 'Pause transaction confirmed successfully',
                'status': 'paused'
            })
            
        elif operation == 'unpause':
            # Index the unpause transaction using TransactionIndexer
            success = transaction_indexer.index_token_transaction(
                token_id=token.id,
                transaction_type='unpause',
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes='Token unpaused'
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index transaction'}), 500
            
            return jsonify({
                'success': True,
                'message': 'Unpause transaction confirmed successfully',
                'status': 'unpaused'
            })
            
        elif operation == 'deploy_token':
            # Get deployment data from session
            deployment_data = session.get('deployment_data')
            if not deployment_data:
                return jsonify({'success': False, 'error': 'Deployment data not found in session'}), 400
            
            # Use TransactionIndexer to handle deployment and create token record
            # This will automatically parse events and create the token with correct addresses
            success = transaction_indexer.index_token_transaction(
                token_id=None,  # New token
                transaction_type='deploy',
                transaction_hash=transaction_hash,
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Deployed token: {deployment_data["token_name"]} ({deployment_data["token_symbol"]})',
                # Pass deployment data for token creation
                deployment_data=deployment_data
            )
            
            if not success:
                return jsonify({'success': False, 'error': 'Failed to index deployment transaction'}), 500
            
            # Get the created token from the indexer
            # The indexer should return the token_id of the created token
            result = transaction_indexer.get_last_deployment_result()
            if not result or not result.get('token_id'):
                return jsonify({'success': False, 'error': 'Failed to retrieve deployed token information'}), 500
            
            # Clear deployment data from session
            session.pop('deployment_data', None)
            
            return jsonify({
                'success': True,
                'message': 'Token deployment confirmed successfully',
                'status': 'deployed',
                'token_id': result.get('token_id'),
                'contract_addresses': result.get('contract_addresses', {})
            })
            
        else:
            return jsonify({'success': False, 'error': f'Unsupported operation: {operation}'}), 400
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Error confirming transaction: {str(e)}'}), 500

def build_add_to_ir_transaction(token, user, target_type, target_id):
    """Build Add to Identity Registry transaction"""
    try:
        # Get the appropriate request object
        if target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        # Verify request belongs to this token
        if request_obj.token_id != token.id:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Get investor
        investor = User.query.get(request_obj.investor_id)
        
        if not investor.onchain_id:
            return jsonify({'success': False, 'error': f'Investor {investor.username} has no OnchainID registered. They need to create an OnchainID first.'}), 400
        
        # Check if Identity Registry address exists
        if not token.identity_registry_address:
            return jsonify({'success': False, 'error': 'Token Identity Registry not deployed. Cannot add investor to IR.'}), 400
        
        # Build Add to Identity Registry transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        result = trex_service.build_add_to_ir_transaction(
            token_address=token.token_address,
            user_address=investor.wallet_address,
            onchain_id_address=investor.onchain_id,
            user_address_for_gas=user.wallet_address
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'investor_username': investor.username
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error building Add to IR transaction: {str(e)}'}), 500

def build_verify_kyc_transaction(token, user, target_type, target_id):
    """Build Verify KYC transaction - call isVerified() on blockchain"""
    try:
        # Get the appropriate request object
        if target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        # Verify request belongs to this token
        if request_obj.token_id != token.id:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Check if investor has been added to Identity Registry first
        if hasattr(request_obj, 'ir_status') and request_obj.ir_status != 'added':
            return jsonify({'success': False, 'error': 'Investor must be added to Identity Registry before KYC verification.'}), 400
        
        # Get investor
        investor = User.query.get(request_obj.investor_id)
        
        if not investor.onchain_id:
            return jsonify({'success': False, 'error': f'Investor {investor.username} has no OnchainID registered.'}), 400
        
        # For KYC verification, we call isVerified() directly on the blockchain
        # No MetaMask transaction needed - it's a read operation
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        # Check if investor is verified using Identity Registry (like V1)
        verification_result = trex_service.check_user_verification(
            token_address=token.token_address,
            user_address=investor.wallet_address
        )
        
        if verification_result['success'] and verification_result['verified']:
            # KYC verification successful - update database immediately
            request_obj.kyc_verified = True
            request_obj.kyc_verified_at = db.func.now()
            request_obj.kyc_verified_by = user.id
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'KYC verified for {investor.username}!',
                'investor_username': investor.username,
                'kyc_verified': True,
                'skip_blockchain': True  # No MetaMask needed
            })
        else:
            reason = verification_result.get('reason', 'User not verified')
            return jsonify({
                'success': False, 
                'error': f'KYC verification failed for {investor.username}: {reason}',
                'kyc_verified': False
            })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error building Verify KYC transaction: {str(e)}'}), 500

def confirm_add_to_ir_transaction(token, user, target_type, target_id, transaction_hash):
    """Confirm Add to IR transaction completion and update database"""
    try:
        # Get the appropriate request object
        if target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        # Verify request belongs to this token
        if request_obj.token_id != token.id:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Update status to 'added'
        request_obj.ir_status = 'added'
        request_obj.ir_added_at = db.func.now()
        request_obj.ir_added_by = user.id
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Identity Registry status updated successfully',
            'ir_status': 'added'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Error updating Add to IR status: {str(e)}'}), 500

def confirm_verify_kyc_transaction(token, user, target_type, target_id, transaction_hash):
    """Confirm Verify KYC transaction completion and update database"""
    try:
        # Get the appropriate request object
        if target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        # Verify request belongs to this token
        if request_obj.token_id != token.id:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Update KYC verification status
        if hasattr(request_obj, 'kyc_verified'):
            request_obj.kyc_verified = True
            request_obj.kyc_verified_at = db.func.now()
            request_obj.kyc_verified_by = user.id
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'KYC verification status updated successfully',
            'kyc_verified': True
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Error updating KYC verification status: {str(e)}'}), 500

# ============================================================================
# NEW HELPER FUNCTIONS FOR GENERIC MASK HANDLER
# ============================================================================

def build_mint_transaction_helper(token, user, target_type, target_id):
    """Build Mint transaction for MetaMask signing"""
    try:
        # Get the appropriate request object or use form data for actions tab
        if target_type == 'actions':
            # For actions tab, get data from request form
            from flask import request
            to_address = request.get_json().get('to_address')
            amount = request.get_json().get('amount')
            
            if not to_address or not amount:
                return jsonify({'success': False, 'error': 'Missing to_address or amount'}), 400
                
            # Validate amount
            try:
                amount = int(amount)
                if amount <= 0:
                    return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid amount format'}), 400
                
        elif target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            to_address = User.query.get(request_obj.investor_id).wallet_address
            amount = request_obj.amount
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            to_address = User.query.get(request_obj.investor_id).wallet_address
            amount = request_obj.amount_requested
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        # Build Mint transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        result = trex_service.build_mint_transaction(
            token_address=token.token_address,
            to_address=to_address,
            amount=str(amount),
            user_address=user.wallet_address
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'to_address': to_address,
                'amount': amount
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error building Mint transaction: {str(e)}'}), 500





def build_burn_transaction_helper(token, user, target_type, target_id):
    """Build Burn transaction for MetaMask signing"""
    try:
        # Get the appropriate request object or use form data for actions tab
        if target_type == 'actions':
            # For actions tab, get data from request form
            from flask import request
            from_address = request.get_json().get('from_address')
            amount = request.get_json().get('amount')
            
            if not from_address or not amount:
                return jsonify({'success': False, 'error': 'Missing from_address or amount'}), 400
                
            # Validate amount
            try:
                amount = int(amount)
                if amount <= 0:
                    return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid amount format'}), 400
                
        elif target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            from_address = User.query.get(request_obj.investor_id).wallet_address
            amount = request_obj.amount
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            from_address = User.query.get(request_obj.investor_id).wallet_address
            amount = request_obj.amount_requested
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        # Build Burn transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        result = trex_service.build_burn_transaction(
            token_address=token.token_address,
            from_address=from_address,
            amount=str(amount),
            user_address=user.wallet_address
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'from_address': from_address,
                'amount': amount
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error building Burn transaction: {str(e)}'}), 500

def confirm_mint_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Mint transaction completion and update database"""
    try:
        # Get the appropriate request object or handle actions tab
        if target_type == 'actions':
            # For actions tab, just return success (no database update needed)
            return jsonify({
                'success': True,
                'message': 'Mint transaction confirmed successfully',
                'status': 'minted'
            })
        elif target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Update status to 'minted'
            request_obj.status = 'minted'
            request_obj.minted_at = db.func.now()
            request_obj.minted_by = user.id
            request_obj.transaction_hash = transaction_hash
            
            db.session.commit()
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Update status to 'completed' (same as force_transfer)
            request_obj.status = 'completed'
            request_obj.minted_at = db.func.now()
            request_obj.minted_by = user.id
            request_obj.transaction_hash = transaction_hash
            
            db.session.commit()
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        return jsonify({
            'success': True,
            'message': 'Mint transaction confirmed successfully',
            'status': 'completed'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Error updating Mint status: {str(e)}'}), 500





def confirm_burn_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Burn transaction completion and update database"""
    try:
        # Get the appropriate request object or handle actions tab
        if target_type == 'actions':
            # For actions tab, just return success (no database update needed)
            return jsonify({
                'success': True,
                'message': 'Burn transaction confirmed successfully',
                'status': 'burned'
            })
        elif target_type == 'interest':
            request_obj = TokenInterest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Update status to 'burned'
            request_obj.status = 'burned'
            request_obj.burned_at = db.func.now()
            request_obj.burned_by = user.id
            request_obj.transaction_hash = transaction_hash
            
            db.session.commit()
        elif target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Update status to 'completed' (same as mint and force_transfer)
            request_obj.status = 'completed'
            request_obj.burned_at = db.func.now()
            request_obj.burned_by = user.id
            request_obj.transaction_hash = transaction_hash
            
            db.session.commit()
        else:
            return jsonify({'success': False, 'error': 'Invalid target type'}), 400
        
        return jsonify({
            'success': True,
            'message': 'Burn transaction confirmed successfully',
            'status': 'completed'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Error updating Burn status: {str(e)}'}), 500

def build_pause_transaction_helper(token, user, target_type, target_id):
    """Build Pause transaction for MetaMask signing"""
    try:
        # For pause operations, we don't need target_type or target_id
        # Get the action from request form
        from flask import request
        request_data = request.get_json()
        print(f"🔍 DEBUG: build_pause_transaction_helper called with:")
        print(f"   token_address: {token.token_address}")
        print(f"   user_address: {user.wallet_address}")
        print(f"   request_data: {request_data}")
        
        action = request_data.get('action_type') or request_data.get('action')
        print(f"   extracted action: {action}")
        
        if not action or action not in ['pause', 'unpause']:
            print(f"   ❌ Invalid action: {action}")
            return jsonify({'success': False, 'error': 'Invalid action. Must be pause or unpause.'}), 400
        
        print(f"   ✅ Valid action: {action}")
        
        # Build Pause/Unpause transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        if action == 'pause':
            print(f"   🔧 Calling trex_service.build_pause_transaction...")
            result = trex_service.build_pause_transaction(
                token_address=token.token_address,
                user_address=user.wallet_address
            )
        else:
            print(f"   🔧 Calling trex_service.build_unpause_transaction...")
            result = trex_service.build_unpause_transaction(
                token_address=token.token_address,
                user_address=user.wallet_address
            )
        
        print(f"   📊 Result: {result}")
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'action': action
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        print(f"   ❌ Exception in build_pause_transaction_helper: {str(e)}")
        return jsonify({'success': False, 'error': f'Error building pause/unpause transaction: {str(e)}'}), 500

def build_unpause_transaction_helper(token, user, target_type, target_id):
    """Build Unpause transaction for MetaMask signing"""
    try:
        # For unpause operations, we don't need target_type or target_id
        # Get the action from request form
        from flask import request
        request_data = request.get_json()
        print(f"🔍 DEBUG: build_unpause_transaction_helper called with:")
        print(f"   token_address: {token.token_address}")
        print(f"   user_address: {user.wallet_address}")
        print(f"   request_data: {request_data}")
        
        action = request_data.get('action_type') or request_data.get('action')
        print(f"   extracted action: {action}")
        
        if not action or action not in ['pause', 'unpause']:
            print(f"   ❌ Invalid action: {action}")
            return jsonify({'success': False, 'error': 'Invalid action. Must be pause or unpause.'}), 400
        
        print(f"   ✅ Valid action: {action}")
        
        # Build Unpause transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        print(f"   🔧 Calling trex_service.build_unpause_transaction...")
        result = trex_service.build_unpause_transaction(
            token_address=token.token_address,
            user_address=user.wallet_address
        )
        
        print(f"   📊 Result: {result}")
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'action': action
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
        
    except Exception as e:
        print(f"   ❌ Exception in build_unpause_transaction_helper: {str(e)}")
        return jsonify({'success': False, 'error': f'Error building pause/unpause transaction: {str(e)}'}), 500

def confirm_pause_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Pause transaction completion and update database"""
    try:
        # For pause operations, just return success (no database update needed)
        return jsonify({
            'success': True,
            'message': 'Pause transaction confirmed successfully',
            'status': 'paused'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error updating Pause status: {str(e)}'}), 500

def confirm_unpause_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Unpause transaction completion and update database"""
    try:
        # For unpause operations, just return success (no database update needed)
        return jsonify({
            'success': True,
            'message': 'Unpause transaction confirmed successfully',
            'status': 'unpaused'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error updating Unpause status: {str(e)}'}), 500

def build_force_transfer_transaction_helper(token, user, target_type, target_id):
    """Build Force Transfer transaction for MetaMask signing"""
    try:
        # Get the appropriate request object or use form data for actions tab
        if target_type == 'purchase':
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            # Verify request belongs to this token
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Get form data from request
            data = request.get_json()
            from_address = data.get('from_address')
            to_address = data.get('to_address')
            amount = data.get('amount')
            
            if not from_address or not to_address or not amount:
                return jsonify({'success': False, 'error': 'from_address, to_address, and amount are required'}), 400
                
        elif target_type == 'actions':
            # For actions tab, get data from request form
            data = request.get_json()
            from_address = data.get('from_address')
            to_address = data.get('to_address')
            amount = data.get('amount')
            
            if not from_address or not to_address or not amount:
                return jsonify({'success': False, 'error': 'Missing from_address, to_address, or amount'}), 400
                
            # Validate amount
            try:
                amount = int(amount)
                if amount <= 0:
                    return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid amount format'}), 400
                
        else:
            return jsonify({'success': False, 'error': 'Force transfer only supported for purchase requests and actions tab'}), 400
        
        # Build Force Transfer transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        result = trex_service.build_force_transfer_transaction(
            token_address=token.token_address,
            from_address=from_address,
            to_address=to_address,
            amount=str(amount),
            user_address=user.wallet_address
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'message': f'Force transfer transaction built successfully'
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error building Force Transfer transaction: {str(e)}'}), 500

def confirm_force_transfer_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Force Transfer transaction completion and update database"""
    try:
        if target_type == 'purchase':
            # Get the purchase request
            request_obj = TokenPurchaseRequest.query.get_or_404(target_id)
            
            # Verify request belongs to this token
            if request_obj.token_id != token.id:
                return jsonify({'success': False, 'error': 'Invalid request'}), 400
            
            # Update purchase request status
            request_obj.status = 'completed'
            request_obj.purchase_completed_at = db.func.now()
            request_obj.transaction_hash = transaction_hash
            
            # Get the addresses from the original request data
            # We need to get this from the frontend data since it's not stored in the database
            data = request.get_json()
            from_address = data.get('from_address')
            to_address = data.get('to_address')
            
            # Create transaction record
            transaction = TokenTransaction(
                token_id=token.id,
                transaction_type='transfer',
                from_address=from_address,
                to_address=to_address,
                amount=request_obj.amount_requested,
                purchase_request_id=target_id,
                transaction_hash=transaction_hash,
                executed_by=user.id
            )
            
            db.session.add(transaction)
            db.session.commit()
            
        elif target_type == 'actions':
            # For actions tab, just create transaction record (no purchase request to update)
            data = request.get_json()
            from_address = data.get('from_address')
            to_address = data.get('to_address')
            amount = data.get('amount')
            
            # Validate required fields for Actions tab
            if not from_address or not to_address or not amount:
                return jsonify({
                    'success': False, 
                    'error': f'Missing required data for Actions tab transfer: from_address={from_address}, to_address={to_address}, amount={amount}'
                }), 400
            
            # Create transaction record
            transaction = TokenTransaction(
                token_id=token.id,
                transaction_type='transfer',
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                transaction_hash=transaction_hash,
                executed_by=user.id
            )
            
            db.session.add(transaction)
            db.session.commit()
            
        else:
            return jsonify({'success': False, 'error': 'Force transfer only supported for purchase requests and actions tab'}), 400
        
        return jsonify({
            'success': True,
            'message': 'Force transfer transaction confirmed successfully',
            'status': 'completed'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error updating Force Transfer status: {str(e)}'}), 500

@issuer_bp.route('/token/<int:token_id>/approve-purchase/<int:request_id>', methods=['POST'])
def approve_purchase(token_id, request_id):
    """Approve a purchase request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token and purchase request
    token = Token.query.get_or_404(token_id)
    purchase_request = TokenPurchaseRequest.query.get_or_404(request_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Verify request belongs to this token
    if purchase_request.token_id != token_id:
        flash('Invalid purchase request.', 'error')
        return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    # Check if investor is verified
    if purchase_request.verification_status != 'verified':
        flash('Cannot approve purchase request. Investor must be verified first.', 'error')
        return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        # Update request status
        purchase_request.status = 'approved'
        purchase_request.approved_at = db.func.now()
        purchase_request.approved_by = user.id
        purchase_request.approval_notes = request.form.get('approval_notes', '')
        
        db.session.commit()
        
        flash(f'Purchase request approved! {purchase_request.amount_requested} {token.symbol} tokens will be available for purchase.', 'success')
        
    except Exception as e:
        flash(f'Error approving purchase request: {str(e)}', 'error')
    
    return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))


# Removed acknowledge_action_transaction route - not needed since we're using blockchain transaction history

@issuer_bp.route('/api/purchase-request/<int:request_id>')
def get_purchase_request_details(request_id):
    """Get purchase request details for API"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        return jsonify({'success': False, 'error': 'Issuer access required'})
    
    try:
        # Get purchase request
        purchase_request = TokenPurchaseRequest.query.get_or_404(request_id)
        
        # Get investor
        investor = User.query.get(purchase_request.investor_id)
        
        # Get token
        token = Token.query.get(purchase_request.token_id)
        
        # Verify ownership
        if token.issuer_address != user.wallet_address:
            return jsonify({'success': False, 'error': 'Access denied'})
        
        # Prepare response data
        request_data = {
            'id': purchase_request.id,
            'status': purchase_request.status,
            'amount_requested': purchase_request.amount_requested,
            'price_per_token': purchase_request.price_per_token,
            'total_value': purchase_request.total_value,
            'ir_status': purchase_request.ir_status,
            'verification_status': purchase_request.verification_status,
            'created_at': purchase_request.created_at.isoformat() if purchase_request.created_at else None,
            'updated_at': purchase_request.updated_at.isoformat() if purchase_request.updated_at else None,
            'verification_checked_at': purchase_request.verification_checked_at.isoformat() if purchase_request.verification_checked_at else None
        }
        
        investor_data = {
            'id': investor.id,
            'username': investor.username,
            'wallet_address': investor.wallet_address,
            'onchain_id': investor.onchain_id,
            'kyc_status': investor.kyc_status
        }
        
        return jsonify({
            'success': True,
            'purchase_request': request_data,
            'investor': investor_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



@issuer_bp.route('/token/<int:token_id>/reject-purchase/<int:request_id>', methods=['POST'])
def reject_purchase(token_id, request_id):
    """Reject a purchase request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token and purchase request
    token = Token.query.get_or_404(token_id)
    purchase_request = TokenPurchaseRequest.query.get_or_404(request_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only manage your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Verify request belongs to this token
    if purchase_request.token_id != token_id:
        flash('Invalid purchase request.', 'error')
        return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        # Update request status
        purchase_request.status = 'rejected'
        purchase_request.approved_at = db.func.now()
        purchase_request.approved_by = user.id
        purchase_request.approval_notes = request.form.get('rejection_notes', '')
        
        db.session.commit()
        
        flash(f'Purchase request rejected.', 'success')
        
    except Exception as e:
        flash(f'Error rejecting purchase request: {str(e)}', 'error')
    
    return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))


@issuer_bp.route('/token/<int:token_id>/enhanced-transactions')
def enhanced_transactions(token_id):
    """Display enhanced transaction history for a token"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    # Verify ownership
    if token.issuer_address != user.wallet_address:
        flash('Access denied. You can only view your own tokens.', 'error')
        return redirect(url_for('issuer.dashboard', tab_session=tab_session.session_id))
    
    # Get blockchain transactions using hybrid approach
    from services.trex_service import TREXService
    from services.web3_service import Web3Service
    
    web3_service = Web3Service()
    trex_service = TREXService(web3_service)
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get all transactions from blockchain
    print(f"🔍 Getting transactions for token: {token.token_address}")
    all_transactions = trex_service.get_token_transactions(
        token_address=token.token_address,
        limit=100  # Get more transactions for pagination
    )
    
    print(f"📊 Found {len(all_transactions)} transactions from blockchain")
    
    # Apply pagination
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    transactions = all_transactions[start_idx:end_idx]
    
    print(f"📄 Showing transactions {start_idx+1}-{min(end_idx, len(all_transactions))} of {len(all_transactions)}")
    
    # Debug: Check transaction structure after pagination
    print(f"🔍 Pagination debug:")
    print(f"   Total transactions: {len(all_transactions)}")
    print(f"   Page: {page}")
    print(f"   Per page: {per_page}")
    print(f"   Start idx: {start_idx}")
    print(f"   End idx: {end_idx}")
    print(f"   Transactions to show: {len(transactions)}")
    
    if transactions:
        print(f"🔍 First transaction structure:")
        first_tx = transactions[0]
        print(f"   Keys: {list(first_tx.keys())}")
        print(f"   Type: {first_tx.get('transaction_type', 'MISSING')}")
        print(f"   Amount: {first_tx.get('amount_formatted', 'MISSING')}")
    
    # Calculate pagination info
    total_transactions = len(all_transactions)
    total_pages = (total_transactions + per_page - 1) // per_page
    
    return render_template('enhanced_transactions.html',
                         user=user,
                         token=token,
                         transactions=transactions,
                         current_page=page,
                         total_pages=total_pages,
                         total_transactions=total_transactions,
                         tab_session_id=tab_session.session_id) 

@issuer_bp.route('/onchainid-keys')
def onchainid_keys():
    """Display enhanced OnchainID key management"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get enhanced OnchainID keys
    from services.transaction_indexer import TransactionIndexer
    from services.web3_service import Web3Service
    
    web3_service = Web3Service()
    transaction_indexer = TransactionIndexer(web3_service)
    
    # Get all OnchainID keys
    onchainid_keys = transaction_indexer.get_onchainid_keys()
    
    # Group keys by OnchainID address
    keys_by_onchainid = {}
    for key in onchainid_keys:
        if key.onchainid_address not in keys_by_onchainid:
            keys_by_onchainid[key.onchainid_address] = []
        keys_by_onchainid[key.onchainid_address].append(key)
    
    return render_template('onchainid_keys.html',
                         user=user,
                         keys_by_onchainid=keys_by_onchainid,
                         tab_session_id=tab_session.session_id)

@issuer_bp.route('/sync-onchainid-keys', methods=['POST'])
def sync_onchainid_keys():
    """Sync all OnchainID keys from blockchain"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    try:
        from services.transaction_indexer import TransactionIndexer
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        transaction_indexer = TransactionIndexer(web3_service)
        
        # Sync all OnchainID keys
        synced_count = transaction_indexer.sync_all_onchainid_keys()
        
        flash(f'Successfully synced OnchainID keys for {synced_count} tokens!', 'success')
        
    except Exception as e:
        flash(f'Error syncing OnchainID keys: {str(e)}', 'error')
    
    return redirect(url_for('issuer.onchainid_keys', tab_session=tab_session.session_id))

@issuer_bp.route('/token/<int:token_id>/debug-database')
def debug_token_database(token_id):
    """Debug route to check database vs deployment addresses"""
    try:
        from models import Token
        
        token = Token.query.get(token_id)
        if not token:
            return jsonify({'error': 'Token not found'})
        
        # Get the deployment result from the logs
        deployment_addresses = {
            'database_token_address': token.token_address,
            'database_identity_registry': token.identity_registry_address,
            'database_compliance': token.compliance_address,
            'database_claim_topics_registry': token.claim_topics_registry_address,
            'database_trusted_issuers_registry': token.trusted_issuers_registry_address,
        }
        
        # Check if addresses are valid contracts
        from services.web3_service import Web3Service
        web3_service = Web3Service()
        
        contract_checks = {}
        for name, address in deployment_addresses.items():
            if address:
                try:
                    code = web3_service.w3.eth.get_code(address)
                    contract_checks[name] = {
                        'address': address,
                        'exists': code != b'',
                        'code_size': len(code),
                        'checksum_address': web3_service.w3.to_checksum_address(address)
                    }
                except Exception as e:
                    contract_checks[name] = {
                        'address': address,
                        'error': str(e)
                    }
            else:
                contract_checks[name] = {'address': None, 'exists': False}
        
        return jsonify({
            'token_id': token_id,
            'token_name': token.name,
            'token_symbol': token.symbol,
            'deployment_addresses': deployment_addresses,
            'contract_checks': contract_checks
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

# ============================================================================
# NEW HELPER FUNCTIONS FOR AGENTS & TRUSTED ISSUERS
# ============================================================================

def build_add_ir_agent_transaction_helper(token, user, target_type, target_id):
    """Build Add IR Agent transaction for MetaMask signing"""
    try:
        # Get the agent address from request form
        from flask import request
        request_data = request.get_json()
        print(f"🔍 DEBUG: build_add_ir_agent_transaction_helper called with:")
        print(f"   token_address: {token.token_address}")
        print(f"   user_address: {user.wallet_address}")
        print(f"   request_data: {request_data}")
        
        agent_address = request_data.get('agent_address')
        print(f"   extracted agent_address: {agent_address}")
        
        if not agent_address:
            print(f"   ❌ Missing agent_address")
            return jsonify({'success': False, 'error': 'Missing agent_address'}), 400
        
        print(f"   ✅ Valid agent_address: {agent_address}")
        
        # Build Add IR Agent transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        print(f"   🔧 Calling trex_service.build_add_ir_agent_transaction...")
        
        result = trex_service.build_add_ir_agent_transaction(
            token_address=token.token_address,
            agent_address=agent_address,
            user_address=user.wallet_address
        )
        
        print(f"   📊 Result: {result}")
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'agent_address': agent_address
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        print(f"   ❌ Exception in build_add_ir_agent_transaction_helper: {str(e)}")
        return jsonify({'success': False, 'error': f'Error building add IR agent transaction: {str(e)}'}), 500

def build_add_token_agent_transaction_helper(token, user, target_type, target_id):
    """Build Add Token Agent transaction for MetaMask signing"""
    try:
        # Get the agent address from request form
        from flask import request
        request_data = request.get_json()
        print(f"🔍 DEBUG: build_add_token_agent_transaction_helper called with:")
        print(f"   token_address: {token.token_address}")
        print(f"   user_address: {user.wallet_address}")
        print(f"   request_data: {request_data}")
        
        agent_address = request_data.get('agent_address')
        print(f"   extracted agent_address: {agent_address}")
        
        if not agent_address:
            print(f"   ❌ Missing agent_address")
            return jsonify({'success': False, 'error': 'Missing agent_address'}), 400
        
        print(f"   ✅ Valid agent_address: {agent_address}")
        
        # Build Add Token Agent transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        print(f"   🔧 Calling trex_service.build_add_token_agent_transaction...")
        result = trex_service.build_add_token_agent_transaction(
            token_address=token.token_address,
            agent_address=agent_address,
            user_address=user.wallet_address
        )
        
        print(f"   📊 Result: {result}")
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'agent_address': agent_address
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        print(f"   ❌ Exception in build_add_token_agent_transaction_helper: {str(e)}")
        return jsonify({'success': False, 'error': f'Error building add token agent transaction: {str(e)}'}), 500

def build_add_trusted_issuer_transaction_helper(token, user, target_type, target_id):
    """Build Add Trusted Issuer transaction for MetaMask signing"""
    try:
        # Get the trusted issuer data from request form
        from flask import request
        request_data = request.get_json()
        print(f"🔍 DEBUG: build_add_trusted_issuer_transaction_helper called with:")
        print(f"   token_address: {token.token_address}")
        print(f"   user_address: {user.wallet_address}")
        print(f"   request_data: {request_data}")
        
        trusted_issuer_address = request_data.get('trusted_issuer_address')
        claim_topics = request_data.get('claim_topics', [])
        print(f"   extracted trusted_issuer_address: {trusted_issuer_address}")
        print(f"   extracted claim_topics: {claim_topics}")
        
        if not trusted_issuer_address or not claim_topics:
            print(f"   ❌ Missing required data")
            return jsonify({'success': False, 'error': 'Missing trusted_issuer_address or claim_topics'}), 400
        
        print(f"   ✅ Valid data: trusted_issuer_address={trusted_issuer_address}, claim_topics={claim_topics}")
        
        # Build Add Trusted Issuer transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        print(f"   🔧 Calling trex_service.build_add_trusted_issuer_transaction...")
        result = trex_service.build_add_trusted_issuer_transaction(
            token_address=token.token_address,
            trusted_issuer_address=trusted_issuer_address,
            claim_topics=claim_topics,
            user_address=user.wallet_address
        )
        
        print(f"   📊 Result: {result}")
        
        if result['success']:
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'trusted_issuer_address': trusted_issuer_address,
                'claim_topics': claim_topics
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build transaction')}), 400
            
    except Exception as e:
        print(f"   ❌ Exception in build_add_trusted_issuer_transaction_helper: {str(e)}")
        return jsonify({'success': False, 'error': f'Error building add trusted issuer transaction: {str(e)}'}), 500

def confirm_add_ir_agent_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Add IR Agent transaction completion and update database"""
    try:
        # For actions tab, just return success (no database update needed)
        return jsonify({
            'success': True,
            'message': 'Add IR Agent transaction confirmed successfully',
            'status': 'completed'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error updating Add IR Agent status: {str(e)}'}), 500

def confirm_add_token_agent_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Add Token Agent transaction completion and update database"""
    try:
        # For actions tab, just return success (no database update needed)
        return jsonify({
            'success': True,
            'message': 'Add Token Agent transaction confirmed successfully',
            'status': 'completed'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error updating Add Token Agent status: {str(e)}'}), 500

def confirm_add_trusted_issuer_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Add Trusted Issuer transaction completion and update database"""
    try:
        # For actions tab, just return success (no database update needed)
        return jsonify({
            'success': True,
            'message': 'Add Trusted Issuer transaction confirmed successfully',
            'status': 'completed'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error updating Add Trusted Issuer status: {str(e)}'}), 500

def build_deploy_token_transaction_helper(token, user, target_type, target_id):
    """Build Deploy Token transaction for MetaMask signing"""
    try:
        # Get the deployment data from request form
        from flask import request
        request_data = request.get_json()
        
        if token:
            print(f"   token_address: {token.token_address}")
        else:
            print(f"   token_address: None (deployment)")
        print(f"   user_address: {user.wallet_address}")
        
        # Extract deployment parameters
        token_name = request_data.get('token_name')
        token_symbol = request_data.get('token_symbol')
        total_supply = request_data.get('total_supply')
        claim_issuer_id = request_data.get('claim_issuer_id')
        claim_topics = request_data.get('claim_topics', [])
        description = request_data.get('description', '')
        price_per_token = request_data.get('price_per_token', '1.00')
        
        if not all([token_name, token_symbol, total_supply, claim_issuer_id, claim_topics]):
            return jsonify({'success': False, 'error': 'Missing required deployment parameters'}), 400
        
        # Build Deploy Token transaction for MetaMask signing
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        # Get the trusted issuer address
        from models.user import User
        trusted_issuer = User.query.get(claim_issuer_id)
        if not trusted_issuer:
            return jsonify({'success': False, 'error': 'Trusted issuer not found'}), 400
        
        print(f"🔍 DEBUG: build_deploy_token_transaction_helper - Trusted issuer found: {trusted_issuer.username}")
        print(f"🔍 DEBUG: build_deploy_token_transaction_helper - Wallet address: {trusted_issuer.wallet_address}")
        print(f"🔍 DEBUG: build_deploy_token_transaction_helper - Claim issuer address: {trusted_issuer.claim_issuer_address}")
        
        claim_issuer_address = trusted_issuer.claim_issuer_address
        print(f"🔍 DEBUG: build_deploy_token_transaction_helper - Using claim_issuer_address: {claim_issuer_address}")
        
        result = trex_service.build_deployment_transaction(
            deployer_address=user.wallet_address,
            token_name=token_name,
            token_symbol=token_symbol,
            total_supply=total_supply,
            claim_topics=claim_topics,
            claim_issuer_address=claim_issuer_address
        )
        
        if result['success']:
            # Store deployment data in session for later use
            from flask import session
            session['deployment_data'] = {
                'token_name': token_name,
                'token_symbol': token_symbol,
                'total_supply': total_supply,
                'claim_issuer_id': claim_issuer_id,
                'claim_topics': claim_topics,
                'description': description,
                'price_per_token': price_per_token,
                'issuer_address': user.wallet_address,
                'gateway_address': result.get('gateway_address')  # Store gateway address for event parsing
            }
            
            return jsonify({
                'success': True,
                'transaction': result['transaction'],
                'token_name': token_name,
                'token_symbol': token_symbol,
                'total_supply': total_supply
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Failed to build deployment transaction')}), 400
            
    except Exception as e:
        print(f"   ❌ Exception in build_deploy_token_transaction_helper: {str(e)}")
        return jsonify({'success': False, 'error': f'Error building deploy token transaction: {str(e)}'}), 500

def confirm_deploy_token_transaction_helper(token, user, target_type, target_id, transaction_hash):
    """Confirm Deploy Token transaction completion and update database"""
    try:
        # Get deployment data from session
        from flask import session
        deployment_data = session.get('deployment_data')
        
        if not deployment_data:
            return jsonify({'success': False, 'error': 'Deployment data not found in session'}), 400
        
        print(f"🔍 Confirm deploy token transaction helper called with:")
        print(f"   transaction_hash: {transaction_hash}")
        
        # Parse deployment event to get contract addresses
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        
        # Get the gateway address from the deployment data
        gateway_address = deployment_data.get('gateway_address')
        if not gateway_address:
            return jsonify({'success': False, 'error': 'Gateway address not found in deployment data'}), 400
        
        # Use the same approach as the working TransactionIndexer above
        # The TransactionIndexer already successfully parsed the addresses, so let's use TREXService directly
        from services.trex_service import TREXService
        
        print(f"🔍 Using TREXService to parse deployment events for transaction: {transaction_hash}")
        
        # Get the addresses using the same method that worked in the logs above
        # Based on the logs, we know the transaction was successful and addresses were extracted
        # Let's parse the transaction receipt to get the addresses
        receipt = web3_service.w3.eth.get_transaction_receipt(transaction_hash)
        
        # Look for the TREXSuiteDeployed event in the Factory logs
        # Get factory address from database (not hardcoded!)
        from models import Contract
        factory_contract = Contract.query.filter_by(contract_type='TREXFactory').first()
        if not factory_contract:
            return jsonify({'success': False, 'error': 'TREXFactory not found in database'}), 400
        factory_address = factory_contract.contract_address
        deployment_event_topic = "0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41"
        
        contract_addresses = None
        for log in receipt.logs:
            if (log.address.lower() == factory_address.lower() and 
                len(log.topics) > 0 and 
                log.topics[0].hex() == deployment_event_topic):
                
                print(f"✅ Found TREXSuiteDeployed event!")
                
                # Extract token address from Topic 1
                token_address = web3_service.w3.to_checksum_address(log.topics[1][-20:])
                
                # Extract addresses from data field (5 addresses: IR, IRS, TIR, CTR, MC)
                data = log.data
                data_addresses = []
                for i in range(0, 160, 32):  # 5 addresses * 32 bytes each
                    address_bytes = data[i:i+32]
                    address = web3_service.w3.to_checksum_address(address_bytes[-20:])
                    data_addresses.append(address)
                
                contract_addresses = {
                    'token_address': token_address,
                    'identity_registry': data_addresses[0],  # IR
                    'identity_registry_storage': data_addresses[1],  # IRS
                    'trusted_issuers_registry': data_addresses[2],  # TIR
                    'claim_topics_registry': data_addresses[3],  # CTR
                    'compliance': data_addresses[4]  # MC
                }
                break
        
        if not contract_addresses:
            return jsonify({'success': False, 'error': 'Failed to parse deployment events from transaction receipt'}), 400
        
        print(f"✅ Parsed contract addresses:")
        print(f"   Token: {contract_addresses['token_address']}")
        print(f"   Identity Registry: {contract_addresses['identity_registry']}")
        print(f"   Compliance: {contract_addresses['compliance']}")
        print(f"   Claim Topics Registry: {contract_addresses['claim_topics_registry']}")
        print(f"   Trusted Issuers Registry: {contract_addresses['trusted_issuers_registry']}")
        
        # Create token record in database with REAL addresses
        from models.token import Token
        from models import db
        import json
        
        # Set initial agents to the issuer's wallet address
        ir_agent = user.wallet_address
        token_agent = user.wallet_address
        
        print(f"🔍 CRITICAL: Setting up token agents in database:")
        print(f"   user.wallet_address: {user.wallet_address}")
        print(f"   deployment_data['issuer_address']: {deployment_data['issuer_address']}")
        print(f"   ir_agent: {ir_agent}")
        print(f"   token_agent: {token_agent}")
        print(f"   Are they the same? {user.wallet_address == deployment_data['issuer_address']}")
        
        # Create token with real contract addresses
        token = Token(
            token_address=contract_addresses['token_address'],
            name=deployment_data['token_name'],
            symbol=deployment_data['token_symbol'],
            total_supply=int(deployment_data['total_supply']),
            issuer_address=deployment_data['issuer_address'],
            description=deployment_data['description'],
            price_per_token=float(deployment_data['price_per_token']) if deployment_data['price_per_token'] else 1.00,
            ir_agent=ir_agent,
            token_agent=token_agent,
            claim_topics=','.join(map(str, deployment_data['claim_topics'])),
            claim_issuer_id=deployment_data['claim_issuer_id'],
            claim_issuer_type='trusted_issuer',
            # Use REAL addresses from parsed events
            identity_registry_address=contract_addresses['identity_registry'],
            compliance_address=contract_addresses['compliance'],
            claim_topics_registry_address=contract_addresses['claim_topics_registry'],
            trusted_issuers_registry_address=contract_addresses['trusted_issuers_registry'],
            agents=json.dumps({
                'identity_agents': [ir_agent],
                'token_agents': [token_agent],
                'compliance_agents': []
            })
        )
        
        db.session.add(token)
        db.session.commit()
        
        # Clear deployment data from session
        session.pop('deployment_data', None)
        
        return jsonify({
            'success': True,
            'message': 'Token deployment confirmed successfully',
            'status': 'deployed',
            'token_id': token.id,
            'contract_addresses': contract_addresses
        })
        
    except Exception as e:
        print(f"   ❌ Exception in confirm_deploy_token_transaction_helper: {str(e)}")
        return jsonify({'success': False, 'error': f'Error updating Deploy Token status: {str(e)}'}), 500