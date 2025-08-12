from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
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

@issuer_bp.route('/deploy-token', methods=['GET', 'POST'])
def deploy_token():
    """Deploy a new token"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    if request.method == 'POST':
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
            
            result = trex_service.deploy_token(
                issuer_address=user.wallet_address,
                token_name=token_name,
                token_symbol=token_symbol,
                total_supply=int(total_supply),
                ir_agent=ir_agent,
                token_agent=token_agent,
                claim_topics=[int(topic) for topic in claim_topics],
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
        blockchain_paused = web3_service.call_contract_function('Token', token.token_address, 'paused')
    except Exception as e:
        print(f"Error getting blockchain pause status: {e}")
        blockchain_paused = token.is_paused  # Fallback to database status

    # Build investors list: only investors who completed the full approval process
    # (IR add + KYC check + purchase approval + minting completed)
    investors = []
    try:
        from models.user import User as DbUser
        from models.token import TokenPurchaseRequest
        
        # Get all completed purchase requests for this token
        completed_requests = TokenPurchaseRequest.query.filter_by(
            token_id=token_id,
            status='completed'
        ).all()
        
        # Get unique investors from completed requests
        approved_investor_ids = set()
        for purchase_request in completed_requests:
            approved_investor_ids.add(purchase_request.investor_id)
        
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

@issuer_bp.route('/token/<int:token_id>/add-trusted-issuer', methods=['POST'])
def add_trusted_issuer_to_token(token_id):
    """Add a trusted issuer to a token's Identity Registry"""
    try:
        # Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        trusted_issuer_id = data.get('trusted_issuer_id')
        trusted_issuer_address = data.get('trusted_issuer_address')
        claim_topics = data.get('claim_topics', [])
        
        # DEBUG: Show exactly what we received from frontend
        print(f"🔍 DEBUG: Frontend form data received:")
        print(f"  trusted_issuer_id: {trusted_issuer_id}")
        print(f"  trusted_issuer_address: {trusted_issuer_address}")
        print(f"  claim_topics: {claim_topics}")
        print(f"  Full data: {data}")
        
        if not trusted_issuer_id or not trusted_issuer_address or not claim_topics:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
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
        if trusted_issuer.user_type != 'trusted_issuer':
            return jsonify({'success': False, 'error': 'Selected user is not a trusted issuer'}), 400
        
        # Verify trusted issuer has ClaimIssuer contract
        if not trusted_issuer.claim_issuer_address:
            return jsonify({'success': False, 'error': 'Selected trusted issuer does not have a ClaimIssuer contract'}), 400
        
        # CRITICAL FIX: Use ClaimIssuer contract address, not wallet address!
        claim_issuer_address = trusted_issuer.claim_issuer_address
        
        # DEBUG: Show what we received vs what we're using
        print(f"🔍 DEBUG: Form data received:")
        print(f"   trusted_issuer_address (from form): {trusted_issuer_address}")
        print(f"   claim_issuer_address (from DB): {claim_issuer_address}")
        
        print(f"🔗 Adding trusted issuer {trusted_issuer.username} to token {token.name}")
        print(f"   Trusted Issuer Wallet: {trusted_issuer.wallet_address}")
        print(f"   ClaimIssuer Contract: {claim_issuer_address}")
        print(f"   Claim Topics: {claim_topics}")
        print(f"   Token Address: {token.token_address}")
        
        # Add trusted issuer to token's Identity Registry via blockchain
        try:
            from services.trex_service import TREXService
            from services.web3_service import Web3Service
            
            # Initialize services
            # IMPORTANT: For trusted issuer management, we need to use Account 0 (platform)
            # because Account 0 owns the TrustedIssuersRegistry
            account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
            web3_service = Web3Service(private_key=account_0_private_key)
            trex_service = TREXService(web3_service)
            
            # Call the token's Identity Registry to add trusted issuer
            print(f"🚀 Calling blockchain to add trusted issuer to TIR...")
            
            # DEBUG: Check who owns the TrustedIssuersRegistry
            print(f"🔍 DEBUG: Checking TIR ownership...")
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
            result = trex_service.add_trusted_issuer_to_token(
                token_address=token.token_address,
                trusted_issuer_address=claim_issuer_address,  # ← Use ClaimIssuer contract address!
                claim_topics=claim_topics
            )
            
            if result['success']:
                print(f"✅ Successfully added trusted issuer to blockchain")
                
                # Update token in database to include this trusted issuer
                current_trusted_issuers = []
                if token.trusted_issuers:
                    try:
                        current_trusted_issuers = json.loads(token.trusted_issuers)
                    except (json.JSONDecodeError, TypeError):
                        current_trusted_issuers = []
                
                if trusted_issuer_id not in current_trusted_issuers:
                    current_trusted_issuers.append(trusted_issuer_id)
                    token.trusted_issuers = json.dumps(current_trusted_issuers)
                    db.session.commit()
                    print(f"✅ Updated token database with trusted issuer")
                
                return jsonify({
                    'success': True, 
                    'message': f'Trusted issuer {trusted_issuer.username} added successfully to token {token.name}'
                })
            else:
                print(f"❌ Blockchain call failed: {result['error']}")
                return jsonify({'success': False, 'error': f'Blockchain integration failed: {result["error"]}'}), 500
                
        except Exception as e:
            print(f"❌ Error adding trusted issuer to blockchain: {str(e)}")
            return jsonify({'success': False, 'error': f'Blockchain integration error: {str(e)}'}), 500
        
    except Exception as e:
        print(f"❌ Error in add_trusted_issuer_to_token: {str(e)}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500

@issuer_bp.route('/token/<int:token_id>/add-agent', methods=['POST'])
def add_agent_to_token(token_id):
    """Add an agent to a token"""
    try:
        # Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        agent_type = data.get('agent_type')  # 'ir_agent' or 'token_agent'
        agent_role = data.get('agent_role')  # 'issuer', 'admin', etc.
        
        if not agent_type or not agent_role:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
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
        
        # Add or remove agent via blockchain
        try:
            from services.trex_service import TREXService
            from services.web3_service import Web3Service
            
            # Initialize services
            # IMPORTANT: For agent management, we need to use Account 0 (platform)
            # because Account 0 has the necessary permissions on the contracts
            account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
            web3_service = Web3Service(private_key=account_0_private_key)
            trex_service = TREXService(web3_service)
            
            if agent_role:
                # Adding agent
                print(f"🚀 Calling blockchain to add agent to {agent_type}...")
                
                # DEBUG: Check who has permissions on the token contracts
                print(f"🔍 DEBUG: Checking token contract permissions...")
                try:
                    # Get the token's Identity Registry address first
                    token_info = trex_service.get_token_info(token.token_address)
                    if token_info.get('success') and token_info.get('token_info'):
                        identity_registry_address = token_info['token_info'].get('identity_registry')
                        print(f"🔍 DEBUG: Identity Registry address: {identity_registry_address}")
                        
                        if identity_registry_address:
                            # Check who owns the Identity Registry
                            ir_owner = web3_service.call_contract_function(
                                'IdentityRegistry', 
                                identity_registry_address, 
                                'owner'
                            )
                            print(f"🔍 DEBUG: Identity Registry owner: {ir_owner}")
                            print(f"🔍 DEBUG: Account 0 address: {web3_service.account.address}")
                            print(f"🔍 DEBUG: Owner match: {ir_owner.lower() == web3_service.account.address.lower()}")
                            
                            # Also check if the issuer has any special permissions
                            print(f"🔍 DEBUG: Issuer address: {user.wallet_address}")
                            
                            # Check if issuer is the owner
                            if ir_owner.lower() == user.wallet_address.lower():
                                print(f"🔍 DEBUG: ISSUER is the owner of Identity Registry!")
                                # Use issuer's private key since they own the Identity Registry
                                print(f"🔑 Using ISSUER's private key for Identity Registry management")
                                web3_service = Web3Service(private_key=user.private_key)
                                trex_service = TREXService(web3_service)
                            elif ir_owner.lower() == web3_service.account.address.lower():
                                print(f"🔍 DEBUG: ACCOUNT 0 is the owner of Identity Registry!")
                                # Already using Account 0's key, no need to change
                                print(f"🔑 Using ACCOUNT 0's private key for Identity Registry management")
                            else:
                                print(f"🔍 DEBUG: Neither issuer nor Account 0 owns Identity Registry. Owner: {ir_owner}")
                                # Fallback to issuer's key
                                print(f"🔑 Using ISSUER's private key as fallback")
                                web3_service = Web3Service(private_key=user.private_key)
                                trex_service = TREXService(web3_service)
                                
                except Exception as debug_error:
                    print(f"🔍 DEBUG: Error checking permissions: {debug_error}")
                    # Fallback to issuer's key
                    print(f"🔑 Using ISSUER's private key as fallback")
                    web3_service = Web3Service(private_key=user.private_key)
                    trex_service = TREXService(web3_service)
                
                # Map agent_type to the format expected by TREXService
                trex_agent_type = agent_type
                
                result = trex_service.add_agent_to_token(
                    token_address=token.token_address,
                    agent_address=agent_role,
                    agent_type=trex_agent_type
                )
                
                if result['success']:
                    print(f"✅ Successfully added agent to blockchain")
                    
                    # Update database only after successful blockchain call
                    # Initialize agents JSON field if it doesn't exist
                    if not hasattr(token, 'agents') or not token.agents:
                        token.agents = json.dumps({
                            'identity_agents': [],
                            'token_agents': [],
                            'compliance_agents': []
                        })
                    
                    # Parse existing agents
                    try:
                        agents_data = json.loads(token.agents)
                    except (json.JSONDecodeError, TypeError):
                        agents_data = {
                            'identity_agents': [],
                            'token_agents': [],
                            'compliance_agents': []
                        }
                    
                    # Add new agent to the appropriate list
                    if agent_type == 'ir_agent':
                        if agent_role not in agents_data['identity_agents']:
                            agents_data['identity_agents'].append(agent_role)
                        # Keep legacy field for backward compatibility
                        token.ir_agent = agent_role
                    elif agent_type == 'token_agent':
                        if agent_role not in agents_data['token_agents']:
                            agents_data['token_agents'].append(agent_role)
                        # Keep legacy field for backward compatibility
                        token.token_agent = agent_role
                    
                    # Update the JSON field
                    token.agents = json.dumps(agents_data)
                    
                    db.session.commit()
                    print(f"✅ Updated token database with new agent")
                    
                    message = f'Agent {agent_role} added successfully as {agent_type} for {token.symbol}'
                else:
                    print(f"❌ Blockchain call failed: {result['error']}")
                    return jsonify({'success': False, 'error': f'Blockchain integration failed: {result["error"]}'}), 500
                    
            else:
                # Removing agent
                print(f"🚀 Calling blockchain to remove agent from {agent_type}...")
                
                # Get current agent address to remove
                current_agent = None
                if agent_type == 'ir_agent':
                    current_agent = token.ir_agent
                elif agent_type == 'token_agent':
                    current_agent = token.token_agent
                
                if not current_agent:
                    return jsonify({'success': False, 'error': f'No agent currently assigned to {agent_type}'}), 400
                
                result = trex_service.remove_agent_from_token(
                    token_address=token.token_address,
                    agent_address=current_agent,
                    agent_type=agent_type
                )
                
                if result['success']:
                    print(f"✅ Successfully removed agent from blockchain")
                    
                    # Update database only after successful blockchain call
                    # Update agents JSON field
                    if hasattr(token, 'agents') and token.agents:
                        try:
                            agents_data = json.loads(token.agents)
                            if agent_type == 'ir_agent' and current_agent in agents_data['identity_agents']:
                                agents_data['identity_agents'].remove(current_agent)
                            elif agent_type == 'token_agent' and current_agent in agents_data['token_agents']:
                                agents_data['token_agents'].remove(current_agent)
                            token.agents = json.dumps(agents_data)
                        except (json.JSONDecodeError, TypeError):
                            pass
                    
                    # Update legacy fields
                    if agent_type == 'ir_agent':
                        token.ir_agent = None
                    elif agent_type == 'token_agent':
                        token.token_agent = None
                    
                    db.session.commit()
                    print(f"✅ Updated token database - removed agent")
                    
                    message = f'Agent removed successfully from {agent_type} for {token.symbol}'
                else:
                    print(f"❌ Blockchain call failed: {result['error']}")
                    return jsonify({'success': False, 'error': f'Blockchain integration failed: {result["error"]}'}), 500
            
            return jsonify({
                'success': True,
                'message': message
            })
            
        except Exception as e:
            print(f"❌ Error in blockchain agent management: {str(e)}")
            return jsonify({'success': False, 'error': f'Blockchain integration error: {str(e)}'}), 500
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error adding agent to token: {e}")
        return jsonify({'success': False, 'error': f'Failed to add agent: {str(e)}'}), 500

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
        
        if all_transactions['success']:
            transactions = all_transactions['transactions']
            print(f"✅ Found {len(transactions)} blockchain transactions")
        else:
            print(f"❌ Error getting blockchain transactions: {all_transactions['error']}")
            transactions = []
            
    except Exception as e:
        print(f"❌ Error initializing services: {str(e)}")
        transactions = []
    
    # Get database transactions as fallback
    db_transactions = TokenTransaction.query.filter_by(token_id=token_id).order_by(TokenTransaction.created_at.desc()).all()
    
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

@issuer_bp.route('/token/<int:token_id>/add-to-identity-registry-interest/<int:interest_id>', methods=['POST'])
def add_to_identity_registry_interest(token_id, interest_id):
    """Add investor's OnchainID to the Token's Identity Registry from interest request"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    if not user or user.user_type != 'issuer':
        flash('Issuer access required.', 'error')
        return redirect(url_for('issuer.login', tab_session=tab_session.session_id))
    
    # Get token and interest request
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
        # Get investor
        investor = User.query.get(interest.investor_id)
        
        if not investor.onchain_id:
            flash(f'Investor {investor.username} has no OnchainID registered. They need to create an OnchainID first.', 'error')
            interest.ir_status = 'failed'
            db.session.commit()
            return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
        
        # Check if Identity Registry address exists
        if not token.identity_registry_address:
            flash('Token Identity Registry not deployed. Cannot add investor to IR.', 'error')
            interest.ir_status = 'failed'
            db.session.commit()
            return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session.session_id))
        
        # Actually add the investor's OnchainID to the token's Identity Registry
        try:
            from services.trex_service import TREXService
            from services.web3_service import Web3Service
            
            # Use issuer's private key (who has Agent role)
            private_key = user.private_key
            web3_service = Web3Service(private_key)
            trex_service = TREXService(web3_service)
            
            # Add investor to token's Identity Registry
            result = trex_service.add_user_to_token_identity_registry(
                token_address=token.token_address,
                user_address=investor.wallet_address,
                onchain_id_address=investor.onchain_id
            )
            
            if result['success']:
                # Update interest status
                interest.ir_status = 'added'
                interest.ir_added_at = db.func.now()
                interest.ir_added_by = user.id
                
                db.session.commit()
                
                flash(f'Investor {investor.username} added to Identity Registry successfully! Transaction: {result["tx_hash"][:10]}...', 'success')
            else:
                flash(f'Failed to add investor to Identity Registry: {result["error"]}', 'error')
                interest.ir_status = 'failed'
                db.session.commit()
                
        except Exception as e:
            flash(f'Error adding investor to Identity Registry: {str(e)}', 'error')
            interest.ir_status = 'failed'
            db.session.commit()
        
    except Exception as e:
        flash(f'Error adding investor to Identity Registry: {str(e)}', 'error')
        interest.ir_status = 'failed'
        db.session.commit()
    
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
            balance = web3_service.from_units(balance_wei, 18)
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

@issuer_bp.route('/api/token/<int:token_id>/mint', methods=['POST'])
def api_mint_tokens(token_id):
    """Mint tokens to an address (issuer must be TokenAgent)"""
    tab_session_id = request.args.get('tab_session')
    tab_session = get_or_create_tab_session(tab_session_id)
    user = get_current_user_from_tab_session(tab_session.session_id)
    if not user or user.user_type != 'issuer':
        return jsonify({'success': False, 'error': 'Issuer access required'}), 403

    token = Token.query.get_or_404(token_id)
    if token.issuer_address != user.wallet_address:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    try:
        payload = request.get_json(silent=True) or {}
        to_address = payload.get('to_address')
        amount = payload.get('amount')
        if not to_address or not amount:
            return jsonify({'success': False, 'error': 'to_address and amount are required'}), 400

        web3_service = Web3Service(user.private_key)
        trex_service = TREXService(web3_service)
        result = trex_service.mint_tokens(token_address=token.token_address, to_address=to_address, amount=amount)
        if result.get('success'):
            return jsonify({'success': True, 'tx_hash': result.get('tx_hash')})
        return jsonify({'success': False, 'error': result.get('error', 'Mint failed')}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@issuer_bp.route('/token/<int:token_id>/purchase-requests')
def purchase_requests(token_id):
    """Deprecated view; redirect to unified Requests tab"""
    tab_session_id = request.args.get('tab_session')
    return redirect(url_for('issuer.token_requests', token_id=token_id, tab_session=tab_session_id))

@issuer_bp.route('/token/<int:token_id>/add-to-identity-registry/<int:request_id>', methods=['POST'])
def add_to_identity_registry(token_id, request_id):
    """Add investor's OnchainID to the Token's Identity Registry"""
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
        # Get investor
        investor = User.query.get(purchase_request.investor_id)
        
        if not investor.onchain_id:
            flash(f'Investor {investor.username} has no OnchainID registered. They need to create an OnchainID first.', 'error')
            purchase_request.ir_status = 'failed'
            db.session.commit()
            return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
        
        # Check if Identity Registry address exists
        if not token.identity_registry_address:
            flash('Token Identity Registry not deployed. Cannot add investor to IR.', 'error')
            purchase_request.ir_status = 'failed'
            db.session.commit()
            return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
        
        # Actually add the investor's OnchainID to the token's Identity Registry
        try:
            from services.trex_service import TREXService
            from services.web3_service import Web3Service
            
            # Use issuer's private key (who has Agent role)
            private_key = user.private_key
            web3_service = Web3Service(private_key)
            trex_service = TREXService(web3_service)
            
            # Add investor to token's Identity Registry
            result = trex_service.add_user_to_token_identity_registry(
                token_address=token.token_address,
                user_address=investor.wallet_address,
                onchain_id_address=investor.onchain_id
            )
            
            if result['success']:
                # Update purchase request status
                purchase_request.ir_status = 'added'
                purchase_request.ir_added_at = db.func.now()
                purchase_request.ir_added_by = user.id
                
                db.session.commit()
                
                flash(f'Investor {investor.username} added to Identity Registry successfully! Transaction: {result["tx_hash"][:10]}...', 'success')
            else:
                flash(f'Failed to add investor to Identity Registry: {result["error"]}', 'error')
                purchase_request.ir_status = 'failed'
                db.session.commit()
                
        except Exception as e:
            flash(f'Error adding investor to Identity Registry: {str(e)}', 'error')
            purchase_request.ir_status = 'failed'
            db.session.commit()
        
    except Exception as e:
        flash(f'Error adding investor to Identity Registry: {str(e)}', 'error')
        purchase_request.ir_status = 'failed'
        db.session.commit()
    
    return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))

@issuer_bp.route('/token/<int:token_id>/verify-investor/<int:request_id>', methods=['POST'])
def verify_investor(token_id, request_id):
    """Verify investor's KYC claims after they've been added to Identity Registry"""
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
    
    # Check if investor has been added to Identity Registry first
    if purchase_request.ir_status != 'added':
        flash('Investor must be added to Identity Registry before KYC verification.', 'warning')
        return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        # Get investor
        investor = User.query.get(purchase_request.investor_id)
        
        # Check if investor has OnchainID
        if not investor.onchain_id:
            flash(f'Investor {investor.username} has no OnchainID registered.', 'error')
            purchase_request.verification_status = 'failed'
            db.session.commit()
            return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
        
        # Check if Identity Registry address exists
        if not token.identity_registry_address:
            flash('Token Identity Registry not deployed. Cannot verify KYC.', 'error')
            purchase_request.verification_status = 'failed'
            db.session.commit()
            return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
        
        # Actually verify KYC using the token's Identity Registry isVerified() method
        try:
            from services.trex_service import TREXService
            from services.web3_service import Web3Service
            
            # Use issuer's private key (who has Agent role)
            private_key = user.private_key
            web3_service = Web3Service(private_key)
            trex_service = TREXService(web3_service)
            
            # Check if investor is verified using Identity Registry
            verification_result = trex_service.check_user_verification(
                token_address=token.token_address,
                user_address=investor.wallet_address
            )
            
            if verification_result['success'] and verification_result['verified']:
                kyc_verified = True
                compliance_verified = True
            else:
                kyc_verified = False
                compliance_verified = False
                flash(f'KYC verification failed: {verification_result.get("reason", "Unknown error")}', 'warning')
                
        except Exception as e:
            flash(f'Error during KYC verification: {str(e)}', 'error')
            kyc_verified = False
            compliance_verified = False
        
        # Update verification status
        purchase_request.verification_status = 'verified' if (kyc_verified and compliance_verified) else 'failed'
        purchase_request.verification_checked_at = db.func.now()
        purchase_request.verification_checked_by = user.id
        
        # Create or update investor verification record
        verification = InvestorVerification.query.filter_by(
            token_id=token_id,
            investor_id=investor.id
        ).first()
        
        if not verification:
            verification = InvestorVerification(
                token_id=token_id,
                investor_id=investor.id
            )
            db.session.add(verification)
        
        verification.is_verified = purchase_request.verification_status == 'verified'
        verification.verification_date = db.func.now()
        verification.verified_by = user.id
        verification.onchain_id_verified = True  # Already added to IR
        verification.kyc_verified = kyc_verified
        verification.compliance_verified = compliance_verified
        verification.verification_notes = f"KYC: {'✓' if kyc_verified else '✗'}, Compliance: {'✓' if compliance_verified else '✗'}"
        
        db.session.commit()
        
        if purchase_request.verification_status == 'verified':
            flash(f'Investor {investor.username} KYC verified successfully!', 'success')
        else:
            flash(f'Investor {investor.username} KYC verification failed. Check KYC status.', 'warning')
        
    except Exception as e:
        flash(f'Error verifying investor KYC: {str(e)}', 'error')
    
    return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))

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

@issuer_bp.route('/token/<int:token_id>/mint-for-purchase/<int:request_id>', methods=['POST'])
def mint_for_purchase(token_id, request_id):
    """Mint tokens for an approved purchase request"""
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
    
    # Investor IR/KYC is handled at interest stage; no duplicate check here
    
    try:
        # Get investor
        investor = User.query.get(purchase_request.investor_id)
        
        # Use issuer's private key
        private_key = user.private_key
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service(private_key)
        trex_service = TREXService(web3_service)
        
        # Mint tokens to investor's account
        result = trex_service.mint_tokens(
            token_address=token.token_address,
            to_address=investor.wallet_address,
            amount=purchase_request.amount_requested
        )
        
        if result['success']:
            # Refresh on-chain verification status for record keeping
            try:
                verification_result = trex_service.check_user_verification(
                    token_address=token.token_address,
                    user_address=investor.wallet_address
                )
                if verification_result.get('success') and verification_result.get('verified'):
                    purchase_request.verification_status = 'verified'
                else:
                    # Keep a failed marker if explicitly unverified
                    if verification_result.get('success'):
                        purchase_request.verification_status = 'failed'
            except Exception:
                pass
            purchase_request.verification_checked_at = db.func.now()
            purchase_request.verification_checked_by = user.id
            # Update purchase request status
            purchase_request.status = 'completed'
            purchase_request.purchase_completed_at = db.func.now()
            purchase_request.transaction_hash = result['tx_hash']
            
            # Create transaction record
            transaction = TokenTransaction(
                token_id=token_id,
                transaction_type='mint',
                to_address=investor.wallet_address,
                amount=purchase_request.amount_requested,
                purchase_request_id=request_id,
                transaction_hash=result['tx_hash'],
                executed_by=user.id
            )
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Successfully minted {purchase_request.amount_requested} {token.symbol} to {investor.username}! Transaction: {result["tx_hash"][:10]}...', 'success')
        else:
            flash(f'Failed to mint tokens: {result["error"]}', 'error')
        
    except Exception as e:
        flash(f'Error minting tokens: {str(e)}', 'error')
    
    return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))

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

@issuer_bp.route('/token/<int:token_id>/force-transfer-for-purchase/<int:request_id>', methods=['POST'])
def force_transfer_for_purchase(token_id, request_id):
    """Force transfer tokens for an approved purchase request"""
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
    
    # Investor IR/KYC is handled at interest stage; no duplicate check here
    
    # Get form data
    from_address = request.form.get('from_address')
    to_address = request.form.get('to_address')
    
    if not from_address or not to_address:
        flash('Both from and to addresses are required.', 'error')
        return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        # Get investor
        investor = User.query.get(purchase_request.investor_id)
        
        # Use issuer's private key
        private_key = user.private_key
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        web3_service = Web3Service(private_key)
        trex_service = TREXService(web3_service)
        
        # Force transfer tokens
        result = trex_service.force_transfer(
            token_address=token.token_address,
            from_address=from_address,
            to_address=to_address,
            amount=purchase_request.amount_requested
        )
        
        if result['success']:
            # Update purchase request status
            purchase_request.status = 'completed'
            purchase_request.purchase_completed_at = db.func.now()
            purchase_request.transaction_hash = result['tx_hash']
            
            # Create transaction record
            transaction = TokenTransaction(
                token_id=token_id,
                transaction_type='transfer',
                from_address=from_address,
                to_address=to_address,
                amount=purchase_request.amount_requested,
                purchase_request_id=request_id,
                transaction_hash=result['tx_hash'],
                executed_by=user.id
            )
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Successfully transferred {purchase_request.amount_requested} {token.symbol} from {from_address[:6]}...{from_address[-4:]} to {to_address[:6]}...{to_address[-4:]}. Transaction: {result["tx_hash"][:10]}...', 'success')
        else:
            flash(f'Failed to transfer tokens: {result["error"]}', 'error')
        
    except Exception as e:
        flash(f'Error transferring tokens: {str(e)}', 'error')
    
    return redirect(url_for('issuer.purchase_requests', token_id=token_id, tab_session=tab_session.session_id))

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

@issuer_bp.route('/token/<int:token_id>/mint-tokens', methods=['POST'])
def mint_tokens(token_id):
    """Mint tokens to an address"""
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
    
    # Get form data
    to_address = request.form.get('to_address')
    amount = request.form.get('amount')
    purchase_request_id = request.form.get('purchase_request_id')
    
    if not to_address or not amount:
        flash('Address and amount are required.', 'error')
        return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        amount = int(amount)
        if amount <= 0:
            flash('Amount must be greater than 0.', 'error')
            return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))
        
        # Actually mint tokens on blockchain
        web3_service = Web3Service(user.private_key)
        trex_service = TREXService(web3_service)
        transaction_indexer = TransactionIndexer(web3_service)
        
        # Create pre-transaction balance snapshot
        transaction_indexer.create_balance_snapshot(
            token_id=token_id,
            wallet_address=to_address,
            snapshot_type='pre_transaction'
        )
        
        result = trex_service.mint_tokens(token_address=token.token_address, to_address=to_address, amount=amount)
        
        if result.get('success'):
            # Index the transaction with enhanced details
            transaction_indexer.index_token_transaction(
                token_id=token_id,
                transaction_type='mint',
                to_address=to_address,
                amount=amount * (10**18),  # Convert to wei for storage
                transaction_hash=result.get('tx_hash'),
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                purchase_request_id=purchase_request_id,
                notes=f'Minted {amount} {token.symbol} tokens'
            )
            
            # Create post-transaction balance snapshot
            transaction_indexer.create_balance_snapshot(
                token_id=token_id,
                wallet_address=to_address,
                snapshot_type='post_transaction'
            )
            
            # Also create legacy transaction record for backward compatibility
            transaction = TokenTransaction(
                token_id=token_id,
                transaction_type='mint',
                to_address=to_address,
                amount=amount,
                purchase_request_id=purchase_request_id,
                executed_by=user.id,
                transaction_hash=result.get('tx_hash')
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Successfully minted {amount} {token.symbol} tokens to {to_address[:6]}...{to_address[-4:]}. Transaction: {result.get("tx_hash", "N/A")}', 'success')
        else:
            flash(f'Failed to mint tokens: {result.get("error", "Unknown error")}', 'error')
        
    except ValueError:
        flash('Invalid amount.', 'error')
    except Exception as e:
        flash(f'Error minting tokens: {str(e)}', 'error')
    
    return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))

@issuer_bp.route('/token/<int:token_id>/burn-tokens', methods=['POST'])
def burn_tokens(token_id):
    """Burn tokens from an address"""
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
    
    # Get form data
    from_address = request.form.get('from_address')
    amount = request.form.get('amount')
    
    if not from_address or not amount:
        flash('Address and amount are required.', 'error')
        return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        amount = int(amount)
        if amount <= 0:
            flash('Amount must be greater than 0.', 'error')
            return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))
        
        # Actually burn tokens on blockchain
        web3_service = Web3Service(user.private_key)
        trex_service = TREXService(web3_service)
        transaction_indexer = TransactionIndexer(web3_service)
        
        # Create pre-transaction balance snapshot
        transaction_indexer.create_balance_snapshot(
            token_id=token_id,
            wallet_address=from_address,
            snapshot_type='pre_transaction'
        )
        
        result = trex_service.burn_tokens(token_address=token.token_address, from_address=from_address, amount=amount)
        
        if result.get('success'):
            # Index the transaction with enhanced details
            transaction_indexer.index_token_transaction(
                token_id=token_id,
                transaction_type='burn',
                from_address=from_address,
                amount=amount * (10**18),  # Convert to wei for storage
                transaction_hash=result.get('tx_hash'),
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Burned {amount} {token.symbol} tokens'
            )
            
            # Create post-transaction balance snapshot
            transaction_indexer.create_balance_snapshot(
                token_id=token_id,
                wallet_address=from_address,
                snapshot_type='post_transaction'
            )
            
            # Also create legacy transaction record for backward compatibility
            transaction = TokenTransaction(
                token_id=token_id,
                transaction_type='burn',
                from_address=from_address,
                amount=amount,
                executed_by=user.id,
                transaction_hash=result.get('tx_hash')
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Successfully burned {amount} {token.symbol} tokens from {from_address[:6]}...{from_address[-4:]}. Transaction: {result.get("tx_hash", "N/A")}', 'success')
        else:
            flash(f'Failed to burn tokens: {result.get("error", "Unknown error")}', 'error')
        
    except ValueError:
        flash('Invalid amount.', 'error')
    except Exception as e:
        flash(f'Error burning tokens: {str(e)}', 'error')
    
    return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))

@issuer_bp.route('/token/<int:token_id>/transfer-tokens', methods=['POST'])
def transfer_tokens(token_id):
    """Transfer tokens between addresses"""
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
    
    # Get form data
    from_address = request.form.get('from_address')
    to_address = request.form.get('to_address')
    amount = request.form.get('amount')
    
    if not from_address or not to_address or not amount:
        flash('From address, to address, and amount are required.', 'error')
        return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))
    
    try:
        amount = int(amount)
        if amount <= 0:
            flash('Amount must be greater than 0.', 'error')
            return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))
        
        # Actually transfer tokens on blockchain
        web3_service = Web3Service(user.private_key)
        trex_service = TREXService(web3_service)
        transaction_indexer = TransactionIndexer(web3_service)
        
        # Create pre-transaction balance snapshots
        transaction_indexer.create_balance_snapshot(
            token_id=token_id,
            wallet_address=from_address,
            snapshot_type='pre_transaction'
        )
        transaction_indexer.create_balance_snapshot(
            token_id=token_id,
            wallet_address=to_address,
            snapshot_type='pre_transaction'
        )
        
        result = trex_service.transfer_tokens(token_address=token.token_address, from_address=from_address, to_address=to_address, amount=amount)
        
        if result.get('success'):
            # Index the transaction with enhanced details
            transaction_indexer.index_token_transaction(
                token_id=token_id,
                transaction_type='forced_transfer',
                from_address=from_address,
                to_address=to_address,
                amount=amount * (10**18),  # Convert to wei for storage
                transaction_hash=result.get('tx_hash'),
                executed_by_user_id=user.id,
                executed_by_address=user.wallet_address,
                notes=f'Transferred {amount} {token.symbol} tokens'
            )
            
            # Create post-transaction balance snapshots
            transaction_indexer.create_balance_snapshot(
                token_id=token_id,
                wallet_address=from_address,
                snapshot_type='post_transaction'
            )
            transaction_indexer.create_balance_snapshot(
                token_id=token_id,
                wallet_address=to_address,
                snapshot_type='post_transaction'
            )
            
            # Also create legacy transaction record for backward compatibility
            transaction = TokenTransaction(
                token_id=token_id,
                transaction_type='transfer',
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                executed_by=user.id,
                transaction_hash=result.get('tx_hash')
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash(f'Successfully transferred {amount} {token.symbol} tokens from {from_address[:6]}...{from_address[-4:]} to {to_address[:6]}...{to_address[-4:]}. Transaction: {result.get("tx_hash", "N/A")}', 'success')
        else:
            flash(f'Failed to transfer tokens: {result.get("error", "Unknown error")}', 'error')
        
    except ValueError:
        flash('Invalid amount.', 'error')
    except Exception as e:
        flash(f'Error transferring tokens: {str(e)}', 'error')
    
    return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id))



@issuer_bp.route('/token/<int:token_id>/toggle-pause', methods=['POST'])
def toggle_pause(token_id):
    """Toggle token pause status"""
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
    
    try:
        # Get current pause status from blockchain
        web3_service = Web3Service(user.private_key)
        current_paused = web3_service.call_contract_function('Token', token.token_address, 'paused')
        
        # Determine what action to take
        if current_paused:
            # Token is paused, so unpause it
            tx_hash = web3_service.transact_contract_function('Token', token.token_address, 'unpause')
            receipt = web3_service.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                token.is_paused = False
                db.session.commit()
                flash(f'Token unpaused successfully. Transaction: {tx_hash}', 'success')
            else:
                flash('Failed to unpause token on blockchain', 'error')
        else:
            # Token is not paused, so pause it
            tx_hash = web3_service.transact_contract_function('Token', token.token_address, 'pause')
            receipt = web3_service.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                token.is_paused = True
                db.session.commit()
                flash(f'Token paused successfully. Transaction: {tx_hash}', 'success')
            else:
                flash('Failed to pause token on blockchain', 'error')
        
    except Exception as e:
        flash(f'Error toggling pause status: {str(e)}', 'error')
    
    return redirect(url_for('issuer.token_actions', token_id=token_id, tab_session=tab_session.session_id)) 

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