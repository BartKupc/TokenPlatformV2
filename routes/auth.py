from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from models.user import User, TrustedIssuerApproval, db
from utils.auth_utils import hash_password
from utils.session_utils import get_or_create_tab_session, login_user_to_tab_session, logout_user_from_tab_session
from utils.contract_utils import get_contract_address
import json

auth_bp = Blueprint('auth', __name__)

def add_issuer_to_gateway(user_id, wallet_address, user_type, password):
    """Add issuer to Gateway as deployer using Account 0 (owner)"""
    try:
        from services.web3_service import Web3Service
        from models.contract import Contract
        
        # Get Gateway contract address from database
        gateway_contract = Contract.query.filter_by(contract_type='TREXGateway').first()
        if not gateway_contract:
            return False, "Gateway contract not found in database"
        
        gateway_address = gateway_contract.contract_address
        
        # Use Account 0 (Gateway owner) to add deployer
        account_0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        web3_service = Web3Service(private_key=account_0_private_key)
        
        # Add deployer to Gateway
        tx_hash = web3_service.add_deployer_to_gateway(gateway_address, wallet_address)
        
        print(f"✅ Successfully added {wallet_address} as deployer to Gateway. Transaction: {tx_hash}")
        return True, tx_hash
        
    except Exception as e:
        print(f"❌ Error adding issuer to Gateway: {e}")
        return False, str(e)

def create_user_onchainid(user_id, wallet_address, user_type):
    """Create OnchainID for a user using T-REX Factory"""
    try:
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Use Account 0 (platform) for all operations
        account0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        web3_service = Web3Service(account0_private_key)
        
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
            
            # 🆕 CHECK IF USER ALREADY HAS MANAGEMENT KEY ON EXISTING ONCHAINID
            try:
                from services.onchainid_key_manager import OnchainIDKeyManager
                
                # Use Account 0's private key to check and add management keys
                account0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
                account0_web3_service = Web3Service(account0_private_key)
                platform_key_manager = OnchainIDKeyManager(account0_web3_service)
                
                # Check if user already has management key
                user_key_hash = account0_web3_service.w3.keccak(
                    account0_web3_service.w3.codec.encode(['address'], [wallet_address])
                )
                has_management_key = platform_key_manager.check_key_exists(
                    onchainid_address=onchain_id_address,
                    key_hash=user_key_hash,
                    purpose=1  # Management key
                )
                
                if not has_management_key:
                    print(f"🔑 User doesn't have management key on existing OnchainID, adding now...")
                    # Add user as management key to existing OnchainID using platform authority
                    # Use the standard add_key_to_onchainid method for consistency
                    from services.onchainid_service import OnchainIDService
                    onchainid_service = OnchainIDService(account0_web3_service)
                    
                    key_result = onchainid_service.add_key_to_onchainid(
                        onchainid_address=onchain_id_address,
                        key_address=wallet_address,
                        purpose=1,  # Management key
                        role="User Management Key"
                    )
                    
                    if key_result.get('success'):
                        print(f"✅ Successfully added user {wallet_address} as management key to existing OnchainID")
                    else:
                        print(f"⚠️ Warning: Failed to add user as management key to existing OnchainID: {key_result.get('error')}")
                else:
                    print(f"✅ User already has management key on existing OnchainID")
                    
            except Exception as e:
                print(f"⚠️ Warning: Error checking/adding management key to existing OnchainID: {str(e)}")
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
            management_keys_added=False,  # Will be set to True after we add user's management key
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
        
        # 🆕 ADD USER AS MANAGEMENT KEY TO THEIR OWN ONCHAINID
        if is_new_onchain_id:
            print(f"🔑 Adding user {wallet_address} as management key to their OnchainID {onchain_id_address}")
            try:
                # Add user as management key using Account 0's private key (which has management access)
                from services.onchainid_key_manager import OnchainIDKeyManager
                
                # Create key manager with Account 0's private key (platform owner)
                # Account 0 is the only one with management key access initially
                account0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
                account0_web3_service = Web3Service(account0_private_key)
                platform_key_manager = OnchainIDKeyManager(account0_web3_service)
                
                # Add user as management key to their own OnchainID using platform authority
                # Use the standard add_key_to_onchainid method for consistency
                from services.onchainid_service import OnchainIDService
                onchainid_service = OnchainIDService(account0_web3_service)
                
                key_result = onchainid_service.add_key_to_onchainid(
                    onchainid_address=onchain_id_address,
                    key_address=wallet_address,
                    purpose=1,  # Management key
                    role="User Management Key"
                )
                
                if key_result.get('success'):
                    print(f"✅ Successfully added user {wallet_address} as management key")
                    # Update database to reflect that management keys are now added
                    onchain_id_entry.management_keys_added = True
                    db.session.commit()
                else:
                    print(f"⚠️ Warning: Failed to add user as management key: {key_result.get('error')}")
                    # Don't fail the registration, but log the warning
                    
            except Exception as e:
                print(f"⚠️ Warning: Error adding user as management key: {str(e)}")
                # Don't fail the registration, but log the warning
                # The user can still use their OnchainID, they just won't have management access
        
        success_msg = f"OnchainID {'created' if is_new_onchain_id else 'found'} at {onchain_id_address}"
        if transaction_hash:
            success_msg += f" (tx: {transaction_hash})"
        
        if is_new_onchain_id and onchain_id_entry.management_keys_added:
            success_msg += " - User now has management key access"
        
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
        
        # MetaMask integration will be added later - for now, allow registration without MetaMask
        
        # Create new user
        new_user = User(
            username=username,
            email=None,  # No email required
            password_hash=hash_password(password),
            wallet_address=wallet_address,
            # private_key removed - no longer storing private keys
            user_type=user_type,
            kyc_status='approved' if user_type in ['admin', 'issuer', 'trusted_issuer'] else 'not_submitted'
        )
        
        db.session.add(new_user)
        db.session.flush()  # Get the ID
        
        # Create OnchainID for the user
        onchainid_success, onchainid_result = create_user_onchainid(
            new_user.id, 
            wallet_address, 
            user_type
        )
        
        if not onchainid_success:
            db.session.rollback()
            flash(f'Error creating OnchainID: {onchainid_result}', 'error')
            return render_template('register.html', tab_session_id=request.args.get('tab_session'))
        
        # Add issuer to Gateway as deployer (V2: Gateway role management)
        if user_type in ['issuer', 'trusted_issuer']:
            gateway_success, gateway_result = add_issuer_to_gateway(
                new_user.id,
                wallet_address,
                user_type
            )
            
            if not gateway_success:
                print(f"⚠️ Warning: Could not add issuer to Gateway: {gateway_result}")
                # Don't fail registration, just log warning
            else:
                print(f"✅ Added {user_type} to Gateway as deployer")
                # Mark user as deployer in database
                new_user.is_gateway_deployer = True
        
        # For trusted issuers, also create ClaimIssuer contract and add CLAIM_SIGNER_KEY
        if user_type == 'trusted_issuer':
            print(f"🏭 Creating ClaimIssuer contract for trusted issuer: {wallet_address}")
            
            # Create ClaimIssuer contract
            claimissuer_success, claimissuer_result = create_claimissuer_contract(
                new_user.id,
                wallet_address
            )
            
            if not claimissuer_success:
                db.session.rollback()
                flash(f'Error creating ClaimIssuer contract: {claimissuer_result}', 'error')
                return render_template('register.html', tab_session_id=request.args.get('tab_session'))
            
            print(f"✅ ClaimIssuer contract created: {claimissuer_result}")
            
            # CRITICAL: Add CLAIM_SIGNER_KEY (purpose=3) to trusted issuer's OnchainID
            print(f"🔑 Adding CLAIM_SIGNER_KEY (purpose=3) to trusted issuer's OnchainID...")
            
            add_claim_signer_key_success, add_claim_signer_key_result = add_claim_signer_key_to_onchainid(
                new_user.id,
                wallet_address
            )
            
            if not add_claim_signer_key_success:
                print(f"⚠️ Warning: Could not add CLAIM_SIGNER_KEY to trusted issuer's OnchainID: {add_claim_signer_key_result}")
                # Don't fail registration, just log warning
            else:
                print(f"✅ CLAIM_SIGNER_KEY (purpose=3) added to trusted issuer's OnchainID")
            
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

def create_claimissuer_contract(user_id, wallet_address):
    """Create ClaimIssuer contract for a trusted issuer"""
    try:
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Use Account 0 (platform) for all operations
        account0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        web3_service = Web3Service(account0_private_key)
        
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

def add_issuer_to_gateway(user_id, wallet_address, user_type):
    """Add issuer to TREXGateway as deployer (V2: Gateway role management)"""
    try:
        from services.trex_service import TREXService
        from services.web3_service import Web3Service
        from utils.contract_utils import get_contract_address
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Get Gateway address from database
        gateway_address = get_contract_address('TREXGateway')
        if not gateway_address:
            return False, "TREXGateway not found in database"
        
        print(f"🎯 Adding {user_type} to TREXGateway as deployer: {wallet_address}")
        
        # IMPORTANT: Use Gateway owner's account (Account 0) to add deployers
        # Only the Gateway owner can call addDeployer/addAgent functions
        gateway_owner_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        gateway_owner_address = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
        
        # Initialize Web3 service with Gateway owner's private key
        web3_service = Web3Service(gateway_owner_private_key)
        
        # Load TREXGateway ABI directly
        try:
            with open('artifacts/trex/TREXGateway.json', 'r') as f:
                import json
                abi_data = json.load(f)
                gateway_abi = abi_data.get('abi', [])
        except Exception as e:
            return False, f"Failed to load TREXGateway ABI: {e}"
        
        # Get Gateway contract instance
        gateway_contract = web3_service.w3.eth.contract(
            address=gateway_address,
            abi=gateway_abi
        )
        
        # Add issuer as deployer using Gateway owner's account
        if user_type == 'issuer':
            # Regular issuer: can deploy for themselves
            tx = gateway_contract.functions.addDeployer(wallet_address).build_transaction({
                'from': gateway_owner_address,
                'gas': 200000,
                'gasPrice': web3_service.w3.eth.gas_price,
                'nonce': web3_service.w3.eth.get_transaction_count(gateway_owner_address)
            })
            
            # Sign and send transaction
            signed_tx = web3_service.w3.eth.account.sign_transaction(tx, gateway_owner_private_key)
            tx_hash = web3_service.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"✅ Added issuer as deployer: {tx_hash.hex()}")
            
        elif user_type == 'trusted_issuer':
            # Trusted issuer: can deploy for themselves and others
            tx = gateway_contract.functions.addDeployer(wallet_address).build_transaction({
                'from': gateway_owner_address,
                'gas': 200000,
                'gasPrice': web3_service.w3.eth.gas_price,
                'nonce': web3_service.w3.eth.get_transaction_count(gateway_owner_address)
            })
            
            # Sign and send transaction
            signed_tx = web3_service.w3.eth.account.sign_transaction(tx, gateway_owner_private_key)
            tx_hash = web3_service.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"✅ Added trusted issuer as deployer: {tx_hash.hex()}")
            
            # Also add as agent if they have broader permissions
            try:
                agent_tx = gateway_contract.functions.addAgent(wallet_address).build_transaction({
                    'from': gateway_owner_address,
                    'gas': 200000,
                    'gasPrice': web3_service.w3.eth.gas_price,
                    'nonce': web3_service.w3.eth.get_transaction_count(gateway_owner_address)
                })
                
                # Sign and send agent transaction
                signed_agent_tx = web3_service.w3.eth.account.sign_transaction(agent_tx, gateway_owner_private_key)
                agent_tx_hash = web3_service.w3.eth.send_raw_transaction(signed_agent_tx.rawTransaction)
                
                print(f"✅ Added trusted issuer as agent: {agent_tx_hash.hex()}")
            except Exception as e:
                print(f"⚠️ Could not add as agent: {e}")
        
        return True, f"Successfully added {user_type} to Gateway"
        
    except Exception as e:
        print(f"❌ Error adding issuer to Gateway: {str(e)}")
        return False, str(e)

def add_claim_signer_key_to_onchainid(user_id, wallet_address):
    """Add CLAIM_SIGNER_KEY (purpose=3) to trusted issuer's OnchainID"""
    try:
        from services.web3_service import Web3Service
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Use Account 0 (platform) for all operations
        account0_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        web3_service = Web3Service(account0_private_key)
        
        print(f"🎯 Adding CLAIM_SIGNER_KEY (purpose=3) to trusted issuer's OnchainID: {user.onchain_id}")
        
        # Get Identity contract ABI
        identity_abi = web3_service.get_contract_abi('Identity')
        if not identity_abi:
            return False, "Could not load Identity contract ABI"
        
        # Create Identity contract instance
        identity_contract = web3_service.w3.eth.contract(
            address=user.onchain_id,
            abi=identity_abi
        )
        
        # Create key hash for trusted issuer's EOA (using correct method)
        trusted_issuer_key_hash = web3_service.w3.keccak(
            web3_service.w3.codec.encode(['address'], [wallet_address])
        )
        
        print(f"🔍 Trusted issuer key hash: {trusted_issuer_key_hash.hex()}")
        
        # Add CLAIM_SIGNER_KEY (purpose=3) using the management key
        add_key_tx = identity_contract.functions.addKey(
            trusted_issuer_key_hash,  # key hash
            3,  # purpose = CLAIM_SIGNER_KEY
            1   # key type = ECDSA
        ).build_transaction({
            'from': web3_service.account.address,
            'gas': 200000,
            'gasPrice': web3_service.w3.eth.gas_price,
            'nonce': web3_service.w3.eth.get_transaction_count(web3_service.account.address)
        })
        
        # Sign and send addKey transaction
        signed_add_key_tx = web3_service.w3.eth.account.sign_transaction(add_key_tx, account0_private_key)
        add_key_tx_hash = web3_service.w3.eth.send_raw_transaction(signed_add_key_tx.rawTransaction)
        
        print(f"✅ CLAIM_SIGNER_KEY addition transaction sent: {add_key_tx_hash.hex()}")
        
        # Wait for transaction receipt
        add_key_receipt = web3_service.w3.eth.wait_for_transaction_receipt(add_key_tx_hash)
        
        print(f"✅ CLAIM_SIGNER_KEY (purpose=3) added successfully to trusted issuer's OnchainID!")
        
        return True, f"CLAIM_SIGNER_KEY added successfully. Transaction: {add_key_tx_hash.hex()}"
        
    except Exception as e:
        print(f"❌ Error adding CLAIM_SIGNER_KEY to OnchainID: {str(e)}")
        return False, str(e) 