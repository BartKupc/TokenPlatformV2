from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from models import db, User, Contract, Token, UserClaim
from services.web3_service import Web3Service
from services.onchainid_service import OnchainIDService
import json

onchainid_bp = Blueprint('onchainid', __name__)

@onchainid_bp.route('/view/<onchainid_address>')
def view_onchainid(onchainid_address):
    """View detailed OnchainID information including keys, claims, and topics"""
    try:
        # Initialize services
        web3_service = Web3Service()
        onchainid_service = OnchainIDService(web3_service)
        
        # Check if this is a wallet address (not a contract) and try to find the OnchainID
        if onchainid_address.startswith('0x') and len(onchainid_address) == 42:
            try:
                # Check if it's already a contract
                code = web3_service.w3.eth.get_code(onchainid_address)
                if code == b'':
                    # It's a wallet address, try to find the OnchainID via IdentityFactory
                    print(f"🔍 Address {onchainid_address} is a wallet, looking up OnchainID...")
                    
                    from services.trex_service import TREXService
                    from utils.contract_utils import get_contract_address
                    
                    trex_service = TREXService(web3_service)
                    identity_factory_address = get_contract_address('IdentityFactory')
                    
                    if identity_factory_address:
                        onchain_id = trex_service.get_identity(onchainid_address, identity_factory_address)
                        if onchain_id and onchain_id != '0x0000000000000000000000000000000000000000':
                            print(f"✅ Found OnchainID {onchain_id} for wallet {onchainid_address}")
                            onchainid_address = onchain_id
                        else:
                            flash(f'No OnchainID found for wallet address {onchainid_address}. Please ensure the user has registered.', 'error')
                            return redirect(url_for('main.home'))
                    else:
                        flash('Identity Factory not deployed. Please deploy T-REX factory first.', 'error')
                        return redirect(url_for('main.home'))
            except Exception as e:
                print(f"❌ Error checking address: {str(e)}")
                # Continue with original address
        
        # Get OnchainID details
        onchainid_info = onchainid_service.get_onchainid_details(onchainid_address)
        
        return render_template('onchainid_view.html', 
                             onchainid_address=onchainid_address,
                             onchainid_info=onchainid_info)
        
    except Exception as e:
        flash(f'Error loading OnchainID details: {str(e)}', 'error')
        return redirect(url_for('main.home'))

@onchainid_bp.route('/api/details/<onchainid_address>')
def api_onchainid_details(onchainid_address):
    """API endpoint to get OnchainID details as JSON"""
    try:
        # Initialize services
        web3_service = Web3Service()
        onchainid_service = OnchainIDService(web3_service)
        
        # Get OnchainID details
        onchainid_info = onchainid_service.get_onchainid_details(onchainid_address)
        
        return jsonify({
            'success': True,
            'onchainid_address': onchainid_address,
            'details': onchainid_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@onchainid_bp.route('/manage-keys/<onchainid_address>')
def manage_keys(onchainid_address):
    """Manage OnchainID keys - add/remove keys with specific purposes"""
    try:
        # Initialize services
        web3_service = Web3Service()
        onchainid_service = OnchainIDService(web3_service)
        
        # Get OnchainID details
        onchainid_info = onchainid_service.get_onchainid_details(onchainid_address)
        
        return render_template('onchainid_manage_keys.html', 
                             onchainid_address=onchainid_address,
                             onchainid_info=onchainid_info)
        
    except Exception as e:
        flash(f'Error loading OnchainID details: {str(e)}', 'error')
        return redirect(url_for('main.home'))

@onchainid_bp.route('/add-key/<onchainid_address>', methods=['POST'])
def add_key(onchainid_address):
    """Add a new key to OnchainID with specific purpose"""
    try:
        data = request.get_json()
        key_address = data.get('key_address')
        role = data.get('role')
        purpose = int(data.get('purpose'))  # 1=Management, 2=Action, 3=Claim Signer
        
        if not key_address or not role or not purpose:
            return jsonify({'success': False, 'error': 'Missing key_address, role, or purpose'}), 400
        
        # Initialize services
        web3_service = Web3Service()
        onchainid_service = OnchainIDService(web3_service)
        
        # Add key to OnchainID
        result = onchainid_service.add_key_to_onchainid(onchainid_address, key_address, purpose, role)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f'Key {key_address} added successfully with purpose {purpose}',
                'transaction_hash': result.get('transaction_hash')
            })
        else:
            return jsonify({'success': False, 'error': result['error']}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@onchainid_bp.route('/remove-key/<onchainid_address>', methods=['POST'])
def remove_key(onchainid_address):
    """Remove a key from OnchainID"""
    try:
        data = request.get_json()
        key_address = data.get('key_address')
        
        if not key_address:
            return jsonify({'success': False, 'error': 'Missing key_address'}), 400
        
        # Initialize services
        web3_service = Web3Service()
        onchainid_service = OnchainIDService(web3_service)
        
        # Remove key from OnchainID
        result = onchainid_service.remove_key_from_onchainid(onchainid_address, key_address)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f'Key {key_address} removed successfully',
                'transaction_hash': result.get('transaction_hash')
            })
        else:
            return jsonify({'success': False, 'error': result['error']}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500 