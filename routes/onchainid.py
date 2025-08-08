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
        
        # Get OnchainID details
        onchainid_info = onchainid_service.get_onchainid_details(onchainid_address)
        

        
        return render_template('onchainid_view.html', 
                             onchainid_address=onchainid_address,
                             onchainid_info=onchainid_info)
        
    except Exception as e:
        flash(f'Error loading OnchainID details: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

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