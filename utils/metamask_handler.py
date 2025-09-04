from flask import jsonify, request
from models.token import Token

def handle_metamask_transaction_core(token_id, user_type, user):
    """Core MetaMask transaction handler logic shared across all user types"""
    # For deployment (token_id = 0), we don't have a token yet
    if token_id == 0:
        token = None
    else:
        # Get token
        token = Token.query.get_or_404(token_id)
        
        # Verify ownership based on user type
        if user_type == 'issuer':
            if token.issuer_address != user.wallet_address:
                return jsonify({'success': False, 'error': 'Access denied. You can only manage your own tokens.'}), 403
        elif user_type == 'trusted_issuer':
            # Trusted issuers can manage any token they're assigned to
            # This would need additional validation based on your business logic
            pass
        elif user_type == 'investor':
            # Investors can only interact with tokens they own
            # This would need additional validation based on your business logic
            pass
    
    try:
        # Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        operation = data.get('operation')  # 'add_to_ir', 'verify_kyc', etc.
        action = data.get('action')        # 'build' or 'confirm'
        target_type = data.get('target_type')  # 'interest' or 'purchase' or 'actions'
        target_id = data.get('target_id')      # interest_id or request_id
        
        # For actions tab operations (mint, burn, pause, unpause, transfer, force_transfer, add_ir_agent, add_token_agent, add_trusted_issuer, deploy_token), target_id can be 0
        if operation in ['mint', 'burn', 'pause', 'unpause', 'transfer', 'force_transfer', 'add_ir_agent', 'add_token_agent', 'add_trusted_issuer', 'deploy_token']:
            if not all([operation, action, target_type]):
                return jsonify({'success': False, 'error': f'Missing required parameters for {operation}'}), 400
        else:
            if not all([operation, action, target_type, target_id]):
                return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        # Import the handlers here to avoid circular imports
        from routes.issuer import handle_build_transaction, handle_confirm_transaction, build_deploy_token_transaction_helper
        
        # Route to appropriate handler based on operation and action
        if action == 'build':
            # Use dedicated handler for token deployment
            if operation == 'deploy_token':
                print(f"🔍 DEBUG: Routing deploy_token to build_deploy_token_transaction_helper")
                return build_deploy_token_transaction_helper(token, user, target_type, target_id)
            elif user_type == 'trusted_issuer' and operation == 'add_claims':
                print(f"🔍 DEBUG: Routing trusted issuer add_claims to claim handler")
                return handle_trusted_issuer_claim_transaction(user, data)
            else:
                print(f"🔍 DEBUG: Routing {operation} to handle_build_transaction")
                return handle_build_transaction(token, user, operation, target_type, target_id)
        elif action == 'confirm':
            return handle_confirm_transaction(token, user, operation, target_type, target_id, data)
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error handling MetaMask transaction: {str(e)}'}), 500

def handle_trusted_issuer_claim_transaction(user, data):
    """Handle trusted issuer claim addition transactions"""
    try:
        print(f"🔍 Handling trusted issuer claim transaction for user: {user.username}")
        
        # Get KYC request ID and claim decisions from data
        kyc_request_id = data.get('kyc_request_id')
        claim_decisions = data.get('claim_decisions', {})
        
        if not kyc_request_id:
            return jsonify({'success': False, 'error': 'KYC request ID is required'}), 400
        
        # Import here to avoid circular imports
        from models.enhanced_models import KYCRequest
        
        # Get KYC request
        kyc_request = KYCRequest.query.get_or_404(kyc_request_id)
        
        # Verify this trusted issuer is assigned to this request
        if kyc_request.trusted_issuer_id != user.id:
            return jsonify({'success': False, 'error': 'Access denied. This KYC request is not assigned to you.'}), 403
        
        # Import the helper function from trusted_issuer routes
        from routes.trusted_issuer import execute_claim_addition_with_metamask_approval
        
        # Execute claim addition with MetaMask approval
        result = execute_claim_addition_with_metamask_approval(kyc_request, claim_decisions)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': result['message'],
                'successful_claims': result.get('successful_claims', []),
                'transaction_hashes': result.get('transaction_hashes', [])
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error'],
                'successful_claims': result.get('successful_claims', []),
                'failed_claims': result.get('failed_claims', [])
            }), 500
            
    except Exception as e:
        print(f"❌ Error in trusted issuer claim transaction: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
