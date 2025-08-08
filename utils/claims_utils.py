from models.user import UserClaim, TokenClaimRequirement, User
from models.token import Token

def check_user_claims_for_token(user_id, token_id):
    """Check if a user has all required claims for a specific token"""
    # Get token's claim requirements
    token_requirements = TokenClaimRequirement.query.filter_by(
        token_id=token_id, 
        is_required=True
    ).all()
    
    if not token_requirements:
        return True, []  # No requirements = always compliant
    
    # Get user's active claims
    user_claims = UserClaim.query.filter_by(
        user_id=user_id, 
        is_active=True
    ).all()
    
    missing_claims = []
    for requirement in token_requirements:
        # Check if user has this specific claim
        has_claim = any(
            claim.claim_topic == requirement.claim_topic and 
            claim.claim_data == requirement.claim_data
            for claim in user_claims
        )
        
        if not has_claim:
            missing_claims.append({
                'topic': requirement.claim_topic,
                'data': requirement.claim_data,
                'description': f"Topic {requirement.claim_topic}: {requirement.claim_data}"
            })
    
    return len(missing_claims) == 0, missing_claims

def get_user_missing_claims(user_id):
    """Get all missing claims for a user across all tokens"""
    all_tokens = Token.query.all()
    missing_claims_summary = {}
    
    for token in all_tokens:
        is_compliant, missing = check_user_claims_for_token(user_id, token.id)
        if not is_compliant:
            missing_claims_summary[token.id] = {
                'token_name': token.name,
                'token_symbol': token.symbol,
                'missing_claims': missing
            }
    
    return missing_claims_summary

def get_trusted_issuers():
    """Get all trusted issuers with their capabilities"""
    from models.user import User, TrustedIssuerCapability
    
    # Get all trusted issuers - the capabilities relationship will be loaded automatically
    trusted_issuers = User.query.filter_by(user_type='trusted_issuer').all()
    
    # Convert capabilities to JSON-serializable format for each trusted issuer
    for trusted_issuer in trusted_issuers:
        # Convert capabilities to a list of dictionaries
        capabilities_list = []
        for capability in trusted_issuer.capabilities:
            if capability.is_active:
                capabilities_list.append({
                    'id': capability.id,
                    'claim_topic': capability.claim_topic,
                    'claim_data': capability.claim_data,
                    'description': capability.description,
                    'is_active': capability.is_active
                })
        
        # Add a JSON-serializable capabilities attribute
        trusted_issuer.capabilities_json = capabilities_list
    
    return trusted_issuers 