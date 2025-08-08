from app import app
from services.web3_service import Web3Service
from models.user import User

with app.app_context():
    web3_service = Web3Service()
    trusted_issuer = User.query.filter_by(user_type='trusted_issuer').first()
    
    print('=== CHECKING CLAIMISSUER CONTRACT ===')
    print(f'ClaimIssuer address: {trusted_issuer.claim_issuer_address}')
    print(f'Trusted issuer wallet: {trusted_issuer.wallet_address}')
    
    # Check what functions are available in ClaimIssuer
    claimissuer_contract = web3_service.w3.eth.contract(
        address=trusted_issuer.claim_issuer_address,
        abi=web3_service.contract_abis['ClaimIssuer']
    )
    
    print('\n=== AVAILABLE FUNCTIONS IN CLAIMISSUER ===')
    for func in claimissuer_contract.all_functions():
        print(f'- {func.fn_name}')
    
    # Try to check if trusted issuer is a signing key using different methods
    print('\n=== CHECKING SIGNING KEY STATUS ===')
    
    try:
        # Try to get the issuer address from the contract
        issuer_address = claimissuer_contract.functions.issuer().call()
        print(f'ClaimIssuer issuer address: {issuer_address}')
        print(f'Matches trusted issuer? {issuer_address.lower() == trusted_issuer.wallet_address.lower()}')
        
    except Exception as e:
        print(f'Error getting issuer address: {e}')
    
    try:
        # Try to check if the address is authorized
        is_authorized = claimissuer_contract.functions.isAuthorized(trusted_issuer.wallet_address).call()
        print(f'Is trusted issuer authorized? {is_authorized}')
        
    except Exception as e:
        print(f'Error checking authorization: {e}')
    
    try:
        # Try to get the owner
        owner = claimissuer_contract.functions.owner().call()
        print(f'ClaimIssuer owner: {owner}')
        print(f'Matches trusted issuer? {owner.lower() == trusted_issuer.wallet_address.lower()}')
        
    except Exception as e:
        print(f'Error getting owner: {e}') 