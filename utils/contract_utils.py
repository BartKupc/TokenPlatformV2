import json
from models import db
from models.contract import Contract

def get_contract_address(contract_type):
    """Get contract address from database"""
    contract = Contract.query.filter_by(contract_type=contract_type, is_active=True).first()
    return contract.contract_address if contract else None

def store_contract(contract_type, contract_address, contract_name, deployed_by, 
                  block_number=None, transaction_hash=None, metadata=None):
    """Store contract information in database"""
    contract = Contract(
        contract_type=contract_type,
        contract_address=contract_address,
        contract_name=contract_name,
        deployed_by=deployed_by,
        block_number=block_number,
        transaction_hash=transaction_hash,
        contract_metadata=json.dumps(metadata) if metadata else None
    )
    db.session.add(contract)
    db.session.commit()
    return contract 