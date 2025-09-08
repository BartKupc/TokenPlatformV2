#!/usr/bin/env python3
"""
Test script to add identity to Identity Registry
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Flask app context
from app import app

from services.web3_service import Web3Service
from services.trex_service import TREXService

def test_add_identity_to_ir():
    """Test adding an identity to the Identity Registry"""
    
    # Test data
    issuer_private_key = "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0"
    issuer_address = "0xdD2FD4581271e230360230F9337D5c0430Bf44C0"
    
    # Identity to add
    investor_address = "0x1CBd3b2770909D4e10f157cABC84C7264073C9Ec"
    onchain_id_address = "0x2ac78F89F8652820C20242b202F45880019AfD64"  # Use existing OnchainID
    country_code = 840  # US
    
    # Token and IR addresses (from your deployment)
    token_address = "0xABE8877fA6546Fff815Ce3DBC491a71fC951C1EB"
    ir_address = "0xa3d6113B1F084b2A1d53E7aC6Cd866A70d5e14d1"
    
    print("🧪 Testing Identity Registry Add Identity")
    print("=" * 50)
    print(f"Issuer: {issuer_address}")
    print(f"Investor: {investor_address}")
    print(f"OnchainID: {onchain_id_address}")
    print(f"Country Code: {country_code}")
    print(f"IR Address: {ir_address}")
    print()
    
    try:
        # Create Web3Service with issuer private key
        print("🔗 Creating Web3Service...")
        web3_service = Web3Service(private_key=issuer_private_key)
        
        # Create TREXService
        print("🔗 Creating TREXService...")
        trex_service = TREXService(web3_service)
        
        # Check if issuer is agent of IR
        print("🔍 Checking if issuer is agent of IR...")
        is_agent = web3_service.call_contract_function(
            'IdentityRegistry',
            ir_address,
            'isAgent',
            issuer_address
        )
        print(f"   Is agent: {is_agent}")
        
        # Check if investor is already registered
        print("🔍 Checking if investor is already registered...")
        is_registered = web3_service.call_contract_function(
            'IdentityRegistry',
            ir_address,
            'contains',
            investor_address
        )
        print(f"   Is registered: {is_registered}")
        
        if is_registered:
            print("⚠️  Investor is already registered, skipping...")
            return
        
        # Check OnchainID validity
        print("🔍 Checking OnchainID validity...")
        try:
            onchain_id_contract = web3_service.get_contract(onchain_id_address, 'Identity')
            is_valid = onchain_id_contract.functions.isValid().call()
            print(f"   OnchainID is valid: {is_valid}")
        except Exception as e:
            print(f"   Error checking OnchainID: {e}")
        
        # Build the transaction
        print("🔧 Building registerIdentity transaction...")
        transaction = trex_service.build_add_to_ir_transaction(
            token_address=token_address,
            user_address=investor_address,
            onchain_id_address=onchain_id_address,
            user_address_for_gas=issuer_address,
            country_code=country_code
        )
        
        if not transaction.get('success', False):
            print(f"❌ Failed to build transaction: {transaction.get('error', 'Unknown error')}")
            return
        
        print("✅ Transaction built successfully!")
        
        # Extract the actual transaction data from the nested structure
        tx_data = transaction['transaction']
        print(f"   To: {tx_data['to']}")
        print(f"   Data: {tx_data['data'][:50]}...")
        print(f"   Gas: {tx_data['gas']}")
        print(f"   Gas Price: {tx_data['gasPrice']}")
        print(f"   Chain ID: {tx_data['chainId']}")
        
        # Check the function selector
        data = tx_data['data']
        if data.startswith('0x'):
            data = data[2:]
        selector = '0x' + data[:8]
        print(f"   Function Selector: {selector}")
        
        # Expected selector for registerIdentity(address,address,uint16)
        expected_selector = "0xa2b46661"
        if selector == expected_selector:
            print("✅ Function selector is correct!")
        else:
            print(f"❌ Function selector mismatch! Expected: {expected_selector}, Got: {selector}")
            
        # Debug: Check what ABI is actually being used
        print("\n🔍 DEBUG: Checking ABI being used...")
        ir_abi = web3_service.contract_abis.get('IdentityRegistry', [])
        print(f"   IdentityRegistry ABI loaded: {len(ir_abi)} functions")
        
        # Find registerIdentity in the ABI
        register_funcs = [func for func in ir_abi if func.get('name') == 'registerIdentity']
        print(f"   Found {len(register_funcs)} registerIdentity functions in ABI:")
        for i, func in enumerate(register_funcs):
            inputs = [inp.get('type') for inp in func.get('inputs', [])]
            print(f"     Function {i+1}: registerIdentity({','.join(inputs)})")
            
        # Check if the contract object has the right ABI
        print(f"\n🔍 DEBUG: Contract object ABI:")
        contract = web3_service.get_contract(ir_address, 'IdentityRegistry')
        if contract:
            contract_abi = contract.abi
            print(f"   Contract ABI has {len(contract_abi)} functions")
            contract_register_funcs = [func for func in contract_abi if func.get('name') == 'registerIdentity']
            print(f"   Contract has {len(contract_register_funcs)} registerIdentity functions:")
            for i, func in enumerate(contract_register_funcs):
                inputs = [inp.get('type') for inp in func.get('inputs', [])]
                print(f"     Function {i+1}: registerIdentity({','.join(inputs)})")
        
        # Ask user if they want to send the transaction
        print()
        response = input("Do you want to send this transaction? (y/N): ").strip().lower()
        if response == 'y':
            print("🚀 Sending transaction...")
            
            # Send the transaction
            tx_hash = web3_service.send_transaction(tx_data)
            print(f"✅ Transaction sent! Hash: {tx_hash}")
            
            # Wait for confirmation
            print("⏳ Waiting for transaction confirmation...")
            receipt = web3_service.wait_for_transaction(tx_hash)
            
            if receipt.status == 1:
                print("✅ Transaction confirmed successfully!")
                
                # Verify the investor is now registered
                is_registered_after = web3_service.call_contract_function(
                    'IdentityRegistry',
                    ir_address,
                    'contains',
                    investor_address
                )
                print(f"   Investor registered after: {is_registered_after}")
            else:
                print(f"❌ Transaction failed with status: {receipt.status}")
        else:
            print("⏭️  Transaction not sent (user cancelled)")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    with app.app_context():
        test_add_identity_to_ir()
