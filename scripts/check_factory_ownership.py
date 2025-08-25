#!/usr/bin/env python3
"""
Check and fix TREXFactory ownership - Standalone version
"""

import sys
from web3 import Web3
from eth_account import Account

def check_factory_ownership():
    """Check Factory ownership and fix if needed"""
    
    # Connect to Hardhat
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    
    if not w3.is_connected():
        print("❌ Cannot connect to Hardhat node")
        return False
    
    print(f"✅ Connected to Hardhat at block {w3.eth.block_number}")
    
    # Known contract addresses from your deployment
    factory_address = "0x322813Fd9A801c5507c9de605d63CEA4f2CE6c44"
    gateway_address = "0x4A679253410272dd5232B3Ff7cF5dbB88f295319"
    
    print(f"🔍 Checking Factory ownership...")
    print(f"Factory: {factory_address}")
    print(f"Gateway: {gateway_address}")
    
    # Load contract ABIs (minimal versions)
    factory_abi = [
        {
            "inputs": [],
            "name": "owner",
            "outputs": [{"type": "address"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [{"type": "address"}],
            "name": "transferOwnership",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]
    
    gateway_abi = [
        {
            "inputs": [],
            "name": "owner",
            "outputs": [{"type": "address"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]
    
    # Get contracts
    factory_contract = w3.eth.contract(
        address=factory_address,
        abi=factory_abi
    )
    
    gateway_contract = w3.eth.contract(
        address=gateway_address,
        abi=gateway_abi
    )
    
    try:
        # Check current Factory owner
        factory_owner = factory_contract.functions.owner().call()
        print(f"🏭 Factory owner: {factory_owner}")
        
        # Check Gateway owner
        gateway_owner = gateway_contract.functions.owner().call()
        print(f"🏛️ Gateway owner: {gateway_owner}")
        
        # Check if Gateway owns Factory
        if factory_owner.lower() == gateway_address.lower():
            print("✅ Gateway owns Factory - this is correct!")
            return True
        else:
            print("❌ Gateway does NOT own Factory!")
            print(f"Expected: {gateway_address}")
            print(f"Actual: {factory_owner}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking ownership: {e}")
        return False

def fix_factory_ownership():
    """Transfer Factory ownership to Gateway"""
    
    # Connect to Hardhat
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    
    if not w3.is_connected():
        print("❌ Cannot connect to Hardhat node")
        return
    
    # Known contract addresses
    factory_address = "0x322813Fd9A801c5507c9de605d63CEA4f2CE6c44"
    gateway_address = "0x4A679253410272dd5232B3Ff7cF5dbB88f295319"
    
    # Load contract ABI
    factory_abi = [
        {
            "inputs": [],
            "name": "owner",
            "outputs": [{"type": "address"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [{"type": "address"}],
            "name": "transferOwnership",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]
    
    factory_contract = w3.eth.contract(
        address=factory_address,
        abi=factory_abi
    )
    
    # Check current Factory owner
    factory_owner = factory_contract.functions.owner().call()
    print(f"🏭 Current Factory owner: {factory_owner}")
    
    if factory_owner.lower() == gateway_address.lower():
        print("✅ Factory already owned by Gateway")
        return
    
    # Use the current Factory owner's private key (Account 0)
    owner_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
    owner_account = Account.from_key(owner_private_key)
    
    if owner_account.address.lower() != factory_owner.lower():
        print(f"❌ Private key doesn't match Factory owner")
        print(f"Expected: {factory_owner}")
        print(f"Got: {owner_account.address}")
        return
    
    print(f"✅ Using Factory owner account: {owner_account.address}")
    
    try:
        # Transfer Factory ownership to Gateway
        print(f"🔧 Transferring Factory ownership to Gateway...")
        
        tx = factory_contract.functions.transferOwnership(gateway_address).build_transaction({
            'from': owner_account.address,
            'gas': 200000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(owner_account.address)
        })
        
        # Sign and send transaction
        signed_tx = w3.eth.account.sign_transaction(tx, owner_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        print(f"📝 Transaction sent: {tx_hash.hex()}")
        
        # Wait for confirmation
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            print(f"✅ Successfully transferred Factory ownership to Gateway")
            print(f"Transaction: {receipt.transactionHash.hex()}")
            
            # Verify the change
            new_owner = factory_contract.functions.owner().call()
            print(f"🏭 New Factory owner: {new_owner}")
            
            if new_owner.lower() == gateway_address.lower():
                print("✅ Factory ownership transfer successful!")
            else:
                print("❌ Factory ownership transfer failed!")
        else:
            print(f"❌ Transaction failed")
            
    except Exception as e:
        print(f"❌ Error transferring ownership: {e}")

if __name__ == "__main__":
    print("🔍 TREXFactory Ownership Checker (Standalone)")
    print("=" * 50)
    
    if len(sys.argv) > 1 and sys.argv[1] == "fix":
        print("🔧 Fixing Factory ownership...")
        fix_factory_ownership()
    else:
        is_correct = check_factory_ownership()
        
        if not is_correct:
            print("\n" + "=" * 50)
            print("To fix Factory ownership, run:")
            print("python check_factory_ownership.py fix")
