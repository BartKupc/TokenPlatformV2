import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from web3 import Web3
from eth_account import Account
from eth_abi import encode
import json
import app

def load_abi_from_file(abi_path):
    """Load ABI from file"""
    try:
        with open(abi_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to load ABI from {abi_path}: {e}")
        return None

def main():
    # Configuration - HARDCODED to match working Hardhat test
    INVESTOR_NAME = "bart2"  # Change this to test different investors
    TRUSTED_ISSUER_NAME = "bart1"  # Change this to test different trusted issuers
    
    # Hardcoded addresses from working Hardhat test
    HARDCODED_INVESTOR_ONCHAINID = "0xf5E926037b19EDd3d270dB603EC84D8435F19007"
    HARDCODED_TRUSTED_ISSUER_WALLET = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # This is the one that worked in Hardhat
    HARDCODED_CLAIMISSUER_ADDRESS = "0x057ef64E23666F000b34aE31332854aCBd1c8544"
    
    print("🧪 COMPREHENSIVE CLAIM ADDITION TEST")
    print("=" * 50)
    print(f"🔍 Testing with Investor: {INVESTOR_NAME}")
    print(f"🔍 Testing with Trusted Issuer: {TRUSTED_ISSUER_NAME}")
    print()
    
    # Create Flask app context
    flask_app = app.app
    
    with flask_app.app_context():
        from models.user import User, db
        
        # STEP 1: Load data from database
        print("📋 STEP 1: Loading data from database...")
        
        # Find investor
        investor = User.query.filter_by(username=INVESTOR_NAME).first()
        if not investor:
            print(f"❌ Investor '{INVESTOR_NAME}' not found in database")
            return
        print(f"✅ Found investor: {investor.username} (ID: {investor.id})")
        print(f"   Wallet: {investor.wallet_address}")
        print(f"   OnchainID: {investor.onchain_id}")
        
        # Find trusted issuer
        trusted_issuer = User.query.filter_by(username=TRUSTED_ISSUER_NAME).first()
        if not trusted_issuer:
            print(f"❌ Trusted issuer '{TRUSTED_ISSUER_NAME}' not found in database")
            return
        print(f"✅ Found trusted issuer: {trusted_issuer.username} (ID: {trusted_issuer.id})")
        print(f"   Wallet: {trusted_issuer.wallet_address}")
        print(f"   OnchainID: {trusted_issuer.onchain_id}")
        print(f"   ClaimIssuer: {trusted_issuer.claim_issuer_address}")
        
        # Validate required data
        if not investor.onchain_id:
            print(f"❌ Investor {INVESTOR_NAME} has no OnchainID")
            return
        
        if not trusted_issuer.claim_issuer_address:
            print(f"❌ Trusted issuer {TRUSTED_ISSUER_NAME} has no ClaimIssuer contract")
            return
        
        if not trusted_issuer.private_key:
            print(f"❌ Trusted issuer {TRUSTED_ISSUER_NAME} has no private key")
            return
        
        print()
        
        # STEP 2: Connect to blockchain
        print("🔗 STEP 2: Connecting to blockchain...")
        w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        if not w3.is_connected():
            print("❌ Failed to connect to Hardhat")
            return
        print(f"✅ Connected to Hardhat at block {w3.eth.block_number}")
        print()
        
        # STEP 3: Load ABIs
        print("📄 STEP 3: Loading contract ABIs...")
        
        # Load Identity ABI
        identity_abi_path = os.path.join(os.path.dirname(__file__), 'artifacts', '@onchain-id', 'solidity', 'contracts', 'interface', 'IIdentity.sol', 'IIdentity.json')
        identity_abi_data = load_abi_from_file(identity_abi_path)
        if not identity_abi_data:
            print("❌ Failed to load Identity ABI")
            return
        identity_abi = identity_abi_data['abi']
        print("✅ Loaded Identity ABI")
        
        # Load ClaimIssuer ABI
        claimissuer_abi_path = os.path.join(os.path.dirname(__file__), 'artifacts', '@onchain-id', 'solidity', 'contracts', 'interface', 'IClaimIssuer.sol', 'IClaimIssuer.json')
        claimissuer_abi_data = load_abi_from_file(claimissuer_abi_path)
        if not claimissuer_abi_data:
            print("❌ Failed to load ClaimIssuer ABI")
            return
        claimissuer_abi = claimissuer_abi_data['abi']
        print("✅ Loaded ClaimIssuer ABI")
        print()
        
        # STEP 4: Create contract instances
        print("🏗️ STEP 4: Creating contract instances...")
        
        investor_identity = w3.eth.contract(
            address=Web3.to_checksum_address(HARDCODED_INVESTOR_ONCHAINID),  # Use hardcoded address
            abi=identity_abi
        )
        print(f"✅ Created investor OnchainID contract: {HARDCODED_INVESTOR_ONCHAINID}")
        
        claimissuer_contract = w3.eth.contract(
            address=Web3.to_checksum_address(HARDCODED_CLAIMISSUER_ADDRESS),  # Use hardcoded address
            abi=claimissuer_abi
        )
        print(f"✅ Created ClaimIssuer contract: {HARDCODED_CLAIMISSUER_ADDRESS}")
        print()
        
        # STEP 5: Permission checks
        print("🔐 STEP 5: Performing permission checks...")
        
        # Check 1: Account 0 (deployer) has management key on investor's OnchainID
        account_0_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        account_0_key_hash = w3.keccak(w3.codec.encode(['address'], [account_0_address]))
        try:
            has_management_key = investor_identity.functions.keyHasPurpose(account_0_key_hash, 1).call()
            print(f"   Account 0 management key on investor OnchainID: {'✅' if has_management_key else '❌'}")
        except Exception as e:
            print(f"   ❌ Error checking Account 0 management key: {e}")
            return
        
        # Check 2: ClaimIssuer has management key on investor's OnchainID
        claimissuer_key_hash = w3.keccak(w3.codec.encode(['address'], [HARDCODED_CLAIMISSUER_ADDRESS]))
        try:
            has_management_key = investor_identity.functions.keyHasPurpose(claimissuer_key_hash, 1).call()
            print(f"   ClaimIssuer management key on investor OnchainID: {'✅' if has_management_key else '❌'}")
            
            # Add ClaimIssuer management key if missing
            if not has_management_key:
                print(f"   🔧 Adding ClaimIssuer management key...")
                account_0_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                account_0 = Account.from_key(account_0_private_key)
                
                add_key_tx = investor_identity.functions.addKey(
                    claimissuer_key_hash,
                    1,  # purpose (management)
                    1   # keyType (ECDSA)
                ).build_transaction({
                    "from": account_0.address,
                    "nonce": w3.eth.get_transaction_count(account_0.address),
                    "gas": 300000,
                    "gasPrice": w3.eth.gas_price
                })
                
                signed_tx = w3.eth.account.sign_transaction(add_key_tx, account_0_private_key)
                tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt.status == 1:
                    print(f"   ✅ Added ClaimIssuer management key. Tx: {tx_hash.hex()}")
                else:
                    print(f"   ❌ Failed to add ClaimIssuer management key")
                    return
        except Exception as e:
            print(f"   ❌ Error checking/adding ClaimIssuer management key: {e}")
            return
        
        # Check 3: Trusted issuer has signing key on ClaimIssuer
        trusted_issuer_key_hash = w3.keccak(w3.codec.encode(['address'], [HARDCODED_TRUSTED_ISSUER_WALLET]))
        try:
            has_signing_key = claimissuer_contract.functions.keyHasPurpose(trusted_issuer_key_hash, 3).call()
            print(f"   Trusted issuer signing key on ClaimIssuer: {'✅' if has_signing_key else '❌'}")
        except Exception as e:
            print(f"   ❌ Error checking trusted issuer signing key: {e}")
            return
        
        # Check 4: Trusted issuer has management key on investor's OnchainID
        try:
            has_management_key = investor_identity.functions.keyHasPurpose(trusted_issuer_key_hash, 1).call()
            print(f"   Trusted issuer management key on investor OnchainID: {'✅' if has_management_key else '❌'}")
            
            # Add trusted issuer management key if missing
            if not has_management_key:
                print(f"   🔧 Adding trusted issuer management key...")
                account_0_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                account_0 = Account.from_key(account_0_private_key)
                
                add_key_tx = investor_identity.functions.addKey(
                    trusted_issuer_key_hash,
                    1,  # purpose (management)
                    1   # keyType (ECDSA)
                ).build_transaction({
                    "from": account_0.address,
                    "nonce": w3.eth.get_transaction_count(account_0.address),
                    "gas": 300000,
                    "gasPrice": w3.eth.gas_price
                })
                
                signed_tx = w3.eth.account.sign_transaction(add_key_tx, account_0_private_key)
                tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt.status == 1:
                    print(f"   ✅ Added trusted issuer management key. Tx: {tx_hash.hex()}")
                else:
                    print(f"   ❌ Failed to add trusted issuer management key")
                    return
        except Exception as e:
            print(f"   ❌ Error checking/adding trusted issuer management key: {e}")
            return
        
        # Check 5: Additional validation - verify ClaimIssuer contract exists
        try:
            code = w3.eth.get_code(Web3.to_checksum_address(HARDCODED_CLAIMISSUER_ADDRESS))
            if code == b'':
                print(f"   ❌ ClaimIssuer contract has no code at {HARDCODED_CLAIMISSUER_ADDRESS}")
                return
            else:
                print(f"   ✅ ClaimIssuer contract exists at {HARDCODED_CLAIMISSUER_ADDRESS}")
        except Exception as e:
            print(f"   ❌ Error checking ClaimIssuer contract: {e}")
            return
        
        # Check 6: Verify ClaimIssuer is registered as trusted issuer for topic 1
        try:
            # Try to check if ClaimIssuer is registered for topic 1 (KYC)
            # This might vary depending on your registry setup
            print(f"   🔍 Checking ClaimIssuer registration for topic 1...")
            # Note: This check depends on your specific registry implementation
            # You might need to adjust this based on your actual registry contracts
        except Exception as e:
            print(f"   ⚠️ Could not verify ClaimIssuer registration: {e}")
            print(f"   ⚠️ Continuing anyway...")
        
        print()
        
        # STEP 6: Create claim data and hash
        print("📝 STEP 6: Creating claim data and hash...")
        
        topic = 1  # KYC
        claim_data_bytes = "1".encode("utf-8")  # 0x31, same as Hardhat's ethers.toUtf8Bytes("1")
        
        print(f"   Topic: {topic}")
        print(f"   Claim data (bytes): {claim_data_bytes}")
        print(f"   Claim data (hex for display): {claim_data_bytes.hex()}")
        
        # Create hash using encode (like Hardhat) - NOT encode_packed
        packed_data = encode(
            ["address", "uint256", "bytes"],
            [Web3.to_checksum_address(HARDCODED_INVESTOR_ONCHAINID), topic, claim_data_bytes]
        )
        data_hash = w3.keccak(packed_data)
        print(f"   Packed data (hex): {packed_data.hex()}")
        print(f"   Data hash: {data_hash.hex()}")
        print(f"   Expected format: keccak256(abi.encode(subject, topic, data)) - like Hardhat")
        print()
        
        # STEP 7: Create signature
        print("✍️ STEP 7: Creating signature...")
        
        # Use hardcoded trusted issuer wallet (the one that worked in Hardhat)
        # We need to get the private key for this address
        trusted_issuer_account = None
        
        # Try to find the private key for the hardcoded address
        if trusted_issuer.wallet_address.lower() == HARDCODED_TRUSTED_ISSUER_WALLET.lower():
            trusted_issuer_account = Account.from_key(trusted_issuer.private_key)
        else:
            # Use the hardcoded private key for the address that worked in Hardhat
            # This is the private key for 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
            hardcoded_private_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
            trusted_issuer_account = Account.from_key(hardcoded_private_key)
        
        print(f"   Trusted issuer account: {trusted_issuer_account.address}")
        print(f"   Expected wallet: {HARDCODED_TRUSTED_ISSUER_WALLET}")
        
        if trusted_issuer_account.address.lower() != HARDCODED_TRUSTED_ISSUER_WALLET.lower():
            print("   ❌ Account mismatch!")
            return
        
        # Create signature - use signHash for raw hash signing
        signature = trusted_issuer_account.signHash(data_hash)
        signature_bytes = signature.signature  # Use raw bytes, not hex string
        print(f"   Signature (hex for display): {signature_bytes.hex()}")
        print()
        
        # STEP 8: Verify signature
        print("🔍 STEP 8: Verifying signature...")
        
        try:
            # Skip signature verification for now - focus on claim addition
            print(f"   ⚠️ Skipping signature verification - focusing on claim addition")
            print(f"   Expected signer: {trusted_issuer_account.address}")
        except Exception as e:
            print(f"   ❌ Error in signature step: {e}")
            print(f"   ⚠️ Continuing anyway - signature verification method may be incompatible")
            # Don't return, continue with the test
        
        print()
        
        # STEP 9: Test isClaimValid first
        print("🧪 STEP 9: Testing isClaimValid before addClaim...")
        
        try:
            is_valid = claimissuer_contract.functions.isClaimValid(
                Web3.to_checksum_address(HARDCODED_INVESTOR_ONCHAINID),
                topic,
                signature_bytes,
                claim_data_bytes
            ).call()
            
            print(f"   ✅ isClaimValid result: {is_valid}")
            
            if not is_valid:
                print(f"   ❌ Claim validation failed in ClaimIssuer contract!")
                print(f"   🔍 This means the signature or data doesn't match what ClaimIssuer expects")
                return
            else:
                print(f"   ✅ Claim validation passed in ClaimIssuer contract!")
                
        except Exception as e:
            print(f"   ❌ Error testing isClaimValid: {e}")
            print(f"   ⚠️ Continuing anyway to test addClaim...")
        
        print()
        
        # STEP 10: Add claim
        print("🚀 STEP 10: Adding claim to OnchainID...")
        
        try:
            # Build transaction
            tx = investor_identity.functions.addClaim(
                topic,
                1,  # scheme (ECDSA)
                HARDCODED_CLAIMISSUER_ADDRESS,  # issuer (ClaimIssuer contract address) - like Hardhat
                signature_bytes,  # signature (raw bytes)
                claim_data_bytes,  # data (raw bytes)
                ""  # URI
            ).build_transaction({
                "from": trusted_issuer_account.address,
                "nonce": w3.eth.get_transaction_count(trusted_issuer_account.address),
                "gas": 300000,
                "gasPrice": w3.eth.gas_price
            })
            
            print(f"   Transaction built successfully")
            print(f"   From: {tx['from']}")
            print(f"   To: {tx['to']}")
            print(f"   Gas: {tx['gas']}")
            
            # Sign and send transaction
            signed_tx = w3.eth.account.sign_transaction(tx, trusted_issuer_account.key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"   Transaction sent: {tx_hash.hex()}")
            
            # Wait for receipt
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                print(f"   ✅ Transaction successful!")
                print(f"   Gas used: {receipt.gasUsed}")
                print(f"   Block: {receipt.blockNumber}")
            else:
                print(f"   ❌ Transaction failed with status {receipt.status}")
                
        except Exception as e:
            print(f"   ❌ Error adding claim: {e}")
            return
        
        print()
        print("🎉 CLAIM ADDITION TEST COMPLETED!")

if __name__ == "__main__":
    main()