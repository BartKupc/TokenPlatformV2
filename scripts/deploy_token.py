 #!/usr/bin/env python3
"""
TokenPlatform Token Suite Deployment Script
Exact Python version of deploy_token_enhanced.js
"""

import json
import os
import sys
import time
from pathlib import Path
from web3 import Web3
from eth_account import Account

# Add TokenPlatform to path (scripts folder is one level down)
sys.path.append(str(Path(__file__).parent.parent))

from app import app
from models import db, Contract
from models.token import Token

class TokenDeployment:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
        self.deployer_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        self.account = Account.from_key(self.deployer_private_key)
        self.deployer_address = self.account.address
        
        # Contract ABIs and bytecodes
        self.contract_abis = {}
        self.contract_bytecodes = {}
        self._load_contract_artifacts()
        
        # Token details (same as JavaScript)
        self.token_details = {
            'owner': None,
            'name': "MySecurityToken",
            'symbol': "MST",
            'decimals': 18,
            'irs': None,
            'ONCHAINID': None,
            'irAgents': [],
            'tokenAgents': [],
            'complianceModules': [],
            'complianceSettings': [],
            'totalSupply': "1000000"
        }
        
        # Claim details
        self.claim_details = {
            'claimTopics': [],
            'issuers': [],
            'issuerClaims': []
        }
        
    def _load_contract_artifacts(self):
        """Load contract ABIs and bytecodes from artifacts"""
        artifacts_dir = Path(__file__).parent.parent / 'artifacts'
        
        # Load T-REX contracts
        trex_contracts = [
            'factory/TREXFactory.sol/TREXFactory.json',
            'token/Token.sol/Token.json',
            'registry/implementation/IdentityRegistry.sol/IdentityRegistry.json'
        ]
        
        for contract_file in trex_contracts:
            file_path = artifacts_dir / 'contracts' / contract_file
            if file_path.exists():
                with open(file_path, 'r') as f:
                    artifact = json.load(f)
                    contract_name = Path(contract_file).stem
                    self.contract_abis[contract_name] = artifact['abi']
                    self.contract_bytecodes[contract_name] = artifact['bytecode']
                    print(f"✅ Loaded {contract_name}")
            else:
                print(f"⚠️  Contract artifact not found: {contract_file}")
    
    def get_trex_factory_address(self):
        """Get TREXFactory address from database - there's only one factory in TokenPlatform"""
        try:
            with app.app_context():
                factory_contract = Contract.query.filter_by(contract_type="TREXFactory").first()
                if factory_contract:
                    print(f"✅ Found TREXFactory: {factory_contract.contract_address}")
                    return factory_contract.contract_address
                else:
                    raise ValueError("TREXFactory not found in database. Please run deploy_factory.py first.")
        except Exception as e:
            print(f"❌ Error getting TREXFactory address: {e}")
            raise
    
    def call_contract_function(self, contract_address, abi, function_name, *args):
        """Call a contract function"""
        contract = self.w3.eth.contract(address=contract_address, abi=abi)
        function = getattr(contract.functions, function_name)
        return function(*args).call()
    
    def send_contract_transaction(self, contract_address, abi, function_name, *args):
        """Send a transaction to a contract function"""
        contract = self.w3.eth.contract(address=contract_address, abi=abi)
        function = getattr(contract.functions, function_name)
        
        # Build transaction
        transaction = function(*args).build_transaction({
            'from': self.deployer_address,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(self.deployer_address)
        })
        
        # Estimate gas (like ethers does)
        estimated_gas = function(*args).estimate_gas({
            'from': self.deployer_address
        })
        transaction['gas'] = int(estimated_gas * 1.2)  # Add 20% buffer like ethers
        
        # Sign and send transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.deployer_private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        # Wait for transaction receipt
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_receipt
    
    def store_token_in_database(self, token_address, token_name, token_symbol, token_decimals, 
                               identity_registry, compliance, claim_topics_registry, 
                               trusted_issuers_registry, deployer_address, salt):
        """Store token suite in TokenPlatform database"""
        try:
            with app.app_context():
                # Store the token using existing Token model structure
                # Use the issuer address, not the deployer address
                issuer_address = self.token_details.get('tokenAgents', [deployer_address])[0]
                token = Token(
                    token_address=token_address,
                    name=token_name,
                    symbol=token_symbol,
                    total_supply=int(self.token_details['totalSupply']),
                    issuer_address=issuer_address,
                    price_per_token=0.0,
                    description=f"ERC-3643 Token deployed via TREXFactory with salt: {salt}",
                    ir_agent='issuer',
                    token_agent='issuer',
                    claim_topics=json.dumps(self.claim_details['claimTopics']),
                    claim_issuer_type='trusted_issuer'
                )
                db.session.add(token)
                db.session.commit()
                print(f"✅ Stored token {token_name} in database")
                print(f"   Token Address: {token_address}")
                print(f"   Identity Registry: {identity_registry}")
                print(f"   Compliance: {compliance}")
                print(f"   Claim Topics Registry: {claim_topics_registry}")
                print(f"   Trusted Issuers Registry: {trusted_issuers_registry}")
        except Exception as e:
            print(f"❌ Error storing token: {e}")
            raise
    
    def deploy(self, deployer_address=None):
        """Main deployment function - exact copy of JavaScript logic"""
        if deployer_address:
            self.deployer_address = deployer_address
            self.account = Account.from_key(self.deployer_private_key)
        
        # Use the issuer address passed as parameter
        if deployer_address:
            print(f"🔍 Using issuer address: {deployer_address}")
            # For now, we'll use the hardcoded private key but set the deployer address
            # In production, you'd need to pass the issuer's private key securely
            self.deployer_address = deployer_address
        
        print("🎯 Enhanced Token Deployment for TokenPlatform")
        print(f"🔗 Connected to Hardhat node at http://127.0.0.1:8545")
        print(f"👤 Deployer: {self.deployer_address}")
        
        # Check initial block number
        initial_block = self.w3.eth.block_number
        print(f"📦 Initial block number: {initial_block}")
        
        try:
            # Get TREXFactory address from database
            trex_factory_address = self.get_trex_factory_address()
            print(f"\n📋 Using TREXFactory: {trex_factory_address}")
            
            # Get the TREXFactory contract instance
            trex_factory = self.w3.eth.contract(
                address=trex_factory_address,
                abi=self.contract_abis["TREXFactory"]
            )
            print("✅ Connected to TREXFactory")
            
            # Verify factory configuration (exact same as JavaScript)
            print("\n📋 Factory Configuration:")
            implementation_authority = self.call_contract_function(
                trex_factory_address, 
                self.contract_abis["TREXFactory"], 
                "getImplementationAuthority"
            )
            id_factory = self.call_contract_function(
                trex_factory_address, 
                self.contract_abis["TREXFactory"], 
                "getIdFactory"
            )
            owner = self.call_contract_function(
                trex_factory_address, 
                self.contract_abis["TREXFactory"], 
                "owner"
            )
            
            print(f"Owner: {owner}")
            print(f"Implementation Authority: {implementation_authority}")
            print(f"ID Factory: {id_factory}")
            
            # Check if we need to use the factory owner's private key
            if owner.lower() != self.deployer_address.lower():
                print(f"⚠️ Factory owner ({owner}) is different from deployer ({self.deployer_address})")
                print("🔧 Using factory owner's private key for deployment")
                # Use the factory owner's private key (hardcoded Hardhat account 0)
                self.deployer_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
                self.account = Account.from_key(self.deployer_private_key)
                self.deployer_address = self.account.address
                print(f"✅ Switched to factory owner: {self.deployer_address}")
            
            # Use claim details from instance (set by TREXService)
            claim_details = self.claim_details
            print('📋 Using claim details from instance:', claim_details)
            print('📋 Claim topics:', claim_details['claimTopics'])
            print('📋 Issuers:', claim_details['issuers'])
            print('📋 Issuer claims:', claim_details['issuerClaims'])
            
            # Token details are already set by TREXService
            print('📋 Using token details from instance:', self.token_details)
            
            salt = "token-" + str(int(time.time()))
            
            print("\n📋 Token Details:")
            print(f"Token Name: {self.token_details['name']}")
            print(f"Token Symbol: {self.token_details['symbol']}")
            print(f"Token Decimals: {self.token_details['decimals']}")
            print(f"Salt: {salt}")
            
            print("\n🚀 Deploying token suite...")
            
            # Set token details (exact same as JavaScript)
            # Use the issuer address as owner and agents, not the deployer address
            issuer_address = self.token_details.get('tokenAgents', [self.deployer_address])[0]
            self.token_details['owner'] = issuer_address
            self.token_details['irs'] = "0x" + "0" * 40  # ethers.ZeroAddress
            self.token_details['ONCHAINID'] = "0x" + "0" * 40  # ethers.ZeroAddress
            
            # Use the agents from config (issuer address) instead of overriding with deployer
            # The config should already have the correct issuer address as agent
            if not self.token_details['tokenAgents']:
                self.token_details['tokenAgents'] = [self.deployer_address]
            if not self.token_details['irAgents']:
                self.token_details['irAgents'] = [self.deployer_address]
            
            print("🔑 Auto-configured agents:")
            print(f"Token Agents: {self.token_details['tokenAgents']}")
            print(f"IR Agents: {self.token_details['irAgents']}")
            
            # Deploy token suite (exact same as JavaScript)
            tx_receipt = self.send_contract_transaction(
                trex_factory_address,
                self.contract_abis["TREXFactory"],
                "deployTREXSuite",
                salt,
                self.token_details,
                claim_details
            )
            
            print(f"Transaction hash: {tx_receipt.transactionHash.hex()}")
            print("✅ Token suite deployed!")
            print(f"Gas used: {tx_receipt.gasUsed}")
            
            # Get deployed addresses (exact same as JavaScript)
            token_address = self.call_contract_function(
                trex_factory_address,
                self.contract_abis["TREXFactory"],
                "getToken",
                salt
            )
            
            print(f"\n📦 Token Suite Components:")
            print(f"Token Address: {token_address}")
            
            if token_address == "0x" + "0" * 40:
                print("⚠️  Token address is zero - deployment may have failed")
                return
            
            # Get the token contract instance
            token_contract = self.w3.eth.contract(
                address=token_address,
                abi=self.contract_abis["Token"]
            )
            
            # Get other contracts in the suite (exact same as JavaScript)
            identity_registry = self.call_contract_function(
                token_address,
                self.contract_abis["Token"],
                "identityRegistry"
            )
            compliance = self.call_contract_function(
                token_address,
                self.contract_abis["Token"],
                "compliance"
            )
            
            # Get the Identity Registry contract to access CTR and TIR
            identity_registry_contract = self.w3.eth.contract(
                address=identity_registry,
                abi=self.contract_abis["IdentityRegistry"]
            )
            claim_topics_registry = self.call_contract_function(
                identity_registry,
                self.contract_abis["IdentityRegistry"],
                "topicsRegistry"
            )
            trusted_issuers_registry = self.call_contract_function(
                identity_registry,
                self.contract_abis["IdentityRegistry"],
                "issuersRegistry"
            )
            
            print(f"Identity Registry: {identity_registry}")
            print(f"Compliance: {compliance}")
            print(f"Claim Topics Registry: {claim_topics_registry}")
            print(f"Trusted Issuers Registry: {trusted_issuers_registry}")
            
            # Verify token details (exact same as JavaScript)
            token_name = self.call_contract_function(
                token_address,
                self.contract_abis["Token"],
                "name"
            )
            token_symbol = self.call_contract_function(
                token_address,
                self.contract_abis["Token"],
                "symbol"
            )
            token_decimals = self.call_contract_function(
                token_address,
                self.contract_abis["Token"],
                "decimals"
            )
            
            print(f"\n📋 Verified Token Details:")
            print(f"Name: {token_name}")
            print(f"Symbol: {token_symbol}")
            print(f"Decimals: {token_decimals}")
            
            # Store token suite in database
            # Commented out - the route will handle database storage
            # self.store_token_in_database(
            #     token_address, token_name, token_symbol, token_decimals,
            #     identity_registry, compliance, claim_topics_registry,
            #     trusted_issuers_registry, self.deployer_address, salt
            # )
            
            # Check final block number
            final_block = self.w3.eth.block_number
            print(f"\n📦 Final block number: {final_block}")
            print(f"📦 Blocks created: {final_block - initial_block}")
            
            print("\n🎉 ERC-3643 Token Suite deployed successfully!")
            print(f"\n📋 Token Address: {token_address}")
            print(f"📋 Salt: {salt}")
            print("📋 Token address will be stored by the route")
            
            print("\n🚀 Next steps:")
            print("1. Configure compliance rules in the ModularCompliance contract")
            print("2. Add trusted issuers to the TrustedIssuersRegistry")
            print("3. Set up claim topics in the ClaimTopicsRegistry")
            print("4. Mint tokens using token.mint()")
            print("5. Check the dashboard for deployment details")
            
            # Return all contract addresses for the route to use
            return {
                'token_address': token_address,
                'identity_registry': identity_registry,
                'compliance': compliance,
                'claim_topics_registry': claim_topics_registry,
                'trusted_issuers_registry': trusted_issuers_registry
            }
            
        except Exception as e:
            print(f"❌ Token deployment failed: {e}")
            import traceback
            traceback.print_exc()
            raise

def main():
    """Main function for standalone testing"""
    deployment = TokenDeployment()
    deployment.deploy()

if __name__ == "__main__":
    main()