#!/usr/bin/env python3
"""
TokenPlatform T-REX Factory Deployment Script
Exact Python version of deploy_factory_enhanced.js
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from web3 import Web3
from eth_account import Account
import time

# Add TokenPlatform to path (scripts folder is one level down)
sys.path.append(str(Path(__file__).parent.parent))

# Import database utilities without importing the full app
from models import db
from utils.contract_utils import store_contract

class TREXDeployment:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
        self.deployer_private_key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        self.account = Account.from_key(self.deployer_private_key)
        self.deployer_address = self.account.address
        
        # Contract ABIs and bytecodes
        self.contract_abis = {}
        self.contract_bytecodes = {}
        self._load_contract_artifacts()
        
    def _load_contract_artifacts(self):
        """Load all contract ABIs and bytecodes from artifacts"""
        artifacts_dir = Path(__file__).parent.parent / 'artifacts'
        
        # Load T-REX contracts
        trex_contracts = [
            'registry/implementation/ClaimTopicsRegistry.sol/ClaimTopicsRegistry.json',
            'registry/implementation/TrustedIssuersRegistry.sol/TrustedIssuersRegistry.json',
            'registry/implementation/IdentityRegistryStorage.sol/IdentityRegistryStorage.json',
            'registry/implementation/IdentityRegistry.sol/IdentityRegistry.json',
            'compliance/modular/ModularCompliance.sol/ModularCompliance.json',
            'token/Token.sol/Token.json',
            'proxy/authority/TREXImplementationAuthority.sol/TREXImplementationAuthority.json',
            'factory/TREXFactory.sol/TREXFactory.json',
            'factory/TREXGateway.sol/TREXGateway.json'
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
        
        # Load OnchainID contracts from npm package (like T-REX does)
        # Get OnchainID package path
        onchainid_path = Path(__file__).parent.parent / 'node_modules' / '@onchain-id' / 'solidity'
        
        try:
            
            # Load Identity contract
            identity_path = onchainid_path / 'artifacts' / 'contracts' / 'Identity.sol' / 'Identity.json'
            if identity_path.exists():
                with open(identity_path, 'r') as f:
                    artifact = json.load(f)
                    self.contract_abis['Identity'] = artifact['abi']
                    self.contract_bytecodes['Identity'] = artifact['bytecode']
                    print(f"✅ Loaded OnchainID Identity")
            
            # Load ImplementationAuthority contract
            impl_auth_path = onchainid_path / 'artifacts' / 'contracts' / 'proxy' / 'ImplementationAuthority.sol' / 'ImplementationAuthority.json'
            if impl_auth_path.exists():
                with open(impl_auth_path, 'r') as f:
                    artifact = json.load(f)
                    self.contract_abis['ImplementationAuthority'] = artifact['abi']
                    self.contract_bytecodes['ImplementationAuthority'] = artifact['bytecode']
                    print(f"✅ Loaded OnchainID ImplementationAuthority")
            
            # Load Factory contract (this is the actual factory, not IdFactory)
            factory_path = onchainid_path / 'artifacts' / 'contracts' / 'factory' / 'IdFactory.sol' / 'IdFactory.json'
            if factory_path.exists():
                with open(factory_path, 'r') as f:
                    artifact = json.load(f)
                    self.contract_abis['Factory'] = artifact['abi']  # Use 'Factory' as the key
                    self.contract_bytecodes['Factory'] = artifact['bytecode']
                    print(f"✅ Loaded OnchainID Factory")
            else:
                print(f"⚠️  OnchainID Factory contract not found: {factory_path}")
                
        except Exception as e:
            print(f"❌ Error loading OnchainID contracts: {e}")
    
    def store_contract_in_database(self, contract_type, contract_address, contract_name, deployer_address, metadata=None):
        """Store contract in TokenPlatform database"""
        try:
            # Create minimal app context for database operations
            from flask import Flask
            
            # Create a minimal Flask app with same config as main app
            temp_app = Flask(__name__)
            temp_app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
            temp_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fundraising.db'
            temp_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
            
            # Initialize database
            db.init_app(temp_app)
            
            with temp_app.app_context():
                # Create tables if they don't exist
                db.create_all()
                
                # Import all models to ensure they're registered
                from models.user import User, TrustedIssuerCapability, TrustedIssuerApproval, UserOnchainID, UserClaim, TokenClaimRequirement
                from models.token import Token, TokenInterest
                from models.contract import Contract
                from models.session import TabSession
                
                # Check if contract already exists
                from models import Contract
                existing_contract = Contract.query.filter_by(contract_address=contract_address).first()
                
                if existing_contract:
                    # Update existing contract
                    existing_contract.contract_type = contract_type
                    existing_contract.contract_name = contract_name
                    existing_contract.deployed_by = deployer_address
                    existing_contract.contract_metadata = json.dumps(metadata) if metadata else None
                    existing_contract.is_active = True
                    db.session.commit()
                    print(f"✅ Updated existing {contract_type} in database")
                else:
                    # Store new contract
                    store_contract(
                        contract_type,
                        contract_address,
                        contract_name,
                        deployer_address,
                        metadata=metadata or {}
                    )
                    print(f"✅ Stored new {contract_type} in database")
        except Exception as e:
            print(f"❌ Error storing {contract_type}: {e}")
            raise
    
    def deploy_contract(self, contract_name, *args, **kwargs):
        """Deploy a contract and return its address"""
        if contract_name not in self.contract_abis:
            raise ValueError(f"Contract {contract_name} not found in artifacts")
        
        contract = self.w3.eth.contract(
            abi=self.contract_abis[contract_name],
            bytecode=self.contract_bytecodes[contract_name]
        )
        
        # Build transaction
        transaction = contract.constructor(*args).build_transaction({
            'from': self.deployer_address,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(self.deployer_address)
        })
        
        # Estimate gas (like ethers does)
        estimated_gas = contract.constructor(*args).estimate_gas({
            'from': self.deployer_address
        })
        transaction['gas'] = int(estimated_gas * 1.2)  # Add 20% buffer like ethers
        
        # Sign and send transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.deployer_private_key)
        # Handle both old and new eth-account versions
        raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
        if not raw_tx:
            raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
        tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
        
        # Wait for transaction receipt
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt.contractAddress
        
        print(f"✅ {contract_name} deployed: {contract_address}")
        return contract_address
    
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
        # Handle both old and new eth-account versions
        raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
        if not raw_tx:
            raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
        tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
        
        # Wait for transaction receipt
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_receipt
    
    async def deploy(self):
        """Main deployment function - exact copy of JavaScript logic"""
        print("🏭 Enhanced TREXFactory Deployment for TokenPlatform")
        print(f"🔗 Connected to Hardhat node at http://localhost:8545")
        print(f"👤 Deployer: {self.deployer_address}")
        
        # Check initial block number
        initial_block = self.w3.eth.block_number
        print(f"📦 Initial block number: {initial_block}")
        
        # Clear existing contracts from database
        try:
            with app.app_context():
                from models import Contract
                Contract.query.delete()
                db.session.commit()
                print("🗑️  Cleared existing contracts from database")
        except Exception as e:
            print(f"⚠️  Warning: Could not clear database: {e}")
        
        try:
            print("\n📋 Step 1: Deploying Implementation Contracts...")
            
            # Deploy all implementation contracts (exact same as JavaScript)
            claim_topics_registry = self.deploy_contract("ClaimTopicsRegistry")
            self.store_contract_in_database("ClaimTopicsRegistry", claim_topics_registry, 
                                          "Claim Topics Registry Implementation", self.deployer_address, 
                                          {"type": "implementation"})
            
            # Initialize ClaimTopicsRegistry
            print("🔧 Initializing ClaimTopicsRegistry...")
            self.send_contract_transaction(claim_topics_registry, 
                                         self.contract_abis["ClaimTopicsRegistry"], 
                                         "init")
            print("✅ ClaimTopicsRegistry initialized")
            
            trusted_issuers_registry = self.deploy_contract("TrustedIssuersRegistry")
            self.store_contract_in_database("TrustedIssuersRegistry", trusted_issuers_registry, 
                                          "Trusted Issuers Registry Implementation", self.deployer_address, 
                                          {"type": "implementation"})
            
            # Initialize TrustedIssuersRegistry
            print("🔧 Initializing TrustedIssuersRegistry...")
            self.send_contract_transaction(trusted_issuers_registry, 
                                         self.contract_abis["TrustedIssuersRegistry"], 
                                         "init")
            print("✅ TrustedIssuersRegistry initialized")
            
            # Add claim topics to ClaimTopicsRegistry
            print("🔧 Adding claim topics to ClaimTopicsRegistry...")
            claim_topics_to_add = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]  # All T-REX standard claim topics
            for topic in claim_topics_to_add:
                try:
                    self.send_contract_transaction(claim_topics_registry, 
                                                 self.contract_abis["ClaimTopicsRegistry"], 
                                                 "addClaimTopic", topic)
                    print(f"✅ Added claim topic {topic}")
                except Exception as e:
                    print(f"⚠️ Could not add claim topic {topic}: {e}")
                    # Continue with other topics
            print("✅ Claim topics added to ClaimTopicsRegistry")
            
            identity_registry_storage = self.deploy_contract("IdentityRegistryStorage")
            self.store_contract_in_database("IdentityRegistryStorage", identity_registry_storage, 
                                          "Identity Registry Storage Implementation", self.deployer_address, 
                                          {"type": "implementation"})
            
            identity_registry = self.deploy_contract("IdentityRegistry")
            self.store_contract_in_database("IdentityRegistry", identity_registry, 
                                          "Identity Registry Implementation", self.deployer_address, 
                                          {"type": "implementation"})
            
            modular_compliance = self.deploy_contract("ModularCompliance")
            self.store_contract_in_database("ModularCompliance", modular_compliance, 
                                          "Modular Compliance Implementation", self.deployer_address, 
                                          {"type": "implementation"})
            
            token_implementation = self.deploy_contract("Token")
            self.store_contract_in_database("Token", token_implementation, 
                                          "Token Implementation", self.deployer_address, 
                                          {"type": "implementation"})
            
            print("\n📋 Step 2: Deploying Identity Implementation...")
            
            # Deploy Identity Implementation (exact same as JavaScript)
            identity_implementation = self.deploy_contract("Identity", self.deployer_address, True)
            self.store_contract_in_database("Identity", identity_implementation, 
                                          "Identity Implementation", self.deployer_address, 
                                          {"type": "implementation"})
            
            print("\n📋 Step 3: Deploying Identity Implementation Authority...")
            
            # Deploy Identity Implementation Authority (exact same as JavaScript)
            identity_implementation_authority = self.deploy_contract("ImplementationAuthority", identity_implementation)
            self.store_contract_in_database("IdentityImplementationAuthority", identity_implementation_authority, 
                                          "Identity Implementation Authority", self.deployer_address, 
                                          {"type": "authority"})
            
            print("\n📋 Step 4: Deploying Identity Factory...")
            
            # Deploy Identity Factory (exact same as JavaScript)
            # Use OnchainID Factory contract, not IdFactory
            identity_factory = self.deploy_contract("Factory", identity_implementation_authority)
            self.store_contract_in_database("IdentityFactory", identity_factory, 
                                          "Identity Factory", self.deployer_address, 
                                          {"type": "factory"})
            
            print("\n📋 Step 5: Deploying TREX Implementation Authority...")
            
            # Deploy TREX Implementation Authority (exact same as JavaScript)
            trex_implementation_authority = self.deploy_contract("TREXImplementationAuthority", True, 
                                                               "0x" + "0" * 40, "0x" + "0" * 40)
            self.store_contract_in_database("TREXImplementationAuthority", trex_implementation_authority, 
                                          "TREX Implementation Authority", self.deployer_address, 
                                          {"type": "authority"})
            
            print("\n📋 Step 6: Adding TREX Version...")
            
            # Add TREX Version (exact same as JavaScript)
            version_struct = {
                'major': 4,
                'minor': 0,
                'patch': 0
            }
            
            contracts_struct = {
                'tokenImplementation': token_implementation,
                'ctrImplementation': claim_topics_registry,
                'irImplementation': identity_registry,
                'irsImplementation': identity_registry_storage,
                'tirImplementation': trusted_issuers_registry,
                'mcImplementation': modular_compliance
            }
            
            # Call addAndUseTREXVersion function
            self.send_contract_transaction(trex_implementation_authority, 
                                         self.contract_abis["TREXImplementationAuthority"], 
                                         "addAndUseTREXVersion", version_struct, contracts_struct)
            print("✅ Added TREX version to Implementation Authority")
            
            print("\n📋 Step 7: Deploying TREXFactory...")
            
            # Deploy TREXFactory (exact same as JavaScript)
            trex_factory = self.deploy_contract("TREXFactory", trex_implementation_authority, identity_factory)
            
            # TREXFactory inherits from Ownable, so deployer automatically becomes owner
            print("✅ TREXFactory deployed with deployer as owner")
            
            self.store_contract_in_database("TREXFactory", trex_factory, 
                                          "TREX Factory", self.deployer_address, 
                                          {"type": "factory", "owner": self.deployer_address, 
                                           "implementationAuthority": trex_implementation_authority, 
                                           "identityFactory": identity_factory})
            
            print("\n📋 Step 8: Configuring Identity Factory...")
            
            # Add TREXFactory to Identity Factory (exact same as JavaScript)
            self.send_contract_transaction(identity_factory, 
                                         self.contract_abis["Factory"], 
                                         "addTokenFactory", trex_factory)
            print("✅ Added TREXFactory to Identity Factory")
            
            print("\n📋 Step 9: Deploying TREXGateway...")
            
            # Deploy TREXGateway (exact same as JavaScript)
            trex_gateway = self.deploy_contract("TREXGateway", trex_factory, True)
            self.store_contract_in_database("TREXGateway", trex_gateway, 
                                          "TREX Gateway", self.deployer_address, 
                                          {"type": "gateway", "owner": self.deployer_address, 
                                           "factory": trex_factory})
            
            print("\n📋 Step 10: Configuring TREXGateway...")
            
            # Check if deployment fees are enabled and disable them (exact same as JavaScript)
            fees_enabled = self.call_contract_function(trex_gateway, 
                                                      self.contract_abis["TREXGateway"], 
                                                      "isDeploymentFeeEnabled")
            if fees_enabled:
                self.send_contract_transaction(trex_gateway, 
                                             self.contract_abis["TREXGateway"], 
                                             "enableDeploymentFee", False)
                print("✅ Deployment fee collection disabled")
            else:
                print("✅ Deployment fees already disabled")
            
            # Add deployer to approved list (exact same as JavaScript)
            self.send_contract_transaction(trex_gateway, 
                                         self.contract_abis["TREXGateway"], 
                                         "addDeployer", self.deployer_address)
            print("✅ Added deployer to approved list")
            
            print("\n📋 Step 11: Setting Back-References...")
            
            # Set back-references (exact same as JavaScript)
            self.send_contract_transaction(trex_implementation_authority, 
                                         self.contract_abis["TREXImplementationAuthority"], 
                                         "setTREXFactory", trex_factory)
            print("✅ Set TREXFactory back-reference in Implementation Authority")
            
            self.send_contract_transaction(trex_implementation_authority, 
                                         self.contract_abis["TREXImplementationAuthority"], 
                                         "setIAFactory", identity_factory)
            print("✅ Set IAFactory back-reference in Implementation Authority")
            
            print("\n📋 Step 12: Verifying Setup...")
            
            # Verify setup (exact same as JavaScript)
            impl_auth_from_factory = self.call_contract_function(trex_factory, 
                                                                self.contract_abis["TREXFactory"], 
                                                                "getImplementationAuthority")
            id_factory_from_factory = self.call_contract_function(trex_factory, 
                                                                 self.contract_abis["TREXFactory"], 
                                                                 "getIdFactory")
            owner = self.call_contract_function(trex_factory, 
                                               self.contract_abis["TREXFactory"], 
                                               "owner")
            
            print(f"✅ TREXFactory Owner: {owner}")
            print(f"✅ TREXFactory Implementation Authority: {impl_auth_from_factory}")
            print(f"✅ TREXFactory ID Factory: {id_factory_from_factory}")
            
            # Verify TREXGateway configuration
            factory_from_gateway = self.call_contract_function(trex_gateway, 
                                                              self.contract_abis["TREXGateway"], 
                                                              "getFactory")
            public_deployment_status = self.call_contract_function(trex_gateway, 
                                                                  self.contract_abis["TREXGateway"], 
                                                                  "getPublicDeploymentStatus")
            is_deployer = self.call_contract_function(trex_gateway, 
                                                     self.contract_abis["TREXGateway"], 
                                                     "isDeployer", self.deployer_address)
            deployment_fee = self.call_contract_function(trex_gateway, 
                                                        self.contract_abis["TREXGateway"], 
                                                        "getDeploymentFee")
            is_fee_enabled = self.call_contract_function(trex_gateway, 
                                                        self.contract_abis["TREXGateway"], 
                                                        "isDeploymentFeeEnabled")
            
            print(f"✅ TREXGateway Factory: {factory_from_gateway}")
            print(f"✅ TREXGateway Public Deployment: {'Enabled' if public_deployment_status else 'Disabled'}")
            print(f"✅ TREXGateway Deployer Approved: {'Yes' if is_deployer else 'No'}")
            print(f"✅ TREXGateway Fee Enabled: {'Yes' if is_fee_enabled else 'No'}")
            print(f"✅ TREXGateway Fee Structure: {deployment_fee}")
            
            # Verify all addresses match (exact same as JavaScript)
            if impl_auth_from_factory != trex_implementation_authority:
                raise ValueError("Implementation Authority mismatch")
            
            if id_factory_from_factory != identity_factory:
                raise ValueError("ID Factory mismatch")
            
            if owner != self.deployer_address:
                raise ValueError("Owner mismatch")
            
            if factory_from_gateway != trex_factory:
                raise ValueError("TREXGateway factory address mismatch")
            
            if not is_deployer:
                raise ValueError("TREXGateway deployer not approved")
            
            # Check final block number
            final_block = self.w3.eth.block_number
            print(f"\n📦 Final block number: {final_block}")
            print(f"📦 Blocks created: {final_block - initial_block}")
            
            print("\n🎉 TREXFactory and TREXGateway deployed successfully!")
            print("\n📋 Contract Addresses:")
            print(f"📋 Factory Address: {trex_factory}")
            print(f"📋 Gateway Address: {trex_gateway}")
            print(f"📋 Identity Factory: {identity_factory}")
            print("📋 All addresses stored in TokenPlatform database")
            
        except Exception as e:
            print(f"❌ Deployment failed: {e}")
            import traceback
            traceback.print_exc()
            raise

def main():
    """Main function"""
    deployment = TREXDeployment()
    asyncio.run(deployment.deploy())

if __name__ == "__main__":
    main() 