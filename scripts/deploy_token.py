#!/usr/bin/env python3
"""
Token Deployment Script for TokenPlatform V2
Uses TREXGateway for deployment and stores results in database
"""

import json
import sys
import os
from web3 import Web3
from eth_account import Account
import time

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Note: Database operations are handled by the Flask route
# This script only handles blockchain deployment and returns results

class TokenDeployment:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
        
        # Load contract ABIs
        self.contract_abis = {}
        self.load_contract_abis()
        
        # Deployer details (will be set during deployment)
        self.deployer_address = None
        self.deployer_private_key = None
        
        # Token details (same as V1)
        self.token_details = {
            'owner': None,
            'name': 'DefaultToken',
            'symbol': 'DTK',
            'decimals': 18,
            'irs': None,
            'ONCHAINID': None,
            'irAgents': [],
            'tokenAgents': [],
            'complianceModules': [],
            'complianceSettings': [],
            'totalSupply': '1000000'
        }
        
        self.claim_details = {
            'claimTopics': [],
            'issuers': [],
            'issuerClaims': []
        }
        
    def load_contract_abis(self):
        """Load all required contract ABIs"""
        abi_files = {
            "TREXGateway": "artifacts/trex/TREXGateway.json",
            "TREXFactory": "artifacts/trex/TREXFactory.json",
            "Token": "artifacts/trex/Token.json",
            "IdentityRegistry": "artifacts/trex/IdentityRegistry.json",
            "ModularCompliance": "artifacts/trex/ModularCompliance.json"
        }
        
        for name, path in abi_files.items():
            try:
                with open(path, 'r') as f:
                    abi_data = json.load(f)
                    self.contract_abis[name] = abi_data.get('abi', [])
                    print(f"✅ Loaded {name} ABI")
            except Exception as e:
                print(f"❌ Failed to load {name} ABI: {e}")
                sys.exit(1)
    
    def call_contract_function(self, contract_address, abi, function_name, *args):
        """Call a contract function (read-only)"""
        try:
            contract = self.w3.eth.contract(address=contract_address, abi=abi)
            function = getattr(contract.functions, function_name)
            result = function(*args).call()
            return result
        except Exception as e:
            print(f"❌ Error calling {function_name}: {e}")
            raise
    
    def send_contract_transaction(self, contract_address, abi, function_name, *args):
        """Send a contract transaction (write operation)"""
        try:
            print(f"🔍 DEBUG: send_contract_transaction called with:")
            print(f"   contract_address: {contract_address}")
            print(f"   function_name: {function_name}")
            print(f"   deployer_address: {self.deployer_address}")
            
            contract = self.w3.eth.contract(address=contract_address, abi=abi)
            function = getattr(contract.functions, function_name)
            
            # Build transaction
            tx = function(*args).build_transaction({
                'from': self.deployer_address,
                'gas': 5000000,  # High gas limit for deployment
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.deployer_address)
            })
            
            print(f"🔍 DEBUG: Transaction built:")
            print(f"   to: {tx.get('to')}")
            print(f"   from: {tx.get('from')}")
            print(f"   data: {tx.get('data')[:66]}...")
            
            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.deployer_private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"📝 Transaction sent: {tx_hash.hex()}")
            
            # Wait for confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if tx_receipt.status == 1:
                print(f"✅ Transaction confirmed in block {tx_receipt.blockNumber}")
                return tx_receipt
            else:
                raise Exception("Transaction failed")
                
        except Exception as e:
            print(f"❌ Error sending transaction {function_name}: {e}")
            raise
    
    def parse_deployment_event(self, logs):
        """Parse TREXSuiteDeployed event from TREXFactory to get deployed contract addresses"""
        try:
            # TREXSuiteDeployed event signature from TREXFactory
            # Event: TREXSuiteDeployed(address indexed _token, address _ir, address _irs, address _tir, address _ctr, address _mc, string indexed _salt)
            # Topic: 0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41
            
            deployment_event_topic = "0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41"
            
            print(f"🔍 DEBUG: Parsing {len(logs)} transaction logs for TREXFactory event...")
            for i, log in enumerate(logs):
                print(f"   Log {i}: topics={[t.hex() for t in log.topics]}, data_length={len(log.data)}")
                if log.topics and len(log.topics) > 0:
                    if log.topics[0].hex() == deployment_event_topic:
                        print(f"✅ Found TREXSuiteDeployed event from Factory!")
                        print(f"   Event data: {log.data.hex()}")
                        print(f"   Data length: {len(log.data)} bytes")
                        
                        # Parse the Factory event data correctly
                        # Factory event contains: [_ir, _irs, _tir, _ctr, _mc] (5 non-indexed addresses)
                        # _token and _salt are indexed (in topics), not in data
                        if len(log.data) >= 160:  # 5 addresses * 32 bytes each
                            print(f"   📊 Parsing Factory event data:")
                            print(f"     Topics: {[t.hex() for t in log.topics]}")
                            print(f"     Data: {log.data.hex()}")
                            
                            # Extract addresses from data (non-indexed fields)
                            ir_address = "0x" + log.data[0:32].hex()[-40:]
                            irs_address = "0x" + log.data[32:64].hex()[-40:]
                            tir_address = "0x" + log.data[64:96].hex()[-40:]
                            ctr_address = "0x" + log.data[96:128].hex()[-40:]
                            mc_address = "0x" + log.data[128:160].hex()[-40:]
                            
                            # Extract indexed fields from topics
                            # Topic 0: event signature (indexed)
                            # Topic 1: _token (indexed) 
                            # Topic 2: _salt (indexed)
                            token_address = "0x" + log.topics[1].hex()[-40:] if len(log.topics) > 1 else "0x0000000000000000000000000000000000000000"
                            salt = log.topics[2].hex() if len(log.topics) > 2 else "0x0000000000000000000000000000000000000000000000000000000000000000"
                            
                            print(f"     📍 Extracted addresses:")
                            print(f"       Token (from topic): {token_address}")
                            print(f"       IR (from data): {ir_address}")
                            print(f"       IRS (from data): {irs_address}")
                            print(f"       TIR (from data): {tir_address}")
                            print(f"       CTR (from data): {ctr_address}")
                            print(f"       MC (from data): {mc_address}")
                            print(f"       Salt (from topic): {salt}")
                            
                            deployed_addresses = {
                                'token': token_address,
                                'identity_registry': ir_address,
                                'identity_registry_storage': irs_address,
                                'trusted_issuers_registry': tir_address,
                                'claim_topics_registry': ctr_address,
                                'compliance': mc_address,
                                'salt': salt
                            }
                            
                            print(f"📋 Parsed Factory deployment addresses:")
                            print(f"  Token: {token_address}")
                            print(f"  Identity Registry: {ir_address}")
                            print(f"  Identity Registry Storage: {irs_address}")
                            print(f"  Trusted Issuers Registry: {tir_address}")
                            print(f"  Claim Topics Registry: {ctr_address}")
                            print(f"  Compliance: {mc_address}")
                            print(f"  Salt: {salt}")
                            
                            return deployed_addresses
                        else:
                            print(f"❌ Event data too short: {len(log.data)} bytes (expected 160)")
                            print(f"   Raw data: {log.data.hex()}")
            
            print("⚠️ TREXSuiteDeployed event from Factory not found in logs")
            return None
            
        except Exception as e:
            print(f"❌ Error parsing Factory deployment event: {e}")
            return None
    
    def store_token_in_database(self, deployed_addresses, token_name, token_symbol, total_supply, issuer_address):
        """Store token suite in database for dashboard display"""
        # Note: Database storage is now handled by the Flask route
        # This method is kept for compatibility but doesn't actually store
        print(f"💾 Database storage will be handled by Flask route")
        print(f"   Token: {token_name} ({token_symbol})")
        print(f"   Address: {deployed_addresses['token']}")
        return None
    
    def deploy(self, deployer_address=None):
        """Main deployment function using TREXGateway V2"""
        try:
            print("🚀 Starting ERC-3643 Token Deployment via TREXGateway V2")
            print("=" * 60)
            
            # Set deployer details from issuer
            if deployer_address:
                self.deployer_address = deployer_address
                print(f"👤 Using issuer as deployer: {self.deployer_address}")
                
                # Get issuer's private key from database
                try:
                    from models import User
                    issuer = User.query.filter_by(wallet_address=deployer_address).first()
                    if issuer and issuer.private_key:
                        self.deployer_private_key = issuer.private_key
                        print(f"🔑 Using issuer's private key for deployment")
                    else:
                        raise Exception("Issuer not found or no private key")
                except Exception as e:
                    print(f"❌ Error getting issuer private key: {e}")
                    return {
                        'success': False,
                        'error': f'Could not get issuer private key: {e}',
                        'note': 'Issuer must be registered with private key'
                    }
            else:
                raise Exception("Deployer address is required")
            
            # Get initial block number
            initial_block = self.w3.eth.block_number
            print(f"📦 Initial block number: {initial_block}")
            
            # Get contract addresses from database
            try:
                from models import Contract
                gateway_contract = Contract.query.filter_by(contract_type='TREXGateway').first()
                gateway_address = gateway_contract.contract_address if gateway_contract else None
                
                factory_contract = Contract.query.filter_by(contract_type='TREXFactory').first()
                trex_factory_address = factory_contract.contract_address if factory_contract else None
                
                if not gateway_address or not trex_factory_address:
                    raise ValueError("Gateway or Factory not found in database")
                    
                print(f"🏛️ Using contract addresses from database:")
                print(f"   Gateway: {gateway_address}")
                print(f"   Factory: {trex_factory_address}")
                
                print(f"🏛️ Gateway Address: {gateway_address}")
                print(f"🏭 Factory Address: {trex_factory_address}")
                    
            except Exception as e:
                print(f"❌ Error getting contract addresses from database: {e}")
                return {
                    'success': False,
                    'error': f'Could not get contract addresses: {e}',
                    'note': 'Check if contracts are deployed and in database'
                }
            
            # Check Gateway roles for deployer
            print(f"\n🔍 Checking Gateway roles for {self.deployer_address}...")
            try:
                gateway_contract = self.w3.eth.contract(
                    address=gateway_address,
                    abi=self.contract_abis["TREXGateway"]
                )
                
                is_deployer = gateway_contract.functions.isDeployer(self.deployer_address).call()
                is_agent = gateway_contract.functions.isAgent(self.deployer_address).call()
                gateway_owner = gateway_contract.functions.owner().call()
                
                print(f"   Is Deployer: {is_deployer}")
                print(f"   Is Agent: {is_agent}")
                print(f"   Gateway Owner: {gateway_owner}")
                
                if not is_deployer and not is_agent:
                    print("❌ Deployer has no Gateway permissions!")
                    return {
                        'success': False,
                        'error': 'Deployer has no Gateway permissions',
                        'note': 'Contact admin to add deployer role'
                    }
                    
            except Exception as e:
                print(f"⚠️ Could not check Gateway roles: {e}")
            
            # Set token details (exact same as V1)
            # Use the deployer address as owner and agents (this is the issuer)
            issuer_address = self.deployer_address
            self.token_details['owner'] = issuer_address
            self.token_details['irs'] = "0x" + "0" * 40  # ethers.ZeroAddress
            self.token_details['ONCHAINID'] = "0x" + "0" * 40  # ethers.ZeroAddress
            
            # Set the agents to the issuer address
            self.token_details['tokenAgents'] = [issuer_address]
            self.token_details['irAgents'] = [issuer_address]
            
            print("🔑 Auto-configured agents:")
            print(f"Token Agents: {self.token_details['tokenAgents']}")
            print(f"IR Agents: {self.token_details['irAgents']}")
            
            # Deploy through Gateway (but use V1 TokenDetails structure)
            tx_receipt = self.send_contract_transaction(
                gateway_address,
                self.contract_abis["TREXGateway"],
                "deployTREXSuite",
                self.token_details,
                self.claim_details
            )
            
            print(f"✅ Gateway deployment transaction successful!")
            print(f"📝 Transaction Hash: {tx_receipt.transactionHash.hex()}")
            print(f"📊 Transaction Status: {tx_receipt.status}")
            print(f"📊 Transaction Logs: {len(tx_receipt.logs)} logs")
            
            # Debug: Show what logs the Gateway transaction produced
            if tx_receipt.logs:
                print(f"🔍 Gateway transaction logs:")
                for i, log in enumerate(tx_receipt.logs):
                    print(f"   Log {i}: topics={[t.hex() for t in log.topics]}, data_length={len(log.data)}")
                    if log.topics and len(log.topics) > 0:
                        print(f"     Topic 0: {log.topics[0].hex()}")
            
            # Parse deployment event to get contract addresses
            print(f"\n🔍 Parsing deployment event for contract addresses...")
            
            # The Gateway calls the Factory, so we need to look for the Factory's TREXSuiteDeployed event
            # Get the Factory address from the database
            try:
                from models import Contract
                factory_contract = Contract.query.filter_by(contract_type='TREXFactory').first()
                if not factory_contract:
                    raise Exception("TREXFactory not found in database")
                
                factory_address = factory_contract.contract_address
                print(f"🔍 Looking for Factory event at: {factory_address}")
                
                # Verify that the Gateway owns the Factory
                try:
                    factory_contract_instance = self.w3.eth.contract(
                        address=factory_address, 
                        abi=self.contract_abis["TREXFactory"]
                    )
                    factory_owner = factory_contract_instance.functions.owner().call()
                    print(f"🔍 Factory owner: {factory_owner}")
                    print(f"🔍 Gateway address: {gateway_address}")
                    if factory_owner.lower() != gateway_address.lower():
                        print(f"⚠️ WARNING: Factory is NOT owned by Gateway!")
                        print(f"   Factory owner: {factory_owner}")
                        print(f"   Gateway: {gateway_address}")
                    else:
                        print(f"✅ Factory is correctly owned by Gateway")
                except Exception as e:
                    print(f"⚠️ Could not verify Factory ownership: {e}")
                
                # Look for the Factory's TREXSuiteDeployed event in recent blocks
                latest_block = self.w3.eth.block_number
                deployment_event_topic = "0x057adae5fa3e9caa8a0d584edff60f61558d33f073412ec2d66d558b739e0a41"
                
                print(f"🔍 Searching for Factory event in blocks {latest_block - 5} to {latest_block}")
                
                # Check the last few blocks for the Factory's event
                for block_num in range(latest_block - 5, latest_block + 1):
                    try:
                        block = self.w3.eth.get_block(block_num, full_transactions=True)
                        print(f"   Checking block {block_num} ({len(block.transactions)} transactions)")
                        
                        for tx in block.transactions:
                            if tx.to and tx.to.lower() == factory_address.lower():
                                print(f"     Found Factory transaction: {tx.hash.hex()}")
                                # This is a Factory transaction
                                receipt = self.w3.eth.get_transaction_receipt(tx.hash)
                                if receipt.logs:
                                    print(f"       Transaction has {len(receipt.logs)} logs")
                                    for log in receipt.logs:
                                        if log.topics and len(log.topics) > 0 and log.topics[0].hex() == deployment_event_topic:
                                            print(f"✅ Found Factory TREXSuiteDeployed event in block {block_num}")
                                            deployed_addresses = self.parse_deployment_event([log])
                                            break
                                    if deployed_addresses:
                                        break
                        if deployed_addresses:
                            break
                    except Exception as e:
                        print(f"⚠️ Error checking block {block_num}: {e}")
                        continue
                
                if not deployed_addresses:
                    # Fallback: try to parse from Gateway logs (might contain Factory event)
                    print(f"🔍 Fallback: checking Gateway logs for Factory event...")
                    deployed_addresses = self.parse_deployment_event(tx_receipt.logs)
                
                if not deployed_addresses:
                    # Second fallback: search more broadly for the event
                    print(f"🔍 Second fallback: searching all recent blocks for Factory event...")
                    try:
                        # Search more blocks and also check for any transaction that might have emitted the event
                        for block_num in range(latest_block - 10, latest_block + 1):
                            try:
                                block = self.w3.eth.get_block(block_num, full_transactions=False)
                                # Just check if the block has any transactions to Factory
                                if any(tx.get('to') and tx.get('to').lower() == factory_address.lower() for tx in block.transactions):
                                    print(f"   Found Factory transaction in block {block_num}, getting full block...")
                                    full_block = self.w3.eth.get_block(block_num, full_transactions=True)
                                    for tx in full_block.transactions:
                                        if tx.to and tx.to.lower() == factory_address.lower():
                                            receipt = self.w3.eth.get_transaction_receipt(tx.hash)
                                            if receipt.logs:
                                                for log in receipt.logs:
                                                    if log.topics and len(log.topics) > 0 and log.topics[0].hex() == deployment_event_topic:
                                                        print(f"✅ Found Factory event in extended search!")
                                                        deployed_addresses = self.parse_deployment_event([log])
                                                        break
                                                if deployed_addresses:
                                                    break
                                    if deployed_addresses:
                                        break
                            except Exception as e:
                                continue
                    except Exception as e:
                        print(f"⚠️ Extended search failed: {e}")
                
            except Exception as e:
                print(f"⚠️ Error looking for Factory event: {e}")
                # Fallback: try to parse from Gateway logs
                print(f"🔍 Fallback: checking Gateway logs...")
                deployed_addresses = self.parse_deployment_event(tx_receipt.logs)
            
            if not deployed_addresses:
                print("❌ Could not parse deployment event - deployment may have failed")
                return {
                    'success': False,
                    'error': 'Could not parse deployment event',
                    'transaction_hash': tx_receipt.transactionHash.hex(),
                    'note': 'Check transaction logs for deployment status'
                }
            
            # Note: Database storage is handled by the Flask route
            print(f"\n💾 Database storage will be handled by Flask route")
            print(f"   Token: {self.token_details['name']} ({self.token_details['symbol']})")
            print(f"   Supply: {self.token_details['totalSupply']}")
            print(f"   Deployed successfully on blockchain")
            print(f"   Addresses extracted from deployment event")
            
            # Get final block number
            final_block = self.w3.eth.block_number
            print(f"\n📦 Final block number: {final_block}")
            print(f"📦 Blocks created: {final_block - initial_block}")
            
            print("\n🎉 ERC-3643 Token Suite deployed successfully via TREXGateway V2!")
            print(f"\n📋 Deployment Summary:")
            print(f"   Token Address: {deployed_addresses['token']}")
            print(f"   Identity Registry: {deployed_addresses['identity_registry']}")
            print(f"   Compliance: {deployed_addresses['compliance']}")
            print(f"   Claim Topics Registry: {deployed_addresses['claim_topics_registry']}")
            print(f"   Trusted Issuers Registry: {deployed_addresses['trusted_issuers_registry']}")
            print(f"   Salt: {deployed_addresses['salt']}")
            print(f"   Transaction: {tx_receipt.transactionHash.hex()}")
            
            print("\n🚀 Next steps:")
            print("1. Configure compliance rules in the ModularCompliance contract")
            print("2. Add trusted issuers to the TrustedIssuersRegistry")
            print("3. Set up claim topics in the ClaimTopicsRegistry")
            print("4. Mint tokens using token.mint()")
            print("5. Check the dashboard for deployment details")
            
            # Return success with all addresses for the Flask route to store in database
            return {
                'success': True,
                'message': 'Token deployed successfully via TREXGateway V2',
                'transaction_hash': tx_receipt.transactionHash.hex(),
                'gateway_address': gateway_address,
                'salt': deployed_addresses['salt'],
                'token_address': deployed_addresses['token'],
                'identity_registry': deployed_addresses['identity_registry'],
                'compliance': deployed_addresses['compliance'],
                'claim_topics_registry': deployed_addresses['claim_topics_registry'],
                'trusted_issuers_registry': deployed_addresses['trusted_issuers_registry'],
                'note': 'Token deployed via Gateway V2 - Flask route will store in database'
            }
            
        except Exception as e:
            print(f"❌ Token deployment failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Token deployment failed: {e}',
                'note': 'Exception occurred during deployment process'
            }

def main():
    """Main function for standalone testing"""
    deployment = TokenDeployment()
    deployment.deploy()

if __name__ == "__main__":
    main()