import os
import subprocess
import json
from models.user import User, db

class HybridClaimService:
    """
    Hybrid claim service that uses JavaScript subprocess for contract interactions
    while keeping database operations in Python.
    
    CORRECT T-REX ARCHITECTURE:
    - Investor OnchainID has ONLY Account 0 (deployer) as management key
    - Trusted issuer keys are ONLY on ClaimIssuer contract
    - Platform (Account 0) adds claims using its existing management key
    - NO third-party management keys are added to investor OnchainID
    """
    
    def __init__(self, scripts_dir=None):
        """
        Initialize the hybrid claim service.
        
        Args:
            scripts_dir (str): Directory containing JavaScript scripts (default: scripts/)
        """
        if scripts_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.scripts_dir = os.path.join(os.path.dirname(current_dir), 'scripts')
        else:
            self.scripts_dir = scripts_dir
    
    
    def _restore_trex_abi_files(self):
        """
        Restore TREX ABI files from trex2 backup folder.
        This is a workaround for the ABI deletion issue during claim addition.
        """
        try:
            import shutil
            
            # Get the artifacts directory path
            current_dir = os.path.dirname(os.path.abspath(__file__))
            artifacts_dir = os.path.join(os.path.dirname(current_dir), 'artifacts')
            trex_backup_dir = os.path.join(artifacts_dir, 'trex2')
            trex_target_dir = os.path.join(artifacts_dir, 'trex')
            
            # Check if backup directory exists
            if not os.path.exists(trex_backup_dir):
                print(f"⚠️ TREX backup directory not found: {trex_backup_dir}")
                return
            
            # Check if target directory exists
            if not os.path.exists(trex_target_dir):
                print(f"⚠️ TREX target directory not found: {trex_target_dir}")
                return
            
            print(f"🔄 Restoring TREX ABI files from {trex_backup_dir} to {trex_target_dir}")
            
            # Get list of files in backup directory
            backup_files = os.listdir(trex_backup_dir)
            restored_count = 0
            
            for file_name in backup_files:
                if file_name.endswith('.json'):
                    backup_file = os.path.join(trex_backup_dir, file_name)
                    target_file = os.path.join(trex_target_dir, file_name)
                    
                    try:
                        # Copy file from backup to target
                        shutil.copy2(backup_file, target_file)
                        restored_count += 1
                        print(f"✅ Restored: {file_name}")
                    except Exception as e:
                        print(f"⚠️ Failed to restore {file_name}: {e}")
            
            print(f"🎉 TREX ABI restoration completed: {restored_count} files restored")
            
        except Exception as e:
            print(f"❌ Error restoring TREX ABI files: {e}")
            import traceback
            traceback.print_exc()

    def _parse_js_result(self, stdout):
        """
        Parse the JSON result from JavaScript output.
        """
        try:
            lines = stdout.split('\n')
            json_started = False
            json_lines = []
            
            for line in lines:
                if "🎯 RESULT:" in line:
                    json_started = True
                    continue
                if json_started and line.strip():
                    json_lines.append(line)
            
            if json_lines:
                json_output = '\n'.join(json_lines)
                return json.loads(json_output)
            else:
                print("⚠️ Could not find JSON result in JavaScript output")
                return None
                
        except json.JSONDecodeError as e:
            print(f"⚠️ Could not parse JSON result: {e}")
            return None
    
    def prepare_claim_transaction_data(self, investor_user_id, trusted_issuer_user_id, topic, data):
        """
        Prepare transaction data for claim addition without executing.
        Used for MetaMask integration.
        
        Args:
            investor_user_id (int): ID of the investor user
            trusted_issuer_user_id (int): ID of the trusted issuer user
            topic (int): Claim topic
            data (str): Claim data
            
        Returns:
            dict: Transaction data for MetaMask
        """
        try:
            print(f"🔧 PREPARING CLAIM TRANSACTION DATA")
            print(f"🔍 Investor User ID: {investor_user_id}")
            print(f"🔍 Trusted Issuer User ID: {trusted_issuer_user_id}")
            print(f"🔍 Topic: {topic}")
            print(f"🔍 Data: {data}")
            
            # Load data from database
            investor = User.query.get(investor_user_id)
            if not investor:
                return {'success': False, 'error': f'Investor user {investor_user_id} not found'}
            
            trusted_issuer = User.query.get(trusted_issuer_user_id)
            if not trusted_issuer:
                return {'success': False, 'error': f'Trusted issuer user {trusted_issuer_user_id} not found'}
            
            # Validate required data
            if not investor.onchain_id:
                return {'success': False, 'error': f'Investor {investor.username} has no OnchainID'}
            
            if not trusted_issuer.claim_issuer_address:
                return {'success': False, 'error': f'Trusted issuer {trusted_issuer.username} has no ClaimIssuer contract'}
            
            # Prepare transaction data
            transaction_data = {
                'investor_onchain_id': investor.onchain_id,
                'trusted_issuer_address': trusted_issuer.wallet_address,
                'claim_issuer_address': trusted_issuer.claim_issuer_address,
                'topic': topic,
                'claim_data': data,
                'scheme': 1,  # ECDSA - hardcoded
                'uri': ''     # Empty URI - hardcoded
            }
            
            return {
                'success': True,
                'transaction_data': transaction_data,
                'investor': {
                    'id': investor.id,
                    'username': investor.username,
                    'wallet_address': investor.wallet_address,
                    'onchain_id': investor.onchain_id
                },
                'trusted_issuer': {
                    'id': trusted_issuer.id,
                    'username': trusted_issuer.username,
                    'wallet_address': trusted_issuer.wallet_address,
                    'claim_issuer_address': trusted_issuer.claim_issuer_address
                },
                'message': 'Transaction data prepared for MetaMask approval'
            }
            
        except Exception as e:
            print(f"❌ Error preparing claim transaction data: {e}")
            return {'success': False, 'error': f'Error preparing claim transaction data: {str(e)}'}

    def build_claim_transaction_data(self, investor_onchain_id, trusted_issuer_address, claim_issuer_address, topic, claim_data, scheme=1, uri=''):
        """
        Build transaction data for claim addition (MetaMask integration)
        This method prepares the data hash that needs to be signed by MetaMask
        
        Args:
            investor_onchain_id (str): Investor's OnchainID address
            trusted_issuer_address (str): Trusted issuer wallet address
            claim_issuer_address (str): ClaimIssuer contract address
            topic (int): Claim topic
            claim_data (str): Claim data
            scheme (int): Claim scheme (default: 1 for ECDSA)
            uri (str): Claim URI (default: empty)
            
        Returns:
            dict: Data hash for MetaMask signing
        """
        try:
            print(f"🔧 BUILDING CLAIM TRANSACTION DATA FOR METAMASK")
            print(f"🔍 Investor OnchainID: {investor_onchain_id}")
            print(f"🔍 Trusted Issuer Address: {trusted_issuer_address}")
            print(f"🔍 ClaimIssuer Address: {claim_issuer_address}")
            print(f"🔍 Topic: {topic}")
            print(f"🔍 Data: {claim_data}")
            print(f"🔍 Scheme: {scheme}")
            print(f"🔍 URI: {uri}")
            
            # Get contract ABIs and addresses
            from services.web3_service import Web3Service
            web3_service = Web3Service()
            
            # Encode claim data
            import binascii
            claim_data_bytes = claim_data.encode('utf-8')
            claim_data_hex = '0x' + claim_data_bytes.hex()
            
            print(f"🔍 Encoded claim data: {claim_data_hex}")
            
            # Create the data hash that needs to be signed (same as original script)
            data_hash = web3_service.w3.keccak(
                web3_service.w3.codec.encode(
                    ['address', 'uint256', 'bytes'],
                    [investor_onchain_id, topic, claim_data_hex]
                )
            )
            
            print(f"🔍 Data hash to sign: {data_hash.hex()}")
            
            # Return the data hash and claim info for MetaMask signing
            return {
                'success': True,
                'data_hash': data_hash.hex(),
                'claim_info': {
                    'investor_onchain_id': investor_onchain_id,
                    'trusted_issuer_address': trusted_issuer_address,
                    'claim_issuer_address': claim_issuer_address,
                    'topic': topic,
                    'claim_data': claim_data,
                    'claim_data_hex': claim_data_hex,
                    'scheme': scheme,
                    'uri': uri
                },
                'message': 'Data hash ready for MetaMask signing'
            }
            
        except Exception as e:
            print(f"❌ Error building claim transaction data: {e}")
            return {'success': False, 'error': f'Error building claim transaction data: {str(e)}'}
    
    def _encode_identity_add_claim_data(self, abi, topic, scheme, issuer_address, signature, claim_data_hex, uri):
        """
        Encode the addClaim function call data for Identity contract
        Function signature: addClaim(uint256 _topic, uint256 _scheme, address _issuer, bytes _signature, bytes _data, string _uri)
        """
        try:
            from web3 import Web3
            
            # Create Web3 instance
            w3 = Web3()
            
            # Find the addClaim function in the ABI
            add_claim_function = None
            for item in abi:
                if item.get('name') == 'addClaim' and item.get('type') == 'function':
                    add_claim_function = item
                    break
            
            if not add_claim_function:
                raise Exception("addClaim function not found in Identity ABI")
            
            # Encode the function call
            function_signature = w3.keccak(text="addClaim(uint256,uint256,address,bytes,bytes,string)")[:4]
            
            # Encode parameters
            encoded_params = w3.codec.encode(
                ['uint256', 'uint256', 'address', 'bytes', 'bytes', 'string'],
                [topic, scheme, issuer_address, signature, claim_data_hex, uri]
            )
            
            # Combine function signature with encoded parameters
            transaction_data = function_signature + encoded_params
            
            return transaction_data.hex()
            
        except Exception as e:
            print(f"❌ Error encoding Identity addClaim data: {e}")
            return None
    
    def add_claim_with_metamask_signature(self, investor_onchain_id, trusted_issuer_address, claim_issuer_address, topic, claim_data, signature, data_hash):
        """
        Add claim using MetaMask signature and original JavaScript script approach
        
        Args:
            investor_onchain_id (str): Investor's OnchainID address
            trusted_issuer_address (str): Trusted issuer wallet address
            claim_issuer_address (str): ClaimIssuer contract address
            topic (int): Claim topic
            claim_data (str): Claim data
            signature (str): MetaMask signature
            data_hash (str): Data hash that was signed
            
        Returns:
            dict: Result of adding claim
        """
        try:
            print(f"🔧 ADDING CLAIM WITH METAMASK SIGNATURE")
            print(f"🔍 Investor OnchainID: {investor_onchain_id}")
            print(f"🔍 Trusted Issuer Address: {trusted_issuer_address}")
            print(f"🔍 ClaimIssuer Address: {claim_issuer_address}")
            print(f"🔍 Topic: {topic}")
            print(f"🔍 Data: {claim_data}")
            print(f"🔍 Signature: {signature}")
            print(f"🔍 Data Hash: {data_hash}")
            
            # Encode claim data
            import binascii
            claim_data_bytes = claim_data.encode('utf-8')
            claim_data_hex = '0x' + claim_data_bytes.hex()
            
            print(f"🔍 Encoded claim data: {claim_data_hex}")
            
            # Create configuration for JavaScript (same as original add_claim method)
            # but with the MetaMask signature
            config = {
                "investorOnchainID": investor_onchain_id,
                "trustedIssuerAddress": trusted_issuer_address,
                "claimIssuerAddress": claim_issuer_address,
                "trustedIssuerPrivateKey": "METAMASK_SIGNATURE",  # Placeholder - we'll use signature directly
                "topic": topic,
                "claimData": claim_data,
                "metamaskSignature": signature,  # Add the MetaMask signature
                "dataHash": data_hash  # Add the data hash
            }
            
            # Create temporary config file in scripts directory
            config_file = os.path.join(self.scripts_dir, 'claim_config.json')
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"🔧 Created config file: {config_file}")
            print(f"🔧 Configuration:")
            print(f"   investorOnchainID: {investor_onchain_id}")
            print(f"   trustedIssuerAddress: {trusted_issuer_address}")
            print(f"   claimIssuerAddress: {claim_issuer_address}")
            print(f"   topic: {topic}")
            print(f"   claimData: {claim_data}")
            print(f"   metamaskSignature: {signature}")
            print(f"   dataHash: {data_hash}")
            
            # Prepare command (same as original add_claim method)
            cmd = [
                "npx", "hardhat", "run", "addClaim.js",
                "--network", "localhost"
            ]
            
            print(f"🔧 Running command: {' '.join(cmd)}")
            
            # Run the JavaScript subprocess
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.scripts_dir
            )
            
            print(f"📤 JavaScript output:")
            print(result.stdout)
            
            if result.stderr:
                print(f"⚠️ JavaScript errors:")
                print(result.stderr)
            
            # Check if the command was successful
            if result.returncode == 0:
                print("✅ JavaScript subprocess completed successfully!")
                
                # Parse the JSON result
                js_result = self._parse_js_result(result.stdout)
                
                if js_result and js_result.get('success'):
                    print("🎉 Claim addition successful!")
                    
                    transaction_hash = js_result.get('transactionHash')
                    print(f"✅ Claim addition transaction: {transaction_hash}")
                    
                    return {
                        'success': True,
                        'transaction_hash': transaction_hash,
                        'message': 'Claim added successfully via MetaMask signature'
                    }
                else:
                    error_msg = js_result.get('error', 'Unknown error') if js_result else 'Failed to parse JavaScript result'
                    return {'success': False, 'error': f'Claim addition failed: {error_msg}'}
                    
            else:
                return {'success': False, 'error': f'JavaScript subprocess failed with return code: {result.returncode}'}
                
        except Exception as e:
            print(f"❌ Error adding claim with MetaMask signature: {e}")
            return {'success': False, 'error': f'Error adding claim with MetaMask signature: {str(e)}'}
            
        finally:
            # Clean up config file
            try:
                if 'config_file' in locals() and os.path.exists(config_file):
                    os.remove(config_file)
                    print(f"🧹 Cleaned up config file: {config_file}")
            except Exception as e:
                print(f"⚠️ Could not clean up config file: {e}")
            
            # RESTORE TREX ABI FILES - Workaround for ABI deletion issue
            try:
                self._restore_trex_abi_files()
            except Exception as e:
                print(f"⚠️ Could not restore TREX ABI files: {e}") 