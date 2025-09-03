from web3 import Web3
from eth_account import Account
import json
from pathlib import Path
import os

class Web3Service:
    """Service for Web3 interactions with Ethereum blockchain"""
    
    def __init__(self, private_key=None):
        # Connect to blockchain
        rpc_url = os.environ.get('RPC_URL') or 'http://localhost:8545'
        print(f"🔗 Connecting to blockchain at: {rpc_url}")
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Test connection
        try:
            block_number = self.w3.eth.block_number
            print(f"✅ Blockchain connected successfully! Current block: {block_number}")
        except Exception as e:
            print(f"❌ Failed to connect to blockchain: {e}")
        
        # Set private key and account
        self.private_key = private_key or '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        self.account = Account.from_key(self.private_key)
        print(f"🔍 Web3Service: Private key {self.private_key[:20]}... creates account {self.account.address}")
        
        # Load contract ABIs
        self.contracts_dir = Path(__file__).parent.parent / 'contracts' / 'artifacts'
        self.contract_abis = {}
        self._load_contract_abis()
    
    def _load_contract_abis(self):
        """Load all contract ABIs from the artifacts directory (simplified like T-REX)"""
        if not self.contracts_dir.exists():
            print(f"Warning: Contracts directory not found: {self.contracts_dir}")
            return
        
        # Load regular contracts from artifacts root (like T-REX)
        for abi_file in self.contracts_dir.glob('*.json'):
            try:
                with open(abi_file, 'r') as f:
                    abi_data = json.load(f)
                    contract_name = abi_file.stem
                    self.contract_abis[contract_name] = abi_data['abi']
                    print(f"✅ Loaded {contract_name} ABI")
            except Exception as e:
                print(f"Error loading ABI for {abi_file}: {e}")
        
        # Load OnchainID contracts from local artifacts (self-contained)
        trex_artifacts_dir = Path(__file__).parent.parent / 'artifacts' / 'trex'
        if trex_artifacts_dir.exists():
            # Load Identity contract (use the interface like T-REX)
            identity_path = trex_artifacts_dir / 'Identity.json'
            if identity_path.exists():
                try:
                    with open(identity_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['Identity'] = abi_data['abi']
                        print(f"✅ Loaded Identity ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading Identity ABI: {e}")
            
            # Load IIdFactory (the interface)
            iidfactory_path = trex_artifacts_dir / 'IIdFactory.json'
            if iidfactory_path.exists():
                try:
                    with open(iidfactory_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['IIdFactory'] = abi_data['abi']
                        print(f"✅ Loaded IIdFactory ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading IIdFactory ABI: {e}")
            
            # Load Factory contract (the actual IdFactory implementation)
            # Try to load from local @onchain-id artifacts
            factory_path = Path(__file__).parent.parent / 'artifacts' / '@onchain-id' / 'solidity' / 'contracts' / 'factory' / 'IdFactory.sol' / 'IdFactory.json'
            if factory_path.exists():
                try:
                    with open(factory_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['Factory'] = abi_data['abi']
                        print(f"✅ Loaded Factory ABI from local @onchain-id")
                except Exception as e:
                    print(f"Error loading Factory ABI: {e}")
            
            # Load ClaimIssuer contract
            claimissuer_path = trex_artifacts_dir / 'ClaimIssuer.json'
            if claimissuer_path.exists():
                try:
                    with open(claimissuer_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['ClaimIssuer'] = abi_data['abi']
                        print(f"✅ Loaded ClaimIssuer ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading ClaimIssuer ABI: {e}")
            
            # Load Token contract (T-REX token implementation)
            token_path = trex_artifacts_dir / 'Token.json'
            if token_path.exists():
                try:
                    with open(token_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['Token'] = abi_data['abi']
                        print(f"✅ Loaded Token ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading Token ABI: {e}")
            
            # Load IdentityRegistry contract (T-REX identity management)
            ir_path = trex_artifacts_dir / 'IdentityRegistry.json'
            if ir_path.exists():
                try:
                    with open(ir_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['IdentityRegistry'] = abi_data['abi']
                        print(f"✅ Loaded IdentityRegistry ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading IdentityRegistry ABI: {e}")
            
            # Load ModularCompliance contract (T-REX compliance engine)
            compliance_path = trex_artifacts_dir / 'ModularCompliance.json'
            if compliance_path.exists():
                try:
                    with open(compliance_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['Compliance'] = abi_data['abi']
                        print(f"✅ Loaded Compliance ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading Compliance ABI: {e}")
            
            # Load TREXImplementationAuthority contract (T-REX implementation management)
            impl_authority_path = trex_artifacts_dir / 'TREXImplementationAuthority.json'
            if impl_authority_path.exists():
                try:
                    with open(impl_authority_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['TREXImplementationAuthority'] = abi_data['abi']
                        print(f"✅ Loaded TREXImplementationAuthority ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading TREXImplementationAuthority ABI: {e}")
            
            # Load TREX Gateway contract
            gateway_path = trex_artifacts_dir / 'TREXGateway.json'
            if gateway_path.exists():
                try:
                    with open(gateway_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['TREXGateway'] = abi_data['abi']
                        print(f"✅ Loaded TREXGateway ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading TREXGateway ABI: {e}")
            
            # Load TREX Factory contract
            factory_path = trex_artifacts_dir / 'TREXFactory.json'
            if factory_path.exists():
                try:
                    with open(factory_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['TREXFactory'] = abi_data['abi']
                        print(f"✅ Loaded TREXFactory ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading TREXFactory ABI: {e}")
            
            # Load IdentityRegistryStorage contract (T-REX identity storage)
            irs_path = trex_artifacts_dir / 'IdentityRegistryStorage.json'
            if irs_path.exists():
                try:
                    with open(irs_path, 'r') as f:
                        abi_data = json.load(f)
                        self.contract_abis['IdentityRegistryStorage'] = abi_data['abi']
                        print(f"✅ Loaded IdentityRegistryStorage ABI from local T-REX")
                except Exception as e:
                    print(f"Error loading IdentityRegistryStorage ABI: {e}")
        else:
            print(f"Warning: Local T-REX artifacts directory not found: {trex_artifacts_dir}")
        
        # Map Factory to IIdFactory since IdFactory.json doesn't exist
        if 'IIdFactory' in self.contract_abis and 'Factory' not in self.contract_abis:
            self.contract_abis['Factory'] = self.contract_abis['IIdFactory']
            print(f"✅ Mapped 'Factory' to 'IIdFactory' (interface)")
    

    
    def parse_units(self, amount, decimals=18):
        """Convert human-readable amount to wei"""
        return self.w3.to_wei(amount, 'ether')
    
    def format_units(self, amount, decimals=18):
        """Convert wei to human-readable amount"""
        return self.w3.from_wei(amount, 'ether')
    
    def transact_contract_function(self, contract_name, contract_address, function_name, *args):
        """Execute a contract function that requires a transaction"""
        try:
            contract = self.get_contract(contract_address, contract_name)
            if not contract:
                raise ValueError(f"Contract {contract_name} not found")
            
            # Get the function
            function = getattr(contract.functions, function_name)
            
            # Build transaction
            tx_args_msg = f"🔧 Building transaction with args: {args}"
            account_msg = f"🔧 Account address: {self.account.address}"
            gas_msg = f"🔧 Gas price: {self.w3.eth.gas_price}"
            nonce_msg = f"🔧 Nonce: {self.w3.eth.get_transaction_count(self.account.address)}"
            
            print(tx_args_msg)
            print(account_msg)
            print(gas_msg)
            print(nonce_msg)
            
            # Also write to file
            log_file = Path(__file__).parent.parent / 'logs' / 'tokenplatform_debug.log'
            try:
                with open(log_file, "a") as f:
                    f.write(f"{tx_args_msg}\n")
                    f.write(f"{account_msg}\n")
                    f.write(f"{gas_msg}\n")
                    f.write(f"{nonce_msg}\n")
            except Exception as e:
                print(f"Warning: Could not write to debug log: {e}")
            
            tx = function(*args).build_transaction({
                'from': self.account.address,
                'gas': 3000000,  # Default gas limit
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address)
            })
            
            # Sign and send the transaction
            signed_tx = self.account.sign_transaction(tx)
            # Handle both old and new eth-account versions
            raw_tx = getattr(signed_tx, 'rawTransaction', None) or getattr(signed_tx, 'raw_transaction', None)
            if not raw_tx:
                raise AttributeError("SignedTransaction object has no rawTransaction or raw_transaction attribute")
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
            
            return tx_hash.hex()
            
        except Exception as e:
            print(f"Error executing {function_name}: {e}")
            raise
    
    def call_contract_function(self, contract_name, contract_address, function_name, *args):
        """Call a contract function (read-only)"""
        try:
            contract = self.get_contract(contract_address, contract_name)
            if not contract:
                raise ValueError(f"Contract {contract_name} not found")
            
            # Get the function
            function = getattr(contract.functions, function_name)
            
            # Call the function
            result = function(*args).call()
            return result
            
        except Exception as e:
            print(f"Error calling {function_name}: {e}")
            raise
    
    @property
    def default_account(self):
        """Get default account address"""
        return self.account.address
    
    def get_token_balance(self, token_address, investor_address):
        """Get token balance for an investor"""
        try:
            # This is a simplified version - in real implementation you'd use the token contract
            return 0
        except Exception as e:
            print(f"Error getting token balance: {e}")
            return 0
    
    def wait_for_transaction(self, tx_hash):
        """Wait for a transaction to be mined"""
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            return receipt
        except Exception as e:
            print(f"Error waiting for transaction {tx_hash}: {e}")
            raise
    
    def get_contract_events(self, contract_name, contract_address, event_name, from_block=0, to_block='latest'):
        """Get events from a contract"""
        try:
            contract = self.get_contract(contract_address, contract_name)
            if not contract:
                raise ValueError(f"Contract {contract_name} not found")
            
            # Get the event
            event = getattr(contract.events, event_name)
            
            # Get events
            events = event.get_logs(fromBlock=from_block, toBlock=to_block)
            return events
            
        except Exception as e:
            print(f"Error getting events {event_name}: {e}")
            return []
    
    def is_address(self, address):
        """Check if a string is a valid Ethereum address"""
        return self.w3.is_address(address)
    
    def to_checksum_address(self, address):
        """Convert address to checksum format"""
        return self.w3.to_checksum_address(address)

    def get_user_account(self):
        """Get the user's account for signing transactions"""
        return self.account

    def get_contract_abi(self, contract_name):
        """Get contract ABI by name"""
        if contract_name in self.contract_abis:
            return self.contract_abis[contract_name]
        else:
            raise ValueError(f"ABI not found for contract: {contract_name}")
    
    def get_contract(self, address, contract_name):
        """Get a contract instance by name and address"""
        try:
            if contract_name not in self.contract_abis:
                raise ValueError(f"ABI not found for contract: {contract_name}")
            
            # Convert address to checksum format
            checksum_address = self.w3.to_checksum_address(address)
            
            contract = self.w3.eth.contract(
                address=checksum_address,
                abi=self.contract_abis[contract_name]
            )
            return contract
        except Exception as e:
            print(f"Error getting contract {contract_name}: {e}")
            return None
    
    def get_contract_for_deployment(self, contract_name):
        """Get a contract instance for deployment (without address)"""
        try:
            if contract_name not in self.contract_abis:
                raise ValueError(f"ABI not found for contract: {contract_name}")
            
            # For deployment, we need the bytecode too
            # For now, we'll use the ABI and let the caller handle bytecode
            contract = self.w3.eth.contract(
                abi=self.contract_abis[contract_name]
            )
            return contract
        except Exception as e:
            print(f"Error getting contract for deployment {contract_name}: {e}")
            return None 

    def add_trusted_issuer_to_registry(self, trusted_issuers_registry_address, claim_issuer_address, claim_topics):
        """
        Add a trusted issuer to the TrustedIssuersRegistry
        
        Args:
            trusted_issuers_registry_address (str): Address of the TrustedIssuersRegistry contract
            claim_issuer_address (str): Address of the ClaimIssuer contract to add
            claim_topics (list): List of claim topic IDs the issuer is allowed to emit
            
        Returns:
            str: Transaction hash
        """
        try:
            print(f"🔧 Adding trusted issuer {claim_issuer_address} to registry {trusted_issuers_registry_address}")
            print(f"🔧 Claim topics: {claim_topics}")
            
            # Call the addTrustedIssuer function
            tx_hash = self.transact_contract_function(
                'TrustedIssuersRegistry',
                trusted_issuers_registry_address,
                'addTrustedIssuer',
                claim_issuer_address,
                claim_topics
            )
            
            print(f"✅ Successfully added trusted issuer. Transaction hash: {tx_hash}")
            return tx_hash
            
        except Exception as e:
            print(f"❌ Error adding trusted issuer: {e}")
            raise

    def is_trusted_issuer(self, trusted_issuers_registry_address, claim_issuer_address):
        """
        Check if a ClaimIssuer is already registered as a trusted issuer
        
        Args:
            trusted_issuers_registry_address (str): Address of the TrustedIssuersRegistry contract
            claim_issuer_address (str): Address of the ClaimIssuer contract to check
            
        Returns:
            bool: True if the issuer is trusted, False otherwise
        """
        try:
            result = self.call_contract_function(
                'TrustedIssuersRegistry',
                trusted_issuers_registry_address,
                'isTrustedIssuer',
                claim_issuer_address
            )
            return result
        except Exception as e:
            print(f"❌ Error checking if issuer is trusted: {e}")
            return False 

    def is_contract_initialized(self, contract_name, contract_address):
        """
        Check if a contract is initialized by checking its owner
        
        Args:
            contract_name (str): Name of the contract
            contract_address (str): Address of the contract
            
        Returns:
            bool: True if contract is initialized (has non-zero owner), False otherwise
        """
        try:
            result = self.call_contract_function(
                contract_name,
                contract_address,
                'owner'
            )
            
            # Check if owner is not zero address
            is_initialized = result and result != '0x0000000000000000000000000000000000000000'
            print(f"🔍 {contract_name} owner: {result}, initialized: {is_initialized}")
            return is_initialized
            
        except Exception as e:
            print(f"❌ Error checking {contract_name} initialization: {e}")
            return False

    def initialize_contract(self, contract_name, contract_address):
        """
        Initialize a contract by calling its init() function
        
        Args:
            contract_name (str): Name of the contract
            contract_address (str): Address of the contract
            
        Returns:
            str: Transaction hash
        """
        try:
            print(f"🔧 Initializing {contract_name} at {contract_address}...")
            
            # Call the init function
            tx_hash = self.transact_contract_function(
                contract_name,
                contract_address,
                'init'
            )
            
            print(f"✅ Successfully initialized {contract_name}. Transaction hash: {tx_hash}")
            return tx_hash
            
        except Exception as e:
            print(f"❌ Error initializing {contract_name}: {e}")
            raise
    
    def add_deployer_to_gateway(self, gateway_address, deployer_address):
        """Add deployer to Gateway using Account 0 (owner)"""
        try:
            # Convert addresses to checksum format
            checksum_gateway = self.w3.to_checksum_address(gateway_address)
            checksum_deployer = self.w3.to_checksum_address(deployer_address)
            
            # Create Gateway contract instance
            gateway_contract = self.w3.eth.contract(
                address=checksum_gateway,
                abi=self.contract_abis['TREXGateway']
            )
            
            # Call addDeployer function
            tx = gateway_contract.functions.addDeployer(checksum_deployer).build_transaction({
                'from': self.account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address)
            })
            
            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for transaction receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                print(f"✅ Successfully added {deployer_address} as deployer to Gateway")
                return tx_hash.hex()
            else:
                raise Exception(f"Transaction failed with status {receipt.status}")
                
        except Exception as e:
            print(f"❌ Error adding deployer to Gateway: {e}")
            raise e
    
    def remove_deployer_from_gateway(self, gateway_address, deployer_address):
        """Remove deployer from Gateway using Account 0 (owner)"""
        try:
            # Convert addresses to checksum format
            checksum_gateway = self.w3.to_checksum_address(gateway_address)
            checksum_deployer = self.w3.to_checksum_address(deployer_address)
            
            # Create Gateway contract instance
            gateway_contract = self.w3.eth.contract(
                address=checksum_gateway,
                abi=self.contract_abis['TREXGateway']
            )
            
            # Call removeDeployer function
            tx = gateway_contract.functions.removeDeployer(checksum_deployer).build_transaction({
                'from': self.account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address)
            })
            
            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for transaction receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                print(f"✅ Successfully removed {deployer_address} as deployer from Gateway")
                return tx_hash.hex()
            else:
                raise Exception(f"Transaction failed with status {receipt.status}")
                
        except Exception as e:
            print(f"❌ Error removing deployer from Gateway: {e}")
            raise e
    
    def is_deployer_on_gateway(self, gateway_address, deployer_address):
        """Check if address is a deployer on Gateway"""
        try:
            # Convert addresses to checksum format
            checksum_gateway = self.w3.to_checksum_address(gateway_address)
            checksum_deployer = self.w3.to_checksum_address(deployer_address)
            
            # Create Gateway contract instance
            gateway_contract = self.w3.eth.contract(
                address=checksum_gateway,
                abi=self.contract_abis['TREXGateway']
            )
            
            # Call isDeployer function (read-only, no transaction needed)
            is_deployer = gateway_contract.functions.isDeployer(checksum_deployer).call()
            
            print(f"🔍 Checked deployer status for {deployer_address}: {is_deployer}")
            return is_deployer
            
        except Exception as e:
            print(f"❌ Error checking deployer status on Gateway: {e}")
            raise e
    
    def send_transaction(self, transaction_data):
        """Send a transaction using the account's private key"""
        try:
            # Build transaction with current nonce and gas price
            tx = {
                'to': transaction_data['to'],
                'data': transaction_data['data'],
                'gas': int(transaction_data['gas'], 16) if isinstance(transaction_data['gas'], str) else transaction_data['gas'],
                'gasPrice': int(transaction_data['gasPrice'], 16) if isinstance(transaction_data['gasPrice'], str) else transaction_data['gasPrice'],
                'nonce': transaction_data['nonce'],
                'value': int(transaction_data['value'], 16) if isinstance(transaction_data['value'], str) else transaction_data['value'],
                'chainId': int(transaction_data['chainId'], 16) if isinstance(transaction_data['chainId'], str) else transaction_data['chainId']
            }
            
            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"✅ Transaction sent successfully: {tx_hash.hex()}")
            return tx_hash
            
        except Exception as e:
            print(f"❌ Error sending transaction: {e}")
            raise e 