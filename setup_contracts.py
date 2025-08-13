#!/usr/bin/env python3
"""
Setup script to copy contract ABIs and store addresses directly in database
"""

import json
import shutil
import os
from pathlib import Path
import sys

# Add the current directory to Python path to import from the platform
sys.path.append(str(Path(__file__).parent))

def setup_contracts():
    """Copy contract ABIs and store addresses directly in database"""
    
    # Paths (self-contained)
    platform_path = Path(__file__).parent
    local_artifacts = platform_path / 'artifacts'
    
    # Create contracts directory if it doesn't exist
    contracts_dir = platform_path / 'contracts'
    contracts_dir.mkdir(exist_ok=True)
    
    print("🔧 Setting up contracts for Token Platform...")
    
    # Use local artifacts (self-contained)
    platform_artifacts = contracts_dir / 'artifacts'
    
    if local_artifacts.exists():
        # Create artifacts directory
        platform_artifacts.mkdir(exist_ok=True)
        
        # Copy all JSON contract files from local artifacts
        contract_files = [
            'TREXFactory.json',
            'Token.json',
            'IdentityRegistry.json',
            'ClaimTopicsRegistry.json',
            'TrustedIssuersRegistry.json',
            'ModularCompliance.json',
            'Identity.json'
        ]
        
        for contract_file in contract_files:
            source = local_artifacts / 'trex' / contract_file
            destination = platform_artifacts / contract_file
            
            if source.exists():
                shutil.copy2(source, destination)
                print(f"✅ Copied {contract_file}")
            else:
                print(f"⚠️  {contract_file} not found")
    
    # Store contracts directly in database
    store_contracts_in_database(local_artifacts)
    
    print("🎉 Contract setup completed!")
    return True

def store_contracts_in_database(local_artifacts):
    """Store contract addresses directly in database from local artifacts"""
    try:
        # Import Flask app and database
        from app import app
        from models import db
        from models.contract import Contract
        from utils.contract_utils import store_contract
        
        # Check if local artifacts exist
        if not local_artifacts.exists():
            print("❌ Local artifacts directory not found")
            return
        
        print("✅ Using local artifacts (self-contained)")
        
        with open(deployments_file, 'r') as f:
            deployments = json.load(f)
        
        with app.app_context():
            # Clear existing contracts to avoid duplicates
            Contract.query.delete()
            db.session.commit()
            print("🧹 Cleared existing contract records")
            
            # Get latest deployment
            if 'easydeploy' in deployments and deployments['easydeploy']:
                latest_deployment = deployments['easydeploy'][-1]
                
                # Store factory contracts
                if 'factory' in latest_deployment:
                    factory = latest_deployment['factory']
                    store_contract(
                        'TREXFactory',
                        factory['address'],
                        'T-REX Factory',
                        latest_deployment['deployer'],
                        metadata={
                            'type': 'factory',
                            'owner': factory['owner'],
                            'implementationAuthority': factory['implementationAuthority']
                        }
                    )
                    print("✅ Stored TREXFactory in database")
                    
                    # Store Identity Factory
                    if 'idFactory' in factory:
                        store_contract(
                            'IdentityFactory',
                            factory['idFactory'],
                            'Identity Factory',
                            latest_deployment['deployer'],
                            metadata={'type': 'factory'}
                        )
                        print("✅ Stored IdentityFactory in database")
                
                # Store gateway
                if 'gateway' in latest_deployment:
                    gateway = latest_deployment['gateway']
                    store_contract(
                        'TREXGateway',
                        gateway['address'],
                        'T-REX Gateway',
                        latest_deployment['deployer'],
                        metadata={
                            'type': 'gateway',
                            'owner': gateway['owner'],
                            'factory': gateway['factory']
                        }
                    )
                    print("✅ Stored TREXGateway in database")
                
                # Store implementation contracts
                if 'implementations' in latest_deployment:
                    implementations = latest_deployment['implementations']
                    for contract_name, address in implementations.items():
                        if address and address != '0x0000000000000000000000000000000000000000':
                            store_contract(
                                contract_name,
                                address,
                                f'{contract_name} Implementation',
                                latest_deployment['deployer'],
                                metadata={'type': 'implementation'}
                            )
                            print(f"✅ Stored {contract_name} in database")
                
                # Store authority contracts
                if 'authorities' in latest_deployment:
                    authorities = latest_deployment['authorities']
                    for authority_name, address in authorities.items():
                        if address and address != '0x0000000000000000000000000000000000000000':
                            store_contract(
                                authority_name,
                                address,
                                f'{authority_name} Authority',
                                latest_deployment['deployer'],
                                metadata={'type': 'authority'}
                            )
                            print(f"✅ Stored {authority_name} in database")
                
                # Store factory contracts
                if 'factories' in latest_deployment:
                    factories = latest_deployment['factories']
                    for factory_name, address in factories.items():
                        if address and address != '0x0000000000000000000000000000000000000000':
                            store_contract(
                                factory_name,
                                address,
                                f'{factory_name} Factory',
                                latest_deployment['deployer'],
                                metadata={'type': 'factory'}
                            )
                            print(f"✅ Stored {factory_name} in database")
                
                # Store deployed tokens
                if 'tokens' in latest_deployment and latest_deployment['tokens']:
                    for token in latest_deployment['tokens']:
                        # Store token contract
                        store_contract(
                            'Token',
                            token['token']['address'],
                            f"{token['token']['name']} ({token['token']['symbol']})",
                            token['deployer'],
                            metadata={
                                'type': 'token',
                                'name': token['token']['name'],
                                'symbol': token['token']['symbol'],
                                'decimals': token['token']['decimals'],
                                'deployed_at': token['timestamp'],
                                'factoryAddress': token['factoryAddress']
                            }
                        )
                        print(f"✅ Stored token {token['token']['symbol']} in database")
                        
                        # Store token suite components
                        if 'suite' in token:
                            suite = token['suite']
                            for component_name, address in suite.items():
                                if address and address != '0x0000000000000000000000000000000000000000':
                                    store_contract(
                                        f"{token['token']['symbol']}_{component_name}",
                                        address,
                                        f"{token['token']['name']} {component_name}",
                                        token['deployer'],
                                        metadata={
                                            'type': 'token_suite',
                                            'token_symbol': token['token']['symbol'],
                                            'component': component_name
                                        }
                                    )
                                    print(f"✅ Stored {token['token']['symbol']}_{component_name} in database")
                
                # Print summary
                print("\n📋 Database Contract Summary:")
                contracts = Contract.query.all()
                for contract in contracts:
                    print(f"  {contract.contract_type}: {contract.contract_address}")
                print(f"\n🎉 Total contracts stored: {len(contracts)}")
        
        print("🎉 All contracts stored in database successfully!")
        
    except Exception as e:
        print(f"❌ Error storing contracts in database: {e}")
        import traceback
        traceback.print_exc()

def check_setup():
    """Check if setup is complete"""
    
    platform_path = Path(__file__).parent
    contracts_dir = platform_path / 'contracts'
    
    required_files = [
        'artifacts/TREXFactory.json',
        'artifacts/Token.json',
        'artifacts/IdentityRegistry.json'
    ]
    
    print("🔍 Checking setup...")
    
    all_good = True
    for file_path in required_files:
        full_path = contracts_dir / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - Missing")
            all_good = False
    
    # Check database contracts
    try:
        from app import app
        from models.contract import Contract
        
        with app.app_context():
            contracts = Contract.query.all()
            if contracts:
                print(f"✅ Database: {len(contracts)} contracts stored")
            else:
                print("❌ Database: No contracts stored")
                all_good = False
    except Exception as e:
        print(f"❌ Database check failed: {e}")
        all_good = False
    
    if all_good:
        print("\n🎉 Setup is complete!")
    else:
        print("\n⚠️  Setup is incomplete. Run setup_contracts() to fix.")
    
    return all_good

if __name__ == "__main__":
    print("🚀 Token Platform Contract Setup")
    print("=" * 40)
    
    # Check if local artifacts exist (self-contained)
    artifacts_path = Path(__file__).parent / 'artifacts'
    if not artifacts_path.exists():
        print("❌ Local artifacts directory not found")
        print("Please ensure artifacts are properly set up.")
        exit(1)
    
    # Run setup
    if setup_contracts():
        print("\n" + "=" * 40)
        check_setup()
    else:
        print("❌ Setup failed")
        exit(1) 