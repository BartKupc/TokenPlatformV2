 te#!/usr/bin/env python3
"""
Test script for multi-step compliance deployment flow
Tests the new hybrid approach where:
1. Platform deploys compliance modules (Account 0)
2. User deploys ModularCompliance via MetaMask
3. User adds and configures modules via MetaMask
4. User deploys token with ModularCompliance attached
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from services.trex_service import TREXService
from services.web3_service import Web3Service
import json

def test_compliance_transaction_building():
    """Test that compliance transactions are built correctly"""
    
    with app.app_context():
        try:
            print("🧪 Testing Multi-Step Compliance Deployment Flow")
            print("=" * 60)
            
            # Initialize services
            web3_service = Web3Service()
            trex_service = TREXService(web3_service)
            deployer_address = "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199"  # Test user account
            
            # Test compliance modules configuration
            compliance_modules = [
                {
                    'type': 'CountryRestrictModule',
                    'config': {
                        'allowed_countries': [250, 156]  # EU and Asia
                    }
                },
                {
                    'type': 'SupplyLimitModule', 
                    'config': {
                        'supply_limit': 100,
                        'per_user_limit': True
                    }
                },
                {
                    'type': 'TimeTransfersLimitsModule',
                    'config': {
                        'cooldown_period': 300  # 5 minutes
                    }
                }
            ]
            
            print(f"📋 Testing compliance modules:")
            for i, module in enumerate(compliance_modules):
                print(f"   {i+1}. {module['type']}: {module['config']}")
            print()
            
            # Step 1: Test compliance module deployment
            print("🔧 Step 1: Testing compliance module deployment...")
            result = trex_service.deploy_compliance_modules(compliance_modules, deployer_address)
            
            if not result['success']:
                print(f"❌ Failed to deploy compliance modules: {result['error']}")
                return False
            
            print("✅ Compliance module deployment test passed!")
            print(f"   Deployed modules: {len(result['deployed_modules'])}")
            
            # Check that we have the expected transaction structure
            expected_keys = [
                'deployed_modules',
                'modular_compliance_deployment', 
                'add_modules_transactions',
                'configure_modules_transactions',
                'token_deployment'
            ]
            
            print("\n🔍 Checking transaction structure...")
            for key in expected_keys:
                if key in result:
                    print(f"   ✅ {key}: Present")
                    if key == 'deployed_modules':
                        print(f"      📋 {len(result[key])} modules deployed")
                    elif key == 'add_modules_transactions':
                        print(f"      📋 {len(result[key])} add transactions")
                    elif key == 'configure_modules_transactions':
                        print(f"      📋 {len(result[key])} configure transactions")
                else:
                    print(f"   ❌ {key}: Missing")
                    return False
            
            # Test individual module deployments
            print("\n🔍 Checking deployed modules...")
            expected_module_types = ['CountryRestrictModule', 'SupplyLimitModule', 'TimeTransfersLimitsModule']
            deployed_module_types = [module['type'] for module in result['deployed_modules']]
            
            for module_type in expected_module_types:
                if module_type in deployed_module_types:
                    print(f"   ✅ {module_type}: Deployed")
                else:
                    print(f"   ❌ {module_type}: Not deployed")
                    return False
            
            # Test ModularCompliance deployment transaction
            print("\n🔍 Checking ModularCompliance deployment transaction...")
            mc_tx = result['modular_compliance_deployment']
            required_tx_fields = ['to', 'data', 'gas', 'gasPrice', 'value', 'chainId']
            
            for field in required_tx_fields:
                if field in mc_tx:
                    print(f"   ✅ {field}: {mc_tx[field]}")
                else:
                    print(f"   ❌ {field}: Missing")
                    return False
            
            # Test add modules transactions
            print("\n🔍 Checking add modules transactions...")
            add_txs = result['add_modules_transactions']
            if len(add_txs) == len(compliance_modules):
                print(f"   ✅ Correct number of add transactions: {len(add_txs)}")
                for i, tx in enumerate(add_txs):
                    print(f"      {i+1}. {tx['module_type']}: {tx['function_name']}")
            else:
                print(f"   ❌ Expected {len(compliance_modules)} add transactions, got {len(add_txs)}")
                return False
            
            # Test configure modules transactions  
            print("\n🔍 Checking configure modules transactions...")
            config_txs = result['configure_modules_transactions']
            if len(config_txs) == len(compliance_modules):
                print(f"   ✅ Correct number of configure transactions: {len(config_txs)}")
                for i, tx in enumerate(config_txs):
                    print(f"      {i+1}. {tx['module_type']}: {tx['function_name']} with {tx['function_params']}")
            else:
                print(f"   ❌ Expected {len(compliance_modules)} configure transactions, got {len(config_txs)}")
                return False
            
            print("\n🎉 All tests passed! Multi-step compliance deployment flow is working correctly.")
            print("\n📋 Flow Summary:")
            print("   1. ✅ Platform deploys individual compliance modules (CountryRestrict, SupplyLimit, TimeTransfers)")
            print("   2. ✅ User deploys ModularCompliance contract (via MetaMask)")
            print("   3. ✅ User adds modules to ModularCompliance (via MetaMask)")
            print("   4. ✅ User configures modules with settings (via MetaMask)")
            print("   5. ✅ User deploys token with ModularCompliance attached (via MetaMask)")
            
            return True
            
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            return False

def test_compliance_module_configurations():
    """Test different compliance module configurations"""
    
    print("\n" + "=" * 60)
    print("🧪 Testing Different Compliance Module Configurations")
    print("=" * 60)
    
    test_configs = [
        {
            'name': 'EU + US Only',
            'modules': [
                {
                    'type': 'CountryRestrictModule',
                    'config': {'allowed_countries': [250, 840]}  # EU + US
                }
            ]
        },
        {
            'name': 'High Security (All modules)',
            'modules': [
                {
                    'type': 'CountryRestrictModule',
                    'config': {'allowed_countries': [250, 840, 156]}  # EU + US + Asia
                },
                {
                    'type': 'SupplyLimitModule',
                    'config': {'supply_limit': 50, 'per_user_limit': True}
                },
                {
                    'type': 'TimeTransfersLimitsModule',
                    'config': {'cooldown_period': 1800}  # 30 minutes
                }
            ]
        },
        {
            'name': 'Minimal (Time-based only)',
            'modules': [
                {
                    'type': 'TimeTransfersLimitsModule',
                    'config': {'cooldown_period': 60}  # 1 minute
                }
            ]
        }
    ]
    
    with app.app_context():
        web3_service = Web3Service()
        trex_service = TREXService(web3_service)
        deployer_address = "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199"
        
        for i, test_config in enumerate(test_configs):
            print(f"\n🔧 Test {i+1}: {test_config['name']}")
            print(f"   Modules: {len(test_config['modules'])}")
            
            try:
                result = trex_service.deploy_compliance_modules(test_config['modules'], deployer_address)
                
                if result['success']:
                    print(f"   ✅ Configuration test passed")
                    print(f"      Deployed: {len(result['deployed_modules'])} modules")
                    print(f"      Add transactions: {len(result['add_modules_transactions'])}")
                    print(f"      Configure transactions: {len(result['configure_modules_transactions'])}")
                else:
                    print(f"   ❌ Configuration test failed: {result['error']}")
                    return False
                    
            except Exception as e:
                print(f"   ❌ Configuration test failed with exception: {e}")
                return False
    
    print(f"\n🎉 All configuration tests passed!")
    return True

if __name__ == "__main__":
    print("🚀 Starting Multi-Step Compliance Deployment Tests")
    print("=" * 60)
    
    # Test 1: Basic compliance transaction building
    test1_passed = test_compliance_transaction_building()
    
    # Test 2: Different compliance configurations
    test2_passed = test_compliance_module_configurations()
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    print(f"✅ Basic Flow Test: {'PASSED' if test1_passed else 'FAILED'}")
    print(f"✅ Configuration Test: {'PASSED' if test2_passed else 'FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 ALL TESTS PASSED! Multi-step compliance deployment is ready for production.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Please review the implementation.")
        sys.exit(1)
