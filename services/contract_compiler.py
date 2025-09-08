#!/usr/bin/env python3
"""
Contract compilation service for compliance modules
"""

import json
import subprocess
import os
from pathlib import Path

class ContractCompiler:
    """Service for compiling Solidity contracts"""
    
    def __init__(self):
        self.contracts_dir = Path(__file__).parent.parent / 'contracts'
        self.compiled_dir = Path(__file__).parent.parent / 'compiled_contracts'
        self.compiled_dir.mkdir(exist_ok=True)
        
        # Compliance module contracts
        self.compliance_modules = {
            'CountryRestrictModule': 'compliance/modular/modules/CountryRestrictModule.sol',
            'SupplyLimitModule': 'compliance/modular/modules/SupplyLimitModule.sol',
            'TimeTransfersLimitsModule': 'compliance/modular/modules/TimeTransfersLimitsModule.sol'
        }
    
    def compile_all_compliance_modules(self):
        """Compile all compliance modules and store bytecode/ABI"""
        print("🔧 Compiling all compliance modules...")
        
        results = {}
        
        for module_name, contract_path in self.compliance_modules.items():
            print(f"   Compiling {module_name}...")
            
            try:
                result = self.compile_contract(contract_path)
                if result['success']:
                    results[module_name] = result
                    print(f"   ✅ {module_name} compiled successfully")
                else:
                    print(f"   ❌ {module_name} compilation failed: {result['error']}")
                    
            except Exception as e:
                print(f"   ❌ {module_name} compilation error: {e}")
                results[module_name] = {'success': False, 'error': str(e)}
        
        # Save compiled results
        self.save_compiled_contracts(results)
        return results
    
    def compile_contract(self, contract_path):
        """Compile a single Solidity contract"""
        try:
            full_path = self.contracts_dir / contract_path
            
            if not full_path.exists():
                return {'success': False, 'error': f'Contract file not found: {full_path}'}
            
            # Use solc to compile the contract
            cmd = [
                'solc',
                '--optimize',
                '--optimize-runs', '200',
                '--combined-json', 'abi,bin',
                '--allow-paths', str(self.contracts_dir),
                str(full_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.contracts_dir)
            
            if result.returncode != 0:
                return {
                    'success': False, 
                    'error': f'Solc compilation failed: {result.stderr}'
                }
            
            # Parse the output
            compiled_data = json.loads(result.stdout)
            
            # Extract contract data
            contract_name = Path(contract_path).stem
            contract_data = compiled_data['contracts'].get(f'{contract_path}:{contract_name}')
            
            if not contract_data:
                return {'success': False, 'error': 'Contract not found in compilation output'}
            
            return {
                'success': True,
                'bytecode': contract_data['bin'],
                'abi': json.loads(contract_data['abi']),
                'contract_name': contract_name
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Compilation error: {e}'}
    
    def save_compiled_contracts(self, results):
        """Save compiled contracts to disk"""
        for module_name, result in results.items():
            if result['success']:
                # Save bytecode
                bytecode_file = self.compiled_dir / f'{module_name}_bytecode.json'
                with open(bytecode_file, 'w') as f:
                    json.dump({
                        'bytecode': result['bytecode'],
                        'contract_name': result['contract_name']
                    }, f, indent=2)
                
                # Save ABI
                abi_file = self.compiled_dir / f'{module_name}_abi.json'
                with open(abi_file, 'w') as f:
                    json.dump(result['abi'], f, indent=2)
                
                print(f"   💾 Saved {module_name} bytecode and ABI")
    
    def get_compiled_contract(self, module_name):
        """Get pre-compiled contract data"""
        try:
            bytecode_file = self.compiled_dir / f'{module_name}_bytecode.json'
            abi_file = self.compiled_dir / f'{module_name}_abi.json'
            
            if not bytecode_file.exists() or not abi_file.exists():
                return None
            
            with open(bytecode_file, 'r') as f:
                bytecode_data = json.load(f)
            
            with open(abi_file, 'r') as f:
                abi_data = json.load(f)
            
            return {
                'bytecode': bytecode_data['bytecode'],
                'abi': abi_data,
                'contract_name': bytecode_data['contract_name']
            }
            
        except Exception as e:
            print(f"Error loading compiled contract {module_name}: {e}")
            return None

if __name__ == "__main__":
    compiler = ContractCompiler()
    results = compiler.compile_all_compliance_modules()
    
    print("\n📊 Compilation Summary:")
    for module_name, result in results.items():
        status = "✅ Success" if result['success'] else f"❌ Failed: {result.get('error', 'Unknown error')}"
        print(f"   {module_name}: {status}")
