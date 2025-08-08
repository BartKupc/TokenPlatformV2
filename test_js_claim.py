#!/usr/bin/env python3
"""
Test script for the JavaScript addClaim.js script.
Tests adding a claim with topic 2 using the current setup.
"""

import os
import sys
import subprocess
import json

def test_js_claim():
    """
    Test the JavaScript addClaim.js script with topic 2.
    """
    print("🧪 TESTING JAVASCRIPT CLAIM SCRIPT")
    print("=" * 50)
    
    # Current setup addresses from your output
    investor_onchainid = "0xf5E926037b19EDd3d270dB603EC84D8435F19007"
    trusted_issuer_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    claim_issuer_address = "0x057ef64E23666F000b34aE31332854aCBd1c8544"
    topic = 2  # Testing topic 2
    claim_data = "AML_PASSED"  # More descriptive data
    
    print(f"🔍 Testing with:")
    print(f"   Investor OnchainID: {investor_onchainid}")
    print(f"   Trusted Issuer: {trusted_issuer_address}")
    print(f"   ClaimIssuer: {claim_issuer_address}")
    print(f"   Topic: {topic}")
    print(f"   Claim Data: {claim_data}")
    print()
    
    # Create configuration for JavaScript
    config = {
        "investorOnchainID": investor_onchainid,
        "trustedIssuerAddress": trusted_issuer_address,
        "claimIssuerAddress": claim_issuer_address,
        "topic": topic,
        "claimData": claim_data
    }
    
    # Create temporary config file in scripts directory
    config_file = os.path.join("scripts", "claim_config.json")
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"🔧 Created config file: {config_file}")
    print(f"🔧 Configuration:")
    print(f"   investorOnchainID: {investor_onchainid}")
    print(f"   trustedIssuerAddress: {trusted_issuer_address}")
    print(f"   claimIssuerAddress: {claim_issuer_address}")
    print(f"   topic: {topic}")
    print(f"   claimData: {claim_data}")
    print()
    
    # Prepare command
    cmd = [
        "npx", "hardhat", "run", "addClaim.js",
        "--network", "localhost"
    ]
    
    print(f"🔧 Running command: {' '.join(cmd)}")
    print()
    
    try:
        # Run the JavaScript script
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd="scripts"  # Run from scripts directory
        )
        
        print("📤 JavaScript output:")
        print(result.stdout)
        
        if result.stderr:
            print("⚠️ JavaScript errors:")
            print(result.stderr)
        
        # Check if successful
        if result.returncode == 0:
            print("✅ JavaScript script completed successfully!")
            
            # Try to parse JSON result
            try:
                lines = result.stdout.split('\n')
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
                    js_result = json.loads(json_output)
                    
                    if js_result.get('success'):
                        print("🎉 Claim addition successful!")
                        print(f"   Transaction Hash: {js_result.get('transactionHash')}")
                        print(f"   Claim ID: {js_result.get('claimId')}")
                        print(f"   Topic: {js_result.get('claim', {}).get('topic')}")
                        print(f"   Data: {js_result.get('claim', {}).get('data')}")
                        return True
                    else:
                        print(f"❌ Claim addition failed: {js_result.get('error')}")
                        return False
                else:
                    print("⚠️ Could not find JSON result in output")
                    return False
                    
            except json.JSONDecodeError as e:
                print(f"⚠️ Could not parse JSON result: {e}")
                return False
                
        else:
            print(f"❌ JavaScript script failed with return code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"❌ Error running JavaScript script: {e}")
        return False
        
    finally:
        # Clean up config file
        try:
            if os.path.exists(config_file):
                os.remove(config_file)
                print(f"🧹 Cleaned up config file: {config_file}")
        except Exception as e:
            print(f"⚠️ Could not clean up config file: {e}")

if __name__ == "__main__":
    # Run the test
    success = test_js_claim()
    
    if success:
        print("\n✅ JavaScript test passed!")
        sys.exit(0)
    else:
        print("\n❌ JavaScript test failed!")
        sys.exit(1) 