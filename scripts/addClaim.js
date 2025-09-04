// addClaim.js - CORRECT T-REX Architecture for adding claims
// This script follows the SECURE architecture where:
// - Investor OnchainID has ONLY Account 0 (deployer) as management key
// - Trusted issuer keys are ONLY on ClaimIssuer contract
// - Platform (Account 0) adds claims using its existing management key
// - NO third-party management keys are added to investor OnchainID
// This can be called as a subprocess from Python

const { ethers } = require("hardhat");

async function addClaim(investorOnchainID, trustedIssuerAddress, claimIssuerAddress, trustedIssuerPrivateKey, topic = 1, claimData = "1") {
    try {
        console.log("🚀 Starting claim addition process...");
        
        // STEP 1: SETUP
        const Identity = await ethers.getContractFactory("Identity");
        console.log("✅ Identity factory created");

        const investorOnchainIDContract = Identity.attach(investorOnchainID);
        console.log("✅ Investor OnchainID attached:", investorOnchainIDContract.target);

        const [deployer] = await ethers.getSigners();
        console.log("✅ Deployer address:", deployer.address);
        console.log("✅ Trusted issuer address:", trustedIssuerAddress);
        console.log("✅ Using ClaimIssuer address:", claimIssuerAddress);

        // STEP 2: VERIFY PERMISSIONS (NO KEY ADDITIONS TO INVESTOR ONCHAINID!)
        console.log("🔐 Verifying permissions (CORRECT T-REX architecture)...");
        
        // CRITICAL: Verify Account 0 (deployer) has management key on investor OnchainID
        const deployerKeyHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address'], [deployer.address]));
        const hasDeployerManagementKey = await investorOnchainIDContract.keyHasPurpose(deployerKeyHash, 1);
        console.log("✅ Account 0 (deployer) has management key on investor OnchainID:", hasDeployerManagementKey);
        
        if (!hasDeployerManagementKey) {
            throw new Error("SECURITY VIOLATION: Account 0 (deployer) must have management key on investor OnchainID!");
        }
        
        // CRITICAL: Verify NO third-party management keys exist on investor OnchainID
        console.log("🔒 Verifying NO third-party management keys on investor OnchainID...");
        
        // Check ClaimIssuer does NOT have management key (should not be added)
        const claimIssuerKeyHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address'], [claimIssuerAddress]));
        const hasClaimIssuerManagementKey = await investorOnchainIDContract.keyHasPurpose(claimIssuerKeyHash, 1);
        console.log("✅ ClaimIssuer management key on investor OnchainID:", hasClaimIssuerManagementKey);
        
        if (hasClaimIssuerManagementKey) {
            console.log("⚠️ WARNING: ClaimIssuer has management key on investor OnchainID (this should not happen in production)");
        }
        
        // Check trusted issuer does NOT have management key (should not be added)
        const trustedIssuerManagementKeyHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address'], [trustedIssuerAddress]));
        const hasTrustedIssuerManagementKey = await investorOnchainIDContract.keyHasPurpose(trustedIssuerManagementKeyHash, 1);
        console.log("✅ Trusted issuer management key on investor OnchainID:", hasTrustedIssuerManagementKey);
        
        if (hasTrustedIssuerManagementKey) {
            console.log("⚠️ WARNING: Trusted issuer has management key on investor OnchainID (this should not happen in production)");
        }
        
        console.log("🔒 SECURITY: Investor OnchainID should ONLY have Account 0 as management key");

        // Check trusted issuer signing key on ClaimIssuer (for claim verification)
        const ClaimIssuer = await ethers.getContractFactory("ClaimIssuer");
        const claimIssuerContract = ClaimIssuer.attach(claimIssuerAddress);

        const trustedIssuerKeyHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address'], [trustedIssuerAddress]));
        const hasSigningKey = await claimIssuerContract.keyHasPurpose(trustedIssuerKeyHash, 3);
        console.log("✅ Trusted issuer signing key on ClaimIssuer:", hasSigningKey);

        if (!hasSigningKey) {
            console.log("🔧 Adding trusted issuer as signing key...");
            // We need to use an account that has management permissions on the ClaimIssuer
            // For now, let's use the deployer account which should have management permissions
            console.log("🔍 Using deployer as management account:", deployer.address);
            
            const addSigningKeyTx = await claimIssuerContract.connect(deployer).addKey(trustedIssuerKeyHash, 3, 1);
            await addSigningKeyTx.wait();
            console.log("✅ Added trusted issuer as signing key. Tx:", addSigningKeyTx.hash);
        }

        // STEP 3: CREATE CLAIM DATA AND HASH
        console.log("📝 Creating claim data and hash...");
        
        console.log("✅ Topic:", topic);
        console.log("✅ Claim Data:", claimData);

        const claimDataBytes = ethers.toUtf8Bytes(claimData);
        console.log("✅ Claim data (bytes):", claimDataBytes);

        const claimDataHex = ethers.hexlify(claimDataBytes);
        console.log("✅ Claim data hex:", claimDataHex);

        const dataHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address', 'uint256', 'bytes'], [investorOnchainIDContract.target, topic, claimDataHex]));
        console.log("✅ Data hash:", dataHash);

        // STEP 4: CREATE SIGNATURE
        console.log("✍️ Creating signature...");
        
        let signature;
        
        // Check if we have a MetaMask signature
        if (global.metamaskSignature && global.metamaskSignature !== "METAMASK_SIGNATURE" && global.metamaskSignature !== "0xMETAMASK_SIGNATURE") {
            console.log("✅ Using MetaMask signature:", global.metamaskSignature);
            signature = global.metamaskSignature;
            
            // Verify the data hash matches
            if (global.dataHash && global.dataHash !== dataHash) {
                console.log("⚠️ WARNING: Data hash mismatch!");
                console.log("   Expected:", dataHash);
                console.log("   Received:", global.dataHash);
            }
        } else {
            // Fallback to private key signing (original behavior)
            console.log("✅ Using private key signing (fallback)");
            
            // Create a wallet from the trusted issuer's private key
            const trustedIssuerWallet = new ethers.Wallet(trustedIssuerPrivateKey);
            console.log("✅ Created wallet from private key for address:", trustedIssuerWallet.address);
            
            // Verify the wallet address matches the expected trusted issuer address
            if (trustedIssuerWallet.address.toLowerCase() !== trustedIssuerAddress.toLowerCase()) {
                throw new Error(`Private key mismatch: expected ${trustedIssuerAddress}, got ${trustedIssuerWallet.address}`);
            }
            
            // Sign the data hash with the trusted issuer's private key
            signature = await trustedIssuerWallet.signMessage(ethers.getBytes(dataHash));
            console.log("✅ Signature:", signature);
        }

        // STEP 5: ADD CLAIM
        console.log("🚀 Adding claim to OnchainID...");
        
        const claimTx = await investorOnchainIDContract.addClaim(topic, 1, claimIssuerAddress, signature, claimDataHex, ""); // Hardcoded scheme=1, uri=""
        console.log("✅ Add claim transaction:", claimTx.hash);

        const receipt = await claimTx.wait();
        console.log("✅ Claim added successfully! Tx:", claimTx.hash);
        console.log("✅ Gas used:", receipt.gasUsed.toString());
        console.log("✅ Block:", receipt.blockNumber);

        // STEP 6: VERIFY CLAIM WAS ADDED
        console.log("🔍 Verifying claim was added...");
        
        const claimId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256"], [claimIssuerAddress, topic]));
        const claim = await investorOnchainIDContract.getClaim(claimId);
        console.log("✅ Claim data:", claim);

        if (claim.issuer !== ethers.ZeroAddress) {
            console.log("✅ Claim successfully added and verified!");
            console.log("✅ Issuer:", claim.issuer);
            console.log("✅ Topic:", claim.topic.toString());
            console.log("✅ Scheme:", claim.scheme.toString());
            console.log("✅ Signature:", claim.signature);
            console.log("✅ Data:", claim.data);
            console.log("✅ URI:", claim.uri);
            
            // Return success result
            return {
                success: true,
                claimId: claimId,
                transactionHash: claimTx.hash,
                claim: {
                    issuer: claim.issuer,
                    topic: claim.topic.toString(),
                    scheme: claim.scheme.toString(),
                    signature: claim.signature,
                    data: claim.data,
                    uri: claim.uri
                }
            };
        } else {
            console.log("❌ Claim not found!");
            return { success: false, error: "Claim not found after addition" };
        }

    } catch (error) {
        console.error("❌ Error in addClaim:", error.message);
        return { success: false, error: error.message };
    }
}

// Main execution
async function main() {
    // Read parameters from temporary JSON file (created by Python)
    const fs = require('fs');
    const path = require('path');
    
    // Look for the config file in the current directory (where Python created it)
    const configFile = path.join(process.cwd(), 'claim_config.json');
    
    if (!fs.existsSync(configFile)) {
        console.error("❌ Configuration file 'claim_config.json' not found");
        console.error("   This file should be created by Python with the required parameters");
        process.exit(1);
    }
    
    let investorOnchainID, trustedIssuerAddress, claimIssuerAddress, trustedIssuerPrivateKey, topic, claimData;
    
    try {
        const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        investorOnchainID = config.investorOnchainID;
        trustedIssuerAddress = config.trustedIssuerAddress;
        claimIssuerAddress = config.claimIssuerAddress;
        trustedIssuerPrivateKey = config.trustedIssuerPrivateKey;
        topic = config.topic || 1;
        claimData = config.claimData || "1";
        
        // Store MetaMask signature and data hash for use in addClaim function
        global.metamaskSignature = config.metamaskSignature;
        global.dataHash = config.dataHash;
        
        if (!investorOnchainID || !trustedIssuerAddress || !claimIssuerAddress || !trustedIssuerPrivateKey) {
            console.error("❌ Missing required parameters in config file:");
            console.error("   investorOnchainID, trustedIssuerAddress, claimIssuerAddress, trustedIssuerPrivateKey");
            process.exit(1);
        }
        
        // Clean up the config file
        fs.unlinkSync(configFile);
        
    } catch (error) {
        console.error("❌ Error reading configuration file:", error.message);
        process.exit(1);
    }

    console.log("🧪 CLAIM ADDITION WITH HARDHAT");
    console.log("=" * 50);
    console.log("🔍 Investor OnchainID:", investorOnchainID);
    console.log("🔍 Trusted Issuer:", trustedIssuerAddress);
    console.log("🔍 ClaimIssuer:", claimIssuerAddress);
    console.log("🔍 Topic:", topic);
    console.log("🔍 Claim Data:", claimData);
    console.log("🔍 Scheme: 1 (ECDSA) - hardcoded");
    console.log("🔍 URI: '' - hardcoded");
    console.log();

    const result = await addClaim(investorOnchainID, trustedIssuerAddress, claimIssuerAddress, trustedIssuerPrivateKey, topic, claimData);
    
    // Output result as JSON for Python to parse
    console.log("\n🎯 RESULT:");
    console.log(JSON.stringify(result, null, 2));
    
    if (result.success) {
        process.exit(0);
    } else {
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error("❌ Script failed:", error);
            process.exit(1);
        });
}

module.exports = { addClaim }; 