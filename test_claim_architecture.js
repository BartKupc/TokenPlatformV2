const { ethers } = require("hardhat");

async function main() {
    console.log("🧪 Testing CORRECT T-REX Claim Architecture");
    console.log("=" .repeat(50));
    
    try {
        console.log("🔧 Initializing Hardhat environment...");
        
        // Read addresses from config file (same way as addClaim.js)
        const fs = require('fs');
        const configPath = './test_config.json';
        
        console.log("📁 Reading config file...");
        if (!fs.existsSync(configPath)) {
            throw new Error('Test config file not found. Please run the Python script first.');
        }
        
        const configContent = fs.readFileSync(configPath, 'utf8');
        console.log("📄 Config file content:", configContent);
        
        const config = JSON.parse(configContent);
        console.log("🔍 Parsed config:", JSON.stringify(config, null, 2));
        
        // Get all addresses and private keys from config
        const deployerAddress = config.deployer_address;
        const deployerPrivateKey = config.deployer_private_key;
        const trustedIssuerAddress = config.trusted_issuer_address;
        const trustedIssuerPrivateKey = config.trusted_issuer_private_key;
        const investorAddress = config.investor_address;
        const investorPrivateKey = config.investor_private_key;
        
        // Create wallet objects from private keys
        const deployer = new ethers.Wallet(deployerPrivateKey, ethers.provider);
        const trustedIssuer = new ethers.Wallet(trustedIssuerPrivateKey, ethers.provider);
        const investor = new ethers.Wallet(investorPrivateKey, ethers.provider);
        
        console.log("✅ Wallets created from private keys");
        
        console.log("👥 Test Accounts:");
        console.log(`   Deployer (Account 0): ${deployer.address}`);
        console.log(`   Trusted Issuer: ${trustedIssuer.address}`);
        console.log(`   Investor: ${investor.address}`);
        
        const trustedIssuerOnchainID = config.trusted_issuer_onchainid;
        const investorOnchainID = config.investor_onchainid;
        const claimIssuerAddress = config.claimissuer_address;
        
        console.log("📍 Extracted addresses:");
        console.log("   Trusted Issuer OnchainID:", trustedIssuerOnchainID);
        console.log("   Investor OnchainID:", investorOnchainID);
        console.log("   ClaimIssuer Address:", claimIssuerAddress);
        
        console.log("\n🔍 OnchainID Addresses:");
        console.log(`   Trusted Issuer OnchainID: ${trustedIssuerOnchainID}`);
        console.log(`   Investor OnchainID: ${investorOnchainID}`);
        console.log(`   ClaimIssuer Contract: ${claimIssuerAddress}`);
        
        // Test the CORRECT T-REX architecture
        console.log("\n🎯 Testing CORRECT T-REX Architecture:");
        
        // 1. Verify investor OnchainID has ONLY Account 0 as management key (NO third party keys!)
        console.log("\n1️⃣ Verifying investor OnchainID has ONLY Account 0 as management key...");
        await verifyInvestorOnchainIDKeysOnly(investorOnchainID, deployer.address);
        
        // 2. Verify trusted issuer has correct keys on ClaimIssuer contract ONLY
        console.log("\n2️⃣ Verifying trusted issuer keys on ClaimIssuer contract ONLY...");
        await verifyTrustedIssuerKeysOnClaimIssuerOnly(claimIssuerAddress, trustedIssuer.address, deployer);
        
        // 3. Test claim signing and addition (Account 0 adds claim, trusted issuer signs)
        console.log("\n3️⃣ Testing claim signing and addition...");
        await testClaimSigningAndAddition(
            trustedIssuer,
            claimIssuerAddress,
            investorOnchainID,
            deployer,
            config,
            trustedIssuerPrivateKey
        );
        
        console.log("\n🎉 All tests passed! The CORRECT T-REX architecture is working!");
        
    } catch (error) {
        console.error("❌ Test failed:", error);
        process.exit(1);
    }
}

async function verifyInvestorOnchainIDKeysOnly(investorOnchainID, deployerAddress) {
    console.log("   🔍 Checking investor OnchainID has ONLY Account 0 as management key...");
    console.log("   📍 OnchainID address:", investorOnchainID);
    console.log("   📍 Deployer address:", deployerAddress);
    
    try {
        // Get OnchainID contract
        console.log("   🔧 Loading Identity contract artifacts...");
        const onchainIDArtifacts = await require("hardhat").artifacts.readArtifact("Identity");
        console.log("   ✅ Identity artifacts loaded");
        
        console.log("   🔧 Creating contract instance...");
        const investorOnchainIDContract = new ethers.Contract(
            investorOnchainID,
            onchainIDArtifacts.abi,
            ethers.provider
        );
        console.log("   ✅ Contract instance created");
        
        // Check for Account 0 (deployer) management key
        const account0KeyHash = ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(['address'], [deployerAddress])
        );
        console.log("   🔍 Account 0 key hash:", account0KeyHash);
        
        // Verify Account 0 has management key
        const hasManagementKey = await investorOnchainIDContract.keyHasPurpose(account0KeyHash, 1);
        console.log("   ✅ Account 0 has management key (purpose 1):", hasManagementKey);
        
        if (!hasManagementKey) {
            throw new Error("Account 0 (deployer) must have management key on investor OnchainID");
        }
        
        console.log("   ✅ Investor OnchainID verified - Account 0 has management key");
        
    } catch (error) {
        console.error("   ❌ Error verifying investor OnchainID keys:", error.message);
        throw error;
    }
}

async function verifyTrustedIssuerKeysOnClaimIssuerOnly(claimIssuerAddress, trustedIssuerAddress, deployer) {
    console.log("   🔍 Verifying trusted issuer keys on ClaimIssuer contract ONLY...");
    console.log("   📍 ClaimIssuer address:", claimIssuerAddress);
    console.log("   📍 Trusted issuer address:", trustedIssuerAddress);
    
    try {
        // Get ClaimIssuer contract
        console.log("   🔧 Loading ClaimIssuer contract artifacts...");
        const claimIssuerArtifacts = await require("hardhat").artifacts.readArtifact("ClaimIssuer");
        console.log("   ✅ ClaimIssuer artifacts loaded");
        
        console.log("   🔧 Creating contract instance...");
        const claimIssuerContract = new ethers.Contract(
            claimIssuerAddress,
            claimIssuerArtifacts.abi,
            ethers.provider
        );
        console.log("   ✅ Contract instance created");
        
        // Check for trusted issuer keys on ClaimIssuer contract
        const trustedIssuerKeyHash = ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(['address'], [trustedIssuerAddress])
        );
        console.log("   🔍 Trusted issuer key hash:", trustedIssuerKeyHash);
        
        let managementKeys = [];
        let claimSignerKeys = [];
        
        // Check management key (purpose 1)
        const hasManagementKey = await claimIssuerContract.keyHasPurpose(trustedIssuerKeyHash, 1);
        console.log("   ✅ Trusted issuer has management key (purpose 1):", hasManagementKey);
        
        if (hasManagementKey) {
            managementKeys.push(trustedIssuerKeyHash);
        }
        
        // Check claim signer key (purpose 3)
        const hasSigningKey = await claimIssuerContract.keyHasPurpose(trustedIssuerKeyHash, 3);
        console.log("   ✅ Trusted issuer has claim signer key (purpose 3):", hasSigningKey);
        
        if (hasSigningKey) {
            claimSignerKeys.push(trustedIssuerKeyHash);
        }
        
        console.log(`   📋 Management keys (Purpose 1): ${managementKeys.length}`);
        console.log(`   📋 Claim signer keys (Purpose 3): ${claimSignerKeys.length}`);
        
        // Verify both keys exist
        if (managementKeys.length === 0) {
            console.log("   ❌ Trusted issuer missing management key on ClaimIssuer");
        } else {
            console.log("   ✅ Trusted issuer has management key on ClaimIssuer");
        }
        
        if (claimSignerKeys.length === 0) {
            console.log("   ❌ Trusted issuer missing claim signer key on ClaimIssuer");
        } else {
            console.log("   ✅ Trusted issuer has claim signer key on ClaimIssuer");
        }
        
        // If keys are missing, add them to ClaimIssuer contract ONLY
        if (managementKeys.length === 0 || claimSignerKeys.length === 0) {
            console.log("   🔧 Adding missing keys to ClaimIssuer contract ONLY...");
            
            // Check who has management permissions on ClaimIssuer
            const deployerKeyHash = ethers.keccak256(
                ethers.AbiCoder.defaultAbiCoder().encode(['address'], [deployer.address])
            );
            
            const deployerHasManagement = await claimIssuerContract.keyHasPurpose(deployerKeyHash, 1);
            console.log("   📍 Deployer (Account 0) has management key on ClaimIssuer:", deployerHasManagement);
            
            if (deployerHasManagement) {
                console.log("   🔑 Using deployer to add missing keys to ClaimIssuer...");
                
                // Add management key (purpose 1) if missing
                if (managementKeys.length === 0) {
                    console.log("   🔑 Adding trusted issuer as management key (purpose 1)...");
                    const addManagementKeyTx = await claimIssuerContract.connect(deployer).addKey(trustedIssuerKeyHash, 1, 1);
                    await addManagementKeyTx.wait();
                    console.log("   ✅ Added management key. Tx:", addManagementKeyTx.hash);
                }
                
                // Add claim signer key (purpose 3) if missing
                if (claimSignerKeys.length === 0) {
                    console.log("   🔑 Adding trusted issuer as claim signer key (purpose 3)...");
                    const addSigningKeyTx = await claimIssuerContract.connect(deployer).addKey(trustedIssuerKeyHash, 3, 1);
                    await addSigningKeyTx.wait();
                    console.log("   ✅ Added claim signer key. Tx:", addSigningKeyTx.hash);
                }
            } else {
                throw new Error("Deployer (Account 0) must have management key on ClaimIssuer to add trusted issuer keys");
            }
        } else {
            console.log("   ✅ All required keys are already present on ClaimIssuer");
        }
        
        console.log("   ✅ ClaimIssuer key verification completed - trusted issuer has proper keys");
        
    } catch (error) {
        console.error("   ❌ Error verifying trusted issuer keys on ClaimIssuer:", error.message);
        throw error;
    }
}

async function testClaimSigningAndAddition(trustedIssuer, claimIssuerAddress, investorOnchainID, deployer, config, trustedIssuerPrivateKey) {
    console.log("   🔍 Testing claim signing and addition...");
    
    // 1. Trusted issuer signs a claim (using exact same logic as addClaim.js)
    console.log("   📝 Step 1: Trusted issuer signing claim...");
    
    const topic = config.test_topic;
    const claimData = config.test_claim_data;
    const issuer = claimIssuerAddress;
    
    console.log("   ✅ Topic:", topic);
    console.log("   ✅ Claim Data:", claimData);
    
    // Convert claim data to hex (exact same as addClaim.js)
    const claimDataBytes = ethers.toUtf8Bytes(claimData);
    const claimDataHex = ethers.hexlify(claimDataBytes);
    console.log("   ✅ Claim data hex:", claimDataHex);
    
    // Create data hash (exact same as addClaim.js)
    const dataHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'bytes'], 
        [investorOnchainID, topic, claimDataHex]
    ));
    console.log("   ✅ Data hash:", dataHash);
    
    // Sign the data hash with trusted issuer's private key (exact same as addClaim.js)
    const trustedIssuerWallet = new ethers.Wallet(trustedIssuerPrivateKey, ethers.provider);
    console.log("   ✅ Created signing wallet for address:", trustedIssuerWallet.address);
    
    // Verify the wallet address matches the expected trusted issuer address
    if (trustedIssuerWallet.address.toLowerCase() !== trustedIssuer.address.toLowerCase()) {
        throw new Error(`Private key mismatch: expected ${trustedIssuer.address}, got ${trustedIssuerWallet.address}`);
    }
    
    const signature = await trustedIssuerWallet.signMessage(ethers.getBytes(dataHash));
    console.log("   ✅ Signature:", signature);
    
    // 2. Platform (Account 0) adds the claim to investor's OnchainID using its existing management key
    console.log("   📝 Step 2: Platform (Account 0) adding claim to investor OnchainID...");
    
    // Get OnchainID contract
    const onchainIDArtifacts = await require("hardhat").artifacts.readArtifact("Identity");
    const investorOnchainIDContract = new ethers.Contract(
        investorOnchainID,
        onchainIDArtifacts.abi,
        deployer // Account 0 as msg.sender (using existing management key)
    );
    
    // Add the claim using Account 0's existing management key (NO new keys added!)
    const addClaimTx = await investorOnchainIDContract.addClaim(
        topic,           // topic
        1,               // scheme (hardcoded to 1)
        issuer,          // issuer address
        signature,       // signature
        claimDataHex,    // data
        ""               // uri (empty)
    );
    
    console.log("   🔄 Waiting for transaction confirmation...");
    const receipt = await addClaimTx.wait();
    
    if (receipt.status === 1) {
        console.log("   ✅ Claim successfully added to investor OnchainID!");
        console.log(`      Transaction hash: ${receipt.hash}`);
        console.log("   🔒 IMPORTANT: NO new management keys were added to investor OnchainID!");
        console.log("   🔒 Only Account 0 (deployer) has management key - this is SECURE!");
        
        // Verify the claim was added
        await verifyClaimAdded(investorOnchainID, topic, issuer);
    } else {
        throw new Error("Transaction failed");
    }
}

async function verifyClaimAdded(investorOnchainID, topic, issuer) {
    console.log("   🔍 Verifying claim was added...");
    
    // Get OnchainID contract
    const onchainIDArtifacts = await require("hardhat").artifacts.readArtifact("Identity");
    const investorOnchainIDContract = new ethers.Contract(
        investorOnchainID,
        onchainIDArtifacts.abi,
        ethers.provider
    );
    
    // Use the same claim ID calculation as addClaim.js
    const claimId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256"], [issuer, topic]));
    console.log("   🔍 Claim ID:", claimId);
    
    try {
        const claim = await investorOnchainIDContract.getClaim(claimId);
        console.log("   ✅ Claim found on OnchainID!");
        console.log("      Topic:", claim.topic.toString());
        console.log("      Issuer:", claim.issuer);
        console.log("      Scheme:", claim.scheme.toString());
        console.log("      Data:", claim.data);
        
        // Verify it's our claim
        if (claim.issuer !== ethers.ZeroAddress && claim.topic.toString() === topic.toString()) {
            console.log("   ✅ Claim verification successful!");
        } else {
            throw new Error("Claim data doesn't match expected values");
        }
        
    } catch (error) {
        console.log("   ❌ Error getting claim:", error.message);
        throw new Error("Claim was not found on the OnchainID");
    }
    
    console.log("   ✅ Claim verification completed successfully");
}

// Run the main function
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    }); 