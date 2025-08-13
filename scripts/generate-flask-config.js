const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Get external IP from environment variable with fallback
const externalIP = process.env.EXTERNAL_IP || '127.0.0.1';
const flaskPort = process.env.FLASK_PORT || '5000';
const hardhatPort = process.env.HARDHAT_PORT || '8545';

// Configuration object
const config = {
  EXTERNAL_IP: externalIP,
  FLASK_PORT: flaskPort,
  HARDHAT_PORT: hardhatPort,
  FLASK_URL: `http://${externalIP}:${flaskPort}`,
  HARDHAT_URL: `http://${externalIP}:${hardhatPort}`,
  LOCAL_FLASK_URL: `http://127.0.0.1:${flaskPort}`,
  LOCAL_HARDHAT_URL: `http://127.0.0.1:${hardhatPort}`
};

// Generate root config.json
const rootConfigPath = path.join(__dirname, '..', 'config.json');
fs.writeFileSync(rootConfigPath, JSON.stringify(config, null, 2));
console.log(`✅ Generated ${rootConfigPath}`);

// Generate Flask config.py
const flaskConfigPath = path.join(__dirname, '..', 'config.py');
const flaskConfigContent = `# Flask Configuration - Auto-generated
# To change, update EXTERNAL_IP in .env and run: node scripts/generate-flask-config.js

EXTERNAL_IP = "${externalIP}"
FLASK_PORT = ${flaskPort}
HARDHAT_PORT = ${hardhatPort}
FLASK_URL = "http://${externalIP}:${flaskPort}"
HARDHAT_URL = "http://${externalIP}:${hardhatPort}"
LOCAL_FLASK_URL = "http://127.0.0.1:${flaskPort}"
LOCAL_HARDHAT_URL = "http://127.0.0.1:${hardhatPort}"

# Use external IP for production, localhost for development
USE_EXTERNAL_IP = ${externalIP !== '127.0.0.1' ? 'True' : 'False'}
`;

fs.writeFileSync(flaskConfigPath, flaskConfigContent);
console.log(`✅ Generated ${flaskConfigPath}`);

console.log(`\n📋 Configuration generated:`);
console.log(`   🌐 External IP: ${externalIP}`);
console.log(`   🚀 Flask URL: http://${externalIP}:${flaskPort}`);
console.log(`   🔗 Hardhat URL: http://${externalIP}:${hardhatPort}`);
console.log(`   💡 To change, update EXTERNAL_IP in your .env file and run this script again.`);
console.log(`   🔧 For Raspberry Pi: EXTERNAL_IP=127.0.0.1`);
console.log(`   🔧 For EC2: EXTERNAL_IP=13.213.37.149`);