# 🚀 TokenPlatform - RWA Tokenization Platform

## 📖 Introduction

**TokenPlatform** is a new Real-World Asset (RWA) Tokenization platform that demonstrates the implementation of ERC-3643 (T-REX) security token standards using modern blockchain technologies. This platform serves as an educational tool to showcase how enterprise-grade tokenization platforms work in practice.

### 🎯 What We Do Here

This platform recreates actual enterprise tokenization behavior using:
- **T-REX Factory** for token creation and management
- **OnchainID** for identity verification and KYC management
- **OpenZeppelin libraries** for secure smart contract implementations
- **ERC-3643** compliance for security token standards

### 🔧 Current Architecture

The platform currently uses **Account 0 on Hardhat** to act as the platform manager, handling most core functions but not all platform capabilities. This design choice allows for educational demonstration while maintaining security.

### 🚀 Future Improvements & Collaborations Needed

1. **MetaMask Integration**: Implement MetaMask for all transaction signings across the platform
2. **Multi-Factory Deployment**: Deploy T-REX factory contracts for each individual issuer instead of shared platform factory

### 🙏 Special Thanks

**Shout out to the ERC-3643 Association** for their pioneering work in establishing security token standards and making enterprise tokenization accessible to developers worldwide.

---

## 🛠️ Prerequisites

Before you begin, ensure you have the following installed on your system:

- **Git** (for cloning the repository)
- **Node.js** (v16 or higher) - for Hardhat and npm packages
- **Python** (3.8 or higher) - for Flask backend
- **pip** (Python package manager)
- **GitHub account** (for cloning)

---

## 📥 Installation & Setup

### Step 0: Install Node.js and npm


#### Option 1: Install via Package Manager

**Ubuntu/Debian:**
```bash
# Update package list
sudo apt update

# Install Node.js and npm
sudo apt install nodejs npm

# Verify installation
node --version
npm --version
```

#### Option 32: Install via Node Version Manager (Advanced Users)

**nvm (Node Version Manager) - Linux/macOS:**
```bash
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Restart terminal or run:
source ~/.bashrc

# Install latest LTS version
nvm install --lts

# Use the installed version
nvm use --lts




#### Verify installation
node --version
npm --version
```

# Test package installation
npm install -g yarn
yarn --version


### Step 1: Clone the Repository

```bash
# Clone the main repository
git clone https://github.com/yourusername/TokenPlatform.git

# Navigate to the project directory
cd TokenPlatform
```

### Step 2: Install Node.js Dependencies

```bash
# Install Hardhat and related packages
npm install

# Install T-REX dependencies
cd T-REX
npm install
cd ..
```

### Step 3: Set Up Python Environment

```bash
# Create a Python virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

**Note:** The requirements.txt contains only essential dependencies. Flask will automatically install its core dependencies (Werkzeug, Jinja2, etc.) when you install Flask.
```

### Step 4: Environment Configuration

```bash
# Create environment file
cp .env.example .env

# Edit the environment file with your configuration
nano .env
```

**Required Environment Variables:**
```env
# Flask Configuration
SECRET_KEY=your-secret-key-here
FLASK_ENV=development

# Database Configuration
DATABASE_URL=sqlite:///fundraising.db

# Blockchain Configuration
RPC_URL=http://localhost:8545
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# T-REX Configuration
TREX_FACTORY_ADDRESS=your-deployed-factory-address
IDENTITY_REGISTRY_ADDRESS=your-deployed-identity-registry-address
```

### Step 5: Database Setup

```bash
# Initialize the database
python -c "from app import app, db; app.app_context().push(); db.create_all()"

# Run database migrations
python -m flask db upgrade
```

---

## 🚀 Running the Application

### Step 1: Start Hardhat Blockchain

```bash
# Start local Hardhat node
npx hardhat node

# Keep this terminal running - it will show transaction logs
```

### Step 6: Deploy Smart Contracts

```bash
# In a new terminal, deploy contracts
npx hardhat run scripts/deploy.js --network localhost

# This will deploy:
# - T-REX Factory
# - Identity Registry
# - Sample Token
# - OnchainID contracts
```

### Step 7: Start Flask Application

```bash
# Activate virtual environment (if not already active)
source venv/bin/activate

# Start the Flask application
python startup.py

# Or alternatively:
# export FLASK_APP=app.py
# flask run --host=0.0.0.0 --port=5000
```

### Step 8: Access the Platform

Open your web browser and navigate to:
```
http://localhost:5000
```

---

## 🧪 Testing the Platform

### Default Accounts

The platform comes with pre-configured Hardhat accounts:

- **Account 0** (Platform Admin): `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
- **Account 1** (Issuer): `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC`
- **Account 2** (Investor): `0x90F79bf6EB2c4f870365E785982E1f101E93b906`

### Quick Test Flow

1. **Register as Investor** using Account 2
2. **Complete KYC** through the multi-lane verification system
3. **Express Interest** in available tokens
4. **Submit Purchase Request** for token investment
5. **Test Transfer** functionality between verified addresses

---

## 📁 Project Structure

```
TokenPlatform/
├── app.py                          # Main Flask application
├── startup.py                      # Application startup script
├── requirements.txt                # Python dependencies
├── package.json                    # Node.js dependencies
├── hardhat.config.js              # Hardhat configuration
├── contracts/                      # Smart contracts
│   ├── token/                     # Token contracts
│   └── onchainid/                 # OnchainID contracts
├── routes/                         # Flask route handlers
│   ├── admin.py                   # Admin functionality
│   ├── issuer.py                  # Issuer functionality
│   ├── investor.py                # Investor functionality
│   └── trusted_issuer.py          # Trusted issuer functionality
├── services/                       # Business logic services
├── models/                         # Database models
├── templates/                      # HTML templates
├── static/                         # CSS, JS, images
├── scripts/                        # Deployment and utility scripts
├── T-REX/                         # T-REX framework integration
└── migrations/                     # Database migrations
```

---

## 🔧 Configuration Options

### Hardhat Configuration

Edit `hardhat.config.js` to customize:
- Network settings
- Compiler versions
- Gas optimization
- Contract verification

### Flask Configuration

Edit `app.py` to customize:
- Database connections
- Session management
- Security settings
- API endpoints

---

## 🐛 Troubleshooting

### Common Issues

**1. Port Already in Use**
```bash
# Kill process using port 5000
lsof -ti:5000 | xargs kill -9
```

**2. Database Locked**
```bash
# Remove database file and recreate
rm fundraising.db
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

**3. Contract Deployment Failed**
```bash
# Check Hardhat node is running
npx hardhat node

# Verify network configuration
npx hardhat run scripts/deploy.js --network localhost
```

**4. Python Dependencies Issues**
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📚 Learning Resources

- **ERC-3643 Documentation**: [Official T-REX Standard](https://erc3643.org/)
- **OnchainID**: [Identity Management](https://onchainid.com/)
- **OpenZeppelin**: [Smart Contract Libraries](https://openzeppelin.com/)
- **Hardhat**: [Development Framework](https://hardhat.org/)

---

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Development Guidelines

- Follow existing code style
- Add tests for new functionality
- Update documentation
- Ensure all tests pass

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the logs in your terminal
3. Open an issue on GitHub
4. Join our community discussions

---

**Happy Tokenizing! 🚀✨** 