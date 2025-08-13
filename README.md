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
- **Python** (3.8-3.11 recommended, 3.12+ supported with updated packages) - for Flask backend
- **pip** (Python package manager)
- **GitHub account** (for cloning)

**Note:** Python 3.12+ users may need to reinstall dependencies due to package compatibility changes.

---

## 📥 Installation & Setup

### Step 0: Install Node.js and npm


#### Install via Package Manager

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

# Test package installation
npm install -g yarn yarn --version


### Step 1: Clone the Repository

```bash
# Clone the main repository
git clone https://github.com/BartKupc/TokenPlatform.git

# Navigate to the project directory
cd TokenPlatform
```

### Step 2: Install Node.js Dependencies

```bash
# Install Hardhat and related packages
npm install

```

### Step 3: Set Up Python Environment

```bash
# Create a Python virtual environment
sudo apt install python3.12-venv

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


## 🚀 Running the Application

### Step 1: Configure Your Environment

Before starting the platform, configure it for your environment:

#### **For local**
```bash
cd TokenPlatform
echo "EXTERNAL_IP=127.0.0.1" > .env
node scripts/generate-flask-config.js
```

#### **For cloud:**
```bash
cd TokenPlatform
echo "EXTERNAL_IP=************" > .env
node scripts/generate-flask-config.js
```

**Note:** Replace `13.213.37.149` with your actual EC2 public IP address.

### Step 2: Quick Start

Your platform comes with convenient shell scripts for easy startup:

```bash
# First time setup (run once)
./setup.sh

# Start the platform
./start.sh

# Restart the platform (stops, cleans, and starts)
./restart.sh

# Stop the platform
./stop.sh
```

### What the start.sh script does:

1. **Checks dependencies** (virtual environment, Node.js modules)
2. **Starts Hardhat blockchain node**
3. **Deploys T-REX factory contracts**
4. **Launches Flask web application**

### Access the Platform

Once started, open your web browser and navigate to:
```
http://localhost:5000
```

---

## 🧪 Testing the Platform

The platform comes with pre-configured Hardhat test accounts. After starting the application, you can:

1. **Register users** with different roles (Investor, Issuer, Trusted Issuer)
2. **Deploy security tokens** with T-REX compliance
3. **Test the complete investment flow** from token creation to transfer

For detailed testing instructions, see the individual route documentation in the `routes/` directory.

---

## 🔧 Troubleshooting




---

## 🔑 Admin Access

### Default Admin Credentials

The platform includes a default admin account for initial setup:

- **Username:** `admin`
- **Password:** `admin123`

### Accessing Admin Dashboard

1. Navigate to `/admin/login` in your browser
2. Use the default credentials above
3. Access the admin dashboard for:
   - User management
   - Platform oversight
   - Compliance monitoring
   - System administration

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

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the logs in your terminal
3. Open an issue on GitHub
4. Join our community discussions

---
