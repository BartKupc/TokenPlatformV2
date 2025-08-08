# Token Platform - ERC-3643 Compliant Fundraising App

A Flask-based tokenized fundraising platform built on the T-REX (Token for Regulated EXchanges) ERC-3643 standard. This platform enables startups to deploy compliant security tokens and allows only KYC-verified investors to purchase tokens.

## 🎯 Features

### For Startups (Issuers)
- **Token Deployment**: Deploy compliant security tokens with built-in KYC requirements
- **Dashboard**: Manage tokens, view investor statistics, and monitor fundraising progress
- **Compliance Management**: Automatic compliance enforcement through ERC-3643 contracts
- **Analytics**: Track fundraising progress and investor distribution

### For Investors
- **KYC Onboarding**: Complete identity verification process
- **Compliance Verification**: Automatic checks before token purchases
- **Token Purchase**: Buy tokens only if compliant
- **Portfolio Management**: Track investments and token balances

### Technical Features
- **ERC-3643 Standard**: Full implementation of T-REX compliance framework
- **Python/Flask Backend**: Modern web framework with web3.py integration
- **SQLite Database**: Lightweight database for user management
- **Bootstrap UI**: Responsive, modern user interface
- **Real-time Compliance**: On-chain compliance verification

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+**
2. **Node.js & npm** (for Hardhat and T-REX contracts)
3. **T-REX Project** (already set up in `/mnt/ethnode/T-REX`)

### One-Command Setup & Start

The Token Platform includes automated setup and startup scripts that handle everything for you:

#### First Time Setup
```bash
cd /mnt/ethnode/TokenPlatform
./setup.sh
```

#### Start the Platform
```bash
cd /mnt/ethnode/TokenPlatform
./start.sh
```

#### Stop the Platform
```bash
cd /mnt/ethnode/TokenPlatform
./stop.sh
```

#### Restart the Platform
```bash
cd /mnt/ethnode/TokenPlatform
./restart.sh
```

#### Check Platform Status
```bash
cd /mnt/ethnode/TokenPlatform
./status.sh
```

That's it! The startup script will:
1. ✅ Start Hardhat blockchain node
2. ✅ Deploy T-REX factory and contracts
3. ✅ Copy contract addresses to Token Platform
4. ✅ Start Flask web application
5. ✅ Open the platform at `http://localhost:5000`

### Manual Setup (Alternative)

If you prefer manual setup:

1. **Install Dependencies**
```bash
cd /mnt/ethnode/TokenPlatform
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Setup Contracts**
```bash
python setup_contracts.py
```

3. **Start Platform**
```bash
python startup.py
```

## 📋 Usage Guide

### For Startups (Issuers)

1. **Register as Issuer**
   - Visit `http://localhost:5000/issuer/register`
   - Enter your wallet address and email
   - Complete registration

2. **Login to Dashboard**
   - Visit `http://localhost:5000/issuer/login`
   - Enter your wallet address
   - Access issuer dashboard

3. **Deploy Token**
   - Navigate to "Deploy Token" tab
   - Fill in token details (name, symbol, supply, price)
   - Submit deployment
   - Token will be deployed with KYC compliance requirements

4. **Manage Investors**
   - Review pending KYC applications
   - Approve/reject investor verifications
   - Monitor fundraising progress

### For Investors

1. **Start KYC Process**
   - Visit `http://localhost:5000/investor/onboarding`
   - Connect wallet or enter wallet address
   - Complete KYC form with personal information
   - Submit for verification

2. **Wait for Approval**
   - KYC applications are reviewed manually
   - Approval typically takes 24-48 hours
   - Check status at `/investor/status`

3. **Purchase Tokens**
   - Once approved, browse available tokens
   - Select tokens to purchase
   - Complete transaction (only if compliant)

## 🏗️ Architecture

```
TokenPlatform/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── startup.py            # Automated startup script
├── setup.sh              # Setup script
├── start.sh              # Start script
├── requirements.txt      # Python dependencies
├── templates/           # HTML templates
│   ├── base.html
│   ├── home.html
│   ├── issuer_dashboard.html
│   └── investor_onboarding.html
├── services/            # Business logic services
│   ├── web3_service.py
│   ├── trex_service.py
│   └── auth_service.py
├── static/              # Static assets (CSS, JS, images)
├── contracts/           # Contract ABIs and addresses
└── database/            # Database files
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///fundraising.db

# Blockchain Configuration
RPC_URL=http://localhost:8545
CHAIN_ID=31337

# Contract Addresses (auto-loaded from deployments.json)
TREX_FACTORY_ADDRESS=0x...
IDENTITY_REGISTRY_ADDRESS=0x...
CLAIM_TOPICS_REGISTRY_ADDRESS=0x...
TRUSTED_ISSUERS_REGISTRY_ADDRESS=0x...

# Gas Settings
GAS_LIMIT=3000000
GAS_PRICE=20000000000

# KYC Claim Topics
KYC_CLAIM_TOPIC=1
AML_CLAIM_TOPIC=2
ACCREDITED_INVESTOR_TOPIC=3
```

## 🔒 Security Features

### Compliance Enforcement
- **KYC Verification**: Required for all investors
- **On-chain Claims**: Verifiable compliance claims stored on blockchain
- **Transfer Restrictions**: Automatic compliance checks before token transfers
- **Identity Management**: Self-sovereign identity with OnchainID

### Data Protection
- **Encrypted Storage**: Sensitive data encrypted in database
- **Secure Sessions**: Flask session management with secure cookies
- **Input Validation**: All user inputs validated and sanitized
- **CSRF Protection**: Built-in CSRF protection for forms

## 📊 API Endpoints

### Authentication
- `POST /issuer/login` - Issuer login
- `POST /issuer/register` - Issuer registration
- `POST /logout` - Logout

### Token Management
- `GET /` - Home page with token listings
- `POST /issuer/deploy-token` - Deploy new token
- `GET /issuer/dashboard` - Issuer dashboard

### Investor Management
- `POST /investor/onboarding` - Submit KYC application
- `GET /investor/status` - Check KYC status
- `POST /investor/purchase/<token_id>` - Purchase tokens

### API Endpoints
- `GET /api/token/<address>/balance/<wallet>` - Get token balance
- `GET /api/compliance/check/<wallet>` - Check compliance status
- `GET /api/token/<address>/info` - Get token information

### Admin Functions
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/kyc-approve/<user_id>` - Approve KYC
- `GET /admin/kyc-reject/<user_id>` - Reject KYC

## 🧪 Testing

### Manual Testing

1. **Startup Flow**
   - Run `./start.sh`
   - Verify Hardhat node starts on port 8545
   - Verify Flask app starts on port 5000
   - Check that contracts are deployed

2. **Issuer Flow**
   - Register as issuer
   - Deploy a token
   - Verify token appears on home page

3. **Investor Flow**
   - Complete KYC onboarding
   - Wait for approval (or approve manually as admin)
   - Attempt to purchase tokens

4. **Compliance Testing**
   - Try to purchase tokens without KYC approval
   - Verify transaction is blocked
   - Approve KYC and retry purchase

## 🚀 Deployment

### Production Deployment

1. **Set Environment Variables**
```bash
export FLASK_ENV=production
export SECRET_KEY=your-production-secret-key
export DATABASE_URL=postgresql://...
```

2. **Use Production WSGI Server**
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

3. **Set Up Reverse Proxy**
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Check the documentation
- Review the code comments
- Open an issue on GitHub
- Contact the development team

## 🔗 Related Projects

- **[T-REX Framework](https://github.com/tokeny/T-REX)**: The underlying ERC-3643 standard
- **[OnchainID](https://onchainid.com/)**: Self-sovereign identity solution
- **[Hardhat](https://hardhat.org/)**: Ethereum development environment

---

**Happy Tokenizing! 🚀** 