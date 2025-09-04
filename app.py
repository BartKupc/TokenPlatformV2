from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime
import json
import os
import secrets

# Import models
from models import db
from models.user import User, TrustedIssuerCapability, TrustedIssuerApproval, UserOnchainID, UserClaim, TokenClaimRequirement
from models.token import Token, TokenInterest
from models.contract import Contract
from models.session import TabSession

# Import utilities
from utils.auth_utils import hash_password, create_default_admin
from utils.contract_utils import get_contract_address, store_contract
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session, login_user_to_tab_session, logout_user_from_tab_session

# Import services
from services.trex_service import TREXService
from services.web3_service import Web3Service
from services.onchainid_service import OnchainIDService
from services.onchain_claims_service import OnchainClaimsService

# Import routes
from routes.auth import auth_bp
from routes.main import main_bp
from routes.admin import admin_bp
from routes.issuer import issuer_bp
from routes.trusted_issuer import trusted_issuer_bp
from routes.investor import investor_bp
from routes.token import token_bp
from routes.onchainid import onchainid_bp
from routes.kyc_system import kyc_system_bp

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fundraising.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(issuer_bp)
app.register_blueprint(trusted_issuer_bp)
app.register_blueprint(investor_bp)
app.register_blueprint(token_bp)
app.register_blueprint(onchainid_bp)
app.register_blueprint(kyc_system_bp)

# Jinja2 filters
@app.template_filter('datetime')
def datetime_filter(timestamp):
    """Convert Unix timestamp to readable datetime"""
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return 'Unknown'

@app.template_filter('from_json')
def from_json_filter(json_string):
    """Parse JSON string to Python object"""
    if json_string:
        try:
            return json.loads(json_string)
        except:
            return []
    return []

# Helper functions moved to utils/claims_utils.py

# Routes moved to blueprints

# All routes moved to blueprints - keeping only context processor and template filters

# Context processor to make current_user available in all templates
@app.context_processor
def inject_current_user():
    """Inject current_user into all templates"""
    # Clear any old Flask session data
    if 'user_id' in session:
        session.pop('user_id', None)
        session.pop('user_type', None)
        session.pop('wallet_address', None)
    
    tab_session_id = request.args.get('tab_session')
    if tab_session_id:
        current_user = get_current_user_from_tab_session(tab_session_id)
        return {'current_user': current_user}
    return {'current_user': None}

# Initialize database and create default admin
with app.app_context():
    db.create_all()
    create_default_admin()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 