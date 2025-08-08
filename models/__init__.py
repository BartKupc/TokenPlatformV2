# Models package
from flask_sqlalchemy import SQLAlchemy

# Create a single database instance for all models
db = SQLAlchemy()

# Import all models
from .user import User, TrustedIssuerCapability, TrustedIssuerApproval, UserOnchainID, UserClaim, TokenClaimRequirement
from .session import TabSession
from .contract import Contract
from .token import Token, TokenInterest, TokenPurchaseRequest, TokenTransaction, InvestorVerification 