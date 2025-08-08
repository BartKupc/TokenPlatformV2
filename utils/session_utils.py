import secrets
from datetime import datetime
from models import db
from models.session import TabSession
from models.user import User

def get_or_create_tab_session(session_id=None):
    """Get or create a tab session"""
    if not session_id:
        session_id = secrets.token_urlsafe(32)
    
    tab_session = TabSession.query.filter_by(session_id=session_id).first()
    if not tab_session:
        tab_session = TabSession(session_id=session_id)
        db.session.add(tab_session)
        db.session.commit()
    
    # Update last activity
    tab_session.last_activity = datetime.utcnow()
    db.session.commit()
    
    return tab_session

def get_current_user_from_tab_session(session_id):
    """Get current user from tab session"""
    if not session_id:
        return None
    
    tab_session = TabSession.query.filter_by(session_id=session_id).first()
    if tab_session and tab_session.user_id:
        return User.query.get(tab_session.user_id)
    return None

def login_user_to_tab_session(session_id, user):
    """Login user to a specific tab session"""
    tab_session = TabSession.query.filter_by(session_id=session_id).first()
    if tab_session:
        tab_session.user_id = user.id
        tab_session.user_type = user.user_type
        tab_session.wallet_address = user.wallet_address
        tab_session.last_activity = datetime.utcnow()
        db.session.commit()

def logout_user_from_tab_session(session_id):
    """Logout user from a specific tab session"""
    tab_session = TabSession.query.filter_by(session_id=session_id).first()
    if tab_session:
        tab_session.user_id = None
        tab_session.user_type = None
        tab_session.wallet_address = None
        tab_session.last_activity = datetime.utcnow()
        db.session.commit() 