from flask import Blueprint, render_template, request
from models.token import Token
from utils.session_utils import get_or_create_tab_session, get_current_user_from_tab_session

token_bp = Blueprint('token', __name__, url_prefix='/token')

@token_bp.route('/view/<int:token_id>')
def view(token_id):
    """View token details"""
    # Get tab session ID from URL parameter
    tab_session_id = request.args.get('tab_session')
    
    # Get or create tab session
    tab_session = get_or_create_tab_session(tab_session_id)
    
    # Get current user from tab session
    user = get_current_user_from_tab_session(tab_session.session_id)
    
    # Get token
    token = Token.query.get_or_404(token_id)
    
    return render_template('view_token.html',
                         token=token,
                         user=user,
                         tab_session_id=tab_session.session_id) 