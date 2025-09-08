"""
Compliance Service for TokenPlatform
Handles compliance validation for different compliance modules
"""

from datetime import datetime, timedelta
from models.user import User
from models.token import Token
from config.modular_compliance import get_compliance_module

class ComplianceService:
    def __init__(self):
        pass
    
    def validate_geographical_compliance(self, investor_address, compliance_module_id):
        """Validate geographical compliance for an investor"""
        module = get_compliance_module(compliance_module_id)
        if not module or not module.geographical_restrictions:
            return True, "No geographical restrictions"
        
        # Get investor's location from their claims
        # This would need to be implemented based on how location is stored
        # For now, we'll assume it's stored in user data or claims
        investor = User.query.filter_by(wallet_address=investor_address).first()
        if not investor:
            return False, "Investor not found"
        
        # Check if investor has location claim (this is a placeholder)
        # In real implementation, you'd check the investor's claims for location
        investor_location = self._get_investor_location(investor)
        
        if investor_location in module.geographical_restrictions:
            return True, f"Investor location {investor_location} is allowed"
        else:
            return False, f"Investor location {investor_location} is not allowed. Allowed: {', '.join(module.geographical_restrictions)}"
    
    def validate_supply_compliance(self, token_address, compliance_module_id, additional_amount=0):
        """Validate supply compliance for token operations"""
        module = get_compliance_module(compliance_module_id)
        if not module or not module.max_supply_limit:
            return True, "No supply restrictions"
        
        # Get current token supply
        token = Token.query.filter_by(token_address=token_address).first()
        if not token:
            return False, "Token not found"
        
        current_supply = token.total_supply
        if current_supply + additional_amount > module.max_supply_limit:
            return False, f"Supply limit exceeded. Current: {current_supply}, Limit: {module.max_supply_limit}, Additional: {additional_amount}"
        
        return True, f"Supply within limits. Current: {current_supply}, Limit: {module.max_supply_limit}"
    
    def validate_cooling_period_compliance(self, investor_address, compliance_module_id):
        """Validate cooling period compliance for purchases"""
        module = get_compliance_module(compliance_module_id)
        if not module or not module.cooling_period_minutes:
            return True, "No cooling period restrictions"
        
        # Get investor's last purchase timestamp
        investor = User.query.filter_by(wallet_address=investor_address).first()
        if not investor:
            return False, "Investor not found"
        
        last_purchase = self._get_last_purchase_timestamp(investor)
        if not last_purchase:
            return True, "No previous purchases, cooling period not applicable"
        
        # Check if enough time has passed
        cooldown_duration = timedelta(minutes=module.cooling_period_minutes)
        if datetime.utcnow() - last_purchase < cooldown_duration:
            remaining_time = cooldown_duration - (datetime.utcnow() - last_purchase)
            return False, f"Cooling period active. Wait {remaining_time.total_seconds()/60:.1f} more minutes"
        
        return True, f"Cooling period satisfied. Last purchase: {last_purchase}"
    
    def validate_token_operation_compliance(self, investor_address, token_address, operation_type, compliance_module_id, additional_amount=0):
        """Validate compliance for any token operation"""
        errors = []
        
        # Check geographical compliance
        geo_valid, geo_message = self.validate_geographical_compliance(investor_address, compliance_module_id)
        if not geo_valid:
            errors.append(f"Geographical: {geo_message}")
        
        # Check supply compliance for minting operations
        if operation_type in ['mint', 'purchase']:
            supply_valid, supply_message = self.validate_supply_compliance(token_address, compliance_module_id, additional_amount)
            if not supply_valid:
                errors.append(f"Supply: {supply_message}")
        
        # Check cooling period for purchases
        if operation_type == 'purchase':
            cooling_valid, cooling_message = self.validate_cooling_period_compliance(investor_address, compliance_module_id)
            if not cooling_valid:
                errors.append(f"Cooling Period: {cooling_message}")
        
        if errors:
            return False, "; ".join(errors)
        
        return True, "All compliance checks passed"
    
    def _get_investor_location(self, investor):
        """Get investor's location from their claims or profile"""
        # This is a placeholder implementation
        # In real implementation, you'd check the investor's claims for location information
        # For now, return a default location for testing
        return "EU"  # Placeholder
    
    def _get_last_purchase_timestamp(self, investor):
        """Get investor's last purchase timestamp"""
        # This is a placeholder implementation
        # In real implementation, you'd query the database for the last purchase timestamp
        # For now, return None to indicate no previous purchases
        return None  # Placeholder
