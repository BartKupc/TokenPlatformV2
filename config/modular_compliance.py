"""
Modular Compliance System for TokenPlatform
Pre-configured compliance modules for different regulatory requirements
"""

class ComplianceModule:
    def __init__(self, module_id, name, description, required_topics, auto_approve_rules, 
                 geographical_restrictions=None, max_supply_limit=None, cooling_period_minutes=None, 
                 manual_verification_topics=None):
        self.module_id = module_id
        self.name = name
        self.description = description
        self.required_topics = required_topics
        self.auto_approve_rules = auto_approve_rules
        self.geographical_restrictions = geographical_restrictions  # ['EU', 'US'] or None
        self.max_supply_limit = max_supply_limit  # 1000000 or None
        self.cooling_period_minutes = cooling_period_minutes  # 5 or None
        self.manual_verification_topics = manual_verification_topics or []

# Pre-defined compliance modules
COMPLIANCE_MODULES = {
    'geographical_eu_us': ComplianceModule(
        module_id='geographical_eu_us',
        name='Geographical (EU & US Only)',
        description='Only allows investors from EU and US regions to hold tokens',
        required_topics=[1, 2],  # Basic KYC and AML
        auto_approve_rules={
            1: 'APPROVED',
            2: 'COMPLIANT'
        },
        geographical_restrictions=['EU', 'US']
    ),
    
    'max_supply_1m': ComplianceModule(
        module_id='max_supply_1m',
        name='Max Supply (1M Tokens)',
        description='Maximum token supply limited to 1,000,000 tokens',
        required_topics=[1, 2],  # Basic KYC and AML
        auto_approve_rules={
            1: 'APPROVED',
            2: 'COMPLIANT'
        },
        max_supply_limit=1000000
    ),
    
    'cooling_period_5min': ComplianceModule(
        module_id='cooling_period_5min',
        name='Cooling Period (5 Minutes)',
        description='5-minute cooldown period between token purchases',
        required_topics=[1, 2],  # Basic KYC and AML
        auto_approve_rules={
            1: 'APPROVED',
            2: 'COMPLIANT'
        },
        cooling_period_minutes=5
    ),
    
    'custom': ComplianceModule(
        module_id='custom',
        name='Custom Selection',
        description='Manually select compliance requirements',
        required_topics=[],
        auto_approve_rules={}
    )
}

def get_compliance_module(module_id):
    """Get a compliance module by ID"""
    return COMPLIANCE_MODULES.get(module_id)

def get_all_modules():
    """Get all available compliance modules"""
    return COMPLIANCE_MODULES

def get_module_required_topics(module_id):
    """Get required topics for a compliance module"""
    module = get_compliance_module(module_id)
    return module.required_topics if module else []

def get_module_auto_approve_rules(module_id):
    """Get auto-approve rules for a compliance module"""
    module = get_compliance_module(module_id)
    return module.auto_approve_rules if module else {}

def get_module_manual_verification_topics(module_id):
    """Get topics that require manual verification for a compliance module"""
    module = get_compliance_module(module_id)
    return module.manual_verification_topics if module else []

def get_module_geographical_restrictions(module_id):
    """Get geographical restrictions for a compliance module"""
    module = get_compliance_module(module_id)
    return module.geographical_restrictions if module else None

def get_module_max_supply_limit(module_id):
    """Get maximum supply limit for a compliance module"""
    module = get_compliance_module(module_id)
    return module.max_supply_limit if module else None

def get_module_cooling_period(module_id):
    """Get cooling period in minutes for a compliance module"""
    module = get_compliance_module(module_id)
    return module.cooling_period_minutes if module else None

def calculate_compliance_status(user_data, module_id):
    """Calculate compliance status based on user data and module rules"""
    module = get_compliance_module(module_id)
    if not module:
        return {}
    
    compliance_status = {}
    auto_rules = module.auto_approve_rules
    manual_topics = module.manual_verification_topics
    
    for topic_id in module.required_topics:
        if topic_id in auto_rules:
            compliance_status[topic_id] = auto_rules[topic_id]
        elif topic_id in manual_topics:
            compliance_status[topic_id] = "PENDING"  # Requires manual verification
        else:
            compliance_status[topic_id] = "PENDING"  # Default to pending
    
    return compliance_status

# Helper function to get module display info
def get_module_display_info():
    """Get formatted module information for frontend display"""
    modules_info = []
    for module_id, module in COMPLIANCE_MODULES.items():
        modules_info.append({
            'id': module_id,
            'name': module.name,
            'description': module.description,
            'required_topics': module.required_topics,
            'manual_verification_count': len(module.manual_verification_topics),
            'auto_approve_count': len(module.auto_approve_rules),
            'geographical_restrictions': module.geographical_restrictions,
            'max_supply_limit': module.max_supply_limit,
            'cooling_period_minutes': module.cooling_period_minutes
        })
    return modules_info
