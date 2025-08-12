"""
Centralized claim topics configuration for TokenPlatform
Following T-REX standard ERC-3643 claim topics
"""

# T-REX Standard Claim Topics
CLAIM_TOPICS = {
    1: 'KYC (Know Your Customer)',
    2: 'AML (Anti-Money Laundering)',
    3: 'Accredited Investor',
    4: 'EU Nationality Confirmed',
    5: 'US Nationality Confirmed',
    6: 'Blacklist',
    7: 'Residency',
    8: 'Compliance Status',
    9: 'Restricted Status',
    10: 'Whitelisted Status'
}

# Reverse mapping for lookups
CLAIM_TOPICS_BY_NAME = {name: topic_id for topic_id, name in CLAIM_TOPICS.items()}

# Claim data options for each topic
CLAIM_DATA_OPTIONS = {
    1: ['APPROVED', 'REJECTED', 'PENDING'],  # KYC
    2: ['COMPLIANT', 'NON_COMPLIANT', 'PENDING'],  # AML
    3: ['ACCREDITED', 'NON_ACCREDITED'],  # Accredited Investor
    4: ['CONFIRMED', 'NOT_CONFIRMED'],  # EU Nationality
    5: ['CONFIRMED', 'NOT_CONFIRMED'],  # US Nationality
    6: ['CLEAN', 'BLACKLISTED'],  # Blacklist
    7: ['RESIDENT', 'NON_RESIDENT', 'PENDING'],  # Residency
    8: ['COMPLIANT', 'NON_COMPLIANT', 'PENDING'],  # Compliance
    9: ['RESTRICTED', 'UNRESTRICTED'],  # Restricted
    10: ['WHITELISTED', 'NOT_WHITELISTED']  # Whitelisted
}

def get_topic_name(topic_id):
    """Get human-readable name for a topic ID"""
    return CLAIM_TOPICS.get(topic_id, f'Unknown Topic {topic_id}')

def get_topic_id(topic_name):
    """Get topic ID for a topic name"""
    # First try exact match
    if topic_name in CLAIM_TOPICS_BY_NAME:
        return CLAIM_TOPICS_BY_NAME[topic_name]
    
    # Try partial matches
    topic_name_upper = topic_name.upper()
    for name, topic_id in CLAIM_TOPICS_BY_NAME.items():
        if topic_name_upper in name.upper():
            return topic_id
    
    return None

def get_claim_data_options(topic_id):
    """Get available claim data options for a topic"""
    return CLAIM_DATA_OPTIONS.get(topic_id, [])

def is_valid_topic(topic_id):
    """Check if a topic ID is valid"""
    return topic_id in CLAIM_TOPICS

def get_all_topics():
    """Get all available topics as a list of tuples (id, name)"""
    return list(CLAIM_TOPICS.items()) 