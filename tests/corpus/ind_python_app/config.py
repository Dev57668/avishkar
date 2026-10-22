"""
Configuration file with security issues
"""

import os

# VULNERABILITY: Hardcoded credentials
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'username': 'admin',
    'password': 'Password123!',  # Hardcoded password
    'database': 'production_db'
}

# VULNERABILITY: Hardcoded API keys
AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

# VULNERABILITY: Hardcoded GitHub token
GITHUB_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'

# VULNERABILITY: Hardcoded encryption key
ENCRYPTION_KEY = b'sixteen byte key'

# VULNERABILITY: Weak crypto usage
import hashlib

def weak_hash(data):
    """Using SHA1 for sensitive data"""
    return hashlib.sha1(data.encode()).hexdigest()


# VULNERABILITY: Insecure random
import random

def generate_token():
    """Using weak random for security token"""
    return random.randint(1000, 9999)


# VULNERABILITY: SSL verification disabled
import requests

def fetch_data(url):
    """Disabling SSL verification"""
    response = requests.get(url, verify=False)
    return response.json()


# VULNERABILITY: Debug mode
DEBUG = True
SECRET_KEY = 'dev-secret-key-not-for-production'
