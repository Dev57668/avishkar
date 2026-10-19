"""
Utility functions with security vulnerabilities
"""

import os
import subprocess
import xml.etree.ElementTree as ET


# VULNERABILITY: Path Traversal
def read_user_file(username, filename):
    """No path validation"""
    filepath = f"/home/{username}/{filename}"
    with open(filepath, 'r') as f:
        return f.read()


# VULNERABILITY: Command Injection via subprocess
def convert_file(input_file, output_file):
    """Vulnerable file conversion"""
    cmd = f"convert {input_file} {output_file}"
    subprocess.call(cmd, shell=True)  # shell=True with user input is dangerous


# VULNERABILITY: XXE (XML External Entity)
def parse_xml(xml_string):
    """Vulnerable XML parsing"""
    # No defusedxml, vulnerable to XXE attacks
    root = ET.fromstring(xml_string)
    return root


# VULNERABILITY: SQL Injection in helper function
def search_users(search_term):
    """Dynamic SQL construction"""
    import sqlite3
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)

    return cursor.fetchall()


# VULNERABILITY: Unsafe file operations
def save_upload(file_data, filename):
    """No validation of filename"""
    # Path traversal via filename
    with open(f"./uploads/{filename}", 'wb') as f:
        f.write(file_data)


# VULNERABILITY: Regex DoS (ReDoS)
import re

def validate_email(email):
    """Vulnerable regex pattern"""
    # This regex can cause catastrophic backtracking
    pattern = r'^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.com$'
    return re.match(pattern, email)


# VULNERABILITY: Insecure temporary file
import tempfile

def process_data(data):
    """Insecure temp file creation"""
    # Creates predictable temp file
    temp_path = "/tmp/data.txt"
    with open(temp_path, 'w') as f:
        f.write(data)
    return temp_path


# VULNERABILITY: Information disclosure
def get_user_info(user_id):
    """Returns sensitive info"""
    return {
        'id': user_id,
        'password_hash': 'abc123',  # Should never return password hash
        'ssn': '123-45-6789',  # PII should be protected
        'credit_card': '4111-1111-1111-1111'
    }
