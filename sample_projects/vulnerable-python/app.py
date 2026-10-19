"""
Intentionally Vulnerable Python Application
FOR DEMO/TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION

Contains common security vulnerabilities found in AI-generated code:
1. SQL Injection
2. Command Injection
3. Hardcoded Secrets
4. Weak Cryptography
5. Path Traversal
6. Insecure Configuration
"""

import os
import hashlib
import sqlite3
from flask import Flask, request, jsonify

# VULNERABILITY 1: Hardcoded Secret
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"
JWT_SECRET = "super_secret_key_do_not_share"

app = Flask(__name__)


# VULNERABILITY 2: SQL Injection
def login(username, password):
    """Vulnerable login function using string concatenation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SQL Injection: User input directly concatenated into query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result


# VULNERABILITY 3: Command Injection
def ping_host(host):
    """Vulnerable ping function"""
    # Command Injection: User input directly passed to shell
    result = os.system(f"ping {host}")
    return result


# VULNERABILITY 4: Weak Cryptography
def hash_password(password):
    """Insecure password hashing using MD5"""
    # Weak Crypto: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY 5: Path Traversal
def read_file(filename):
    """Vulnerable file read function"""
    # Path Traversal: No validation of user-supplied filename
    filepath = f"/uploads/{filename}"
    with open(filepath, 'r') as f:
        return f.read()


# VULNERABILITY 6: Eval - Code Injection
def calculate(expression):
    """Dangerous eval usage"""
    # Code Injection: eval executes arbitrary code
    return eval(expression)


# VULNERABILITY 7: Insecure Deserialization
import pickle

def load_user_data(data):
    """Vulnerable pickle deserialization"""
    # Insecure Deserialization: pickle.loads can execute arbitrary code
    return pickle.loads(data)


# Flask routes with vulnerabilities
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    user = login(data['username'], data['password'])
    if user:
        return jsonify({"success": True, "token": API_KEY})
    return jsonify({"success": False}), 401


@app.route('/api/ping', methods=['POST'])
def api_ping():
    data = request.json
    result = ping_host(data['host'])
    return jsonify({"result": result})


@app.route('/api/file/<filename>')
def api_read_file(filename):
    content = read_file(filename)
    return content


@app.route('/api/calculate', methods=['POST'])
def api_calculate():
    data = request.json
    result = calculate(data['expression'])
    return jsonify({"result": result})


# VULNERABILITY 8: Insecure Configuration
if __name__ == '__main__':
    # Debug mode enabled in production
    # Binding to all interfaces (0.0.0.0)
    app.run(debug=True, host='0.0.0.0', port=5000)
