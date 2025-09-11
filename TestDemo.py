# Legacy banking system being modernized from COBOL
# File: account_management.py (converted from COBOL)

import sqlite3
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# CRITICAL VULNERABILITIES - Typical in COBOL migrations
@app.route('/account/balance', methods=['POST'])
def get_account_balance():
    account_id = request.form.get('account_id')
    pin = request.form.get('pin')
    
    # VULNERABILITY 1: SQL Injection (CWE-89)
    # Legacy COBOL didn't have parameterized queries
    query = f"SELECT balance FROM accounts WHERE id = '{account_id}' AND pin = '{pin}'"
    
    conn = sqlite3.connect('bank.db')
    cursor = conn.execute(query)  # Semgrep will flag this
    result = cursor.fetchone()
    
    if result:
        return jsonify({"balance": result[0]})
    return jsonify({"error": "Invalid credentials"})

# VULNERABILITY 2: Weak Cryptography (CWE-327)
# COBOL systems often used simple hashing
def hash_customer_data(ssn):
    # MD5 is cryptographically broken
    return hashlib.md5(ssn.encode()).hexdigest()  # Semgrep will flag this

# VULNERABILITY 3: Hardcoded Secrets (CWE-798)
# Legacy systems often had embedded credentials
DATABASE_PASSWORD = "admin123"  # Semgrep will flag this
API_KEY = "sk-1234567890abcdef"  # Semgrep will flag this

# VULNERABILITY 4: Path Traversal (CWE-22)
# File handling from COBOL conversions
@app.route('/reports/<filename>')
def get_report(filename):
    # No path validation - directory traversal possible
    with open(f"/reports/{filename}", 'r') as f:  # Semgrep will flag this
        return f.read()