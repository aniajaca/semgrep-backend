import os
import subprocess
import hashlib
import sqlite3

# A02: Cryptographic Failures - Weak hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# A07: Authentication Failures - Hardcoded credentials  
DATABASE_PASSWORD = "admin123"
API_SECRET = "sk-1234567890abcdef"

# A03: Injection - SQL injection
def get_user(user_id):
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return conn.execute(query).fetchone()

# A03: Injection - Command injection
def process_file(filename):
    os.system(f"cat {filename}")

# A01: Broken Access Control - Path traversal
def read_config(config_name):
    with open(f"/config/{config_name}", "r") as f:
        return f.read()