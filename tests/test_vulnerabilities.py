import hashlib
import sqlite3
import subprocess
import os

# MD5 usage (should be detected)
password_hash = hashlib.md5("password123".encode()).hexdigest()

# SQL injection vulnerability (should be detected)
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# Command injection (should be detected)
def run_command(user_input):
    os.system(f"echo {user_input}")

# Hardcoded secret (might be detected)
API_KEY = "sk-1234567890abcdef"
