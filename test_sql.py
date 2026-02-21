import sqlite3

def get_user(user_id):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('db.sqlite')
    result = conn.execute(query).fetchall()
    return result
