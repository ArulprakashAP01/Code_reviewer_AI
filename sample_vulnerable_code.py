# Sample file with intentional security vulnerabilities for testing

import os
import subprocess
import sqlite3

# VULNERABILITY 1: Hardcoded password (Bandit will detect this)
password = "admin123"

# VULNERABILITY 2: SQL injection risk
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILITY 3: Command injection risk
def run_command(command):
    # VULNERABLE: Direct command execution
    return os.system(command)

# VULNERABILITY 4: Insecure random
import random
def generate_token():
    # VULNERABLE: Using random instead of secrets
    return random.randint(1000, 9999)

# VULNERABILITY 5: Debug code in production
print("Debug: User logged in")  # This should be removed in production

# VULNERABILITY 6: Weak crypto
import hashlib
def hash_password(password):
    # VULNERABLE: Using MD5
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    # Test the vulnerable functions
    user_id = input("Enter user ID: ")
    get_user_data(user_id)
    
    cmd = input("Enter command: ")
    run_command(cmd) 