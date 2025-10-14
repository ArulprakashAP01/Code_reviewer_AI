#!/usr/bin/env python3
"""
Demo file with intentional vulnerabilities for testing
"""

import os
import subprocess
import sqlite3
import pickle
import base64

# HIGH SEVERITY: Command injection vulnerability
def vulnerable_function(user_input):
    # This is intentionally vulnerable
    os.system(f"echo {user_input}")  # HIGH: Command injection
    subprocess.call(f"ls {user_input}", shell=True)  # HIGH: Command injection
    
    # HIGH SEVERITY: SQL injection vulnerability
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")  # HIGH: SQL injection
    
    # MEDIUM SEVERITY: Hardcoded password
    password = "admin123"  # MEDIUM: Hardcoded password
    api_key = "sk-1234567890abcdef"  # MEDIUM: Hardcoded secret
    
    # LOW SEVERITY: Weak crypto
    import hashlib
    hashed = hashlib.md5(password.encode()).hexdigest()  # LOW: Weak hash
    
    # HIGH SEVERITY: Deserialization vulnerability
    data = base64.b64decode(user_input)
    obj = pickle.loads(data)  # HIGH: Unsafe deserialization
    
    return obj

# MEDIUM SEVERITY: Debug mode in production
DEBUG = True  # MEDIUM: Debug mode enabled

if __name__ == "__main__":
    user_input = input("Enter your name: ")
    result = vulnerable_function(user_input)
    print(f"Result: {result}")
hj
dsd
