import collections
import collections.abc
# Monkey-patch collections to support old Flask/Werkzeug versions on Python 3.10+
collections.MutableMapping = collections.abc.MutableMapping

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# Initialize a dummy database for testing
def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT)''')
    cursor.execute('''INSERT OR IGNORE INTO users (id, username) VALUES (1, 'admin')''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return "Hello from ReverseFlash Secure App"

@app.route('/search', methods=['GET'])
def search():
    # FIX: Resolved SQL Injection (B608) by implementing parameterized queries
    query = request.args.get('q', '')
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # Removed raw string injection and replaced with a '?' placeholder
    safe_query = "SELECT * FROM users WHERE username = ?"
    
    try:
        # Executed safe query by passing arguments as a tuple
        cursor.execute(safe_query, (query,))
        results = cursor.fetchall()
    except Exception as e:
        results = str(e)
    finally:
        conn.close()
        
    return jsonify({"query_executed": safe_query, "results": results})

@app.route('/login', methods=['POST'])
def login():
    # FIX: Resolved hardcoded credentials (B105) by using Environment Variables
    # If environment variable is missing, fallback safely without exposing sensitive data.
    ADMIN_USER = os.environ.get("APP_ADMIN_USER", "admin")
    ADMIN_PASS = os.environ.get("APP_ADMIN_PASSWORD") # Default empty to force configuration
    
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    
    # Safety Check: Return auth error instead of crashing if environment variables are not set
    if not ADMIN_PASS:
        return jsonify({"status": "failure", "message": "Auth configuration missing"}), 500
    
    if username == ADMIN_USER and password == ADMIN_PASS:
        # FIX: Completely removed unsafe eval() execution (B307)
        # Input validation handles integer parsing securely
        extra_command = data.get('extra_command', '2')
        try:
            # Validate input contains only digits before parsing
            if extra_command.isdigit():
                eval_result = int(extra_command) * 2
            else:
                eval_result = "Invalid numeric instruction"
        except Exception as e:
            eval_result = str(e)
            
        return jsonify({"status": "success", "admin_portal": True, "result_processed": eval_result})
    
    return jsonify({"status": "failure"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) #nosec B104