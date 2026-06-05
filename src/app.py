from flask import Response
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

@app.route('/metrics')
def metrics():
    return Response(
        "flask_app_up 1\n",
        mimetype="text/plain"
    )
@app.route('/')
def home():
    return "Hello from ReverseFlash Secure App (Secure Version)"

@app.route('/search', methods=['GET'])
def search():
    # FIX: Parameterized Queries use karke SQL Injection (B608) ko khatam kiya
    query = request.args.get('q', '')

    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # Raw string injection hata kar '?' placeholder use kiya hai
    safe_query = "SELECT * FROM users WHERE username = ?"
    
    try:
        # Tuple ke roop mein safe query aur argument pass kiya
        cursor.execute(safe_query, (query,))
        results = cursor.fetchall()
    except Exception as e:
        results = str(e)
    finally:
        conn.close()
        
    return jsonify({"query_executed": safe_query, "results": results})

@app.route('/login', methods=['POST'])
def login():
    # FIX: Hardcoded credentials (B105) ko hata kar Environment Variables use kiya hai
    # Agar environment variable nahi mila, toh fallback secure alternate pass hoga, text-string nahi.
    ADMIN_USER = os.environ.get("APP_ADMIN_USER", "admin")
    ADMIN_PASS = os.environ.get("APP_ADMIN_PASSWORD") # Default empty to force configuration
    
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    
    # Safety Check: Agar environment set nahi hai toh route login fail karega, crash nahi
    if not ADMIN_PASS:
        return jsonify({"status": "failure", "message": "Auth configuration missing"}), 500
    
    if username == ADMIN_USER and password == ADMIN_PASS:
        # FIX: Unsafe eval() execution (B307) ko poori tarah remove kar diya
        # Hamne input logic ko securely safe integer parsing se control kiya hai
        extra_command = data.get('extra_command', '2')
        try:
            # Sirf safe digit mathematical inputs parse karne ke liye safe cast lagaya
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