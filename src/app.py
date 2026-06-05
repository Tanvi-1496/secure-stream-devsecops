from flask import Flask, request, jsonify, Response
import collections
import collections.abc
import sqlite3
import os

from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

# Monkey-patch for compatibility (safe for your setup)
collections.MutableMapping = collections.abc.MutableMapping

app = Flask(__name__)

# -----------------------------
# PROMETHEUS METRICS
# -----------------------------
REQUEST_COUNT = Counter(
    'flask_requests_total',
    'Total number of requests to Flask app'
)

SEARCH_COUNT = Counter(
    'flask_search_requests_total',
    'Total number of search requests'
)

LOGIN_SUCCESS = Counter(
    'flask_login_success_total',
    'Total successful logins'
)

LOGIN_FAILURE = Counter(
    'flask_login_failure_total',
    'Total failed logins'
)

# -----------------------------
# INIT DB
# -----------------------------
def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT
        )
    ''')
    cursor.execute('INSERT OR IGNORE INTO users (id, username) VALUES (1, "admin")')
    conn.commit()
    conn.close()

init_db()

# -----------------------------
# METRICS ENDPOINT (PROMETHEUS)
# -----------------------------
@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

# -----------------------------
# HOME ROUTE
# -----------------------------
@app.route('/')
def home():
    REQUEST_COUNT.inc()
    return "Hello from ReverseFlash Secure App (Secure Version)"

# -----------------------------
# SEARCH ROUTE
# -----------------------------
@app.route('/search', methods=['GET'])
def search():
    REQUEST_COUNT.inc()
    SEARCH_COUNT.inc()

    query = request.args.get('q', '')

    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()

    safe_query = "SELECT * FROM users WHERE username = ?"

    try:
        cursor.execute(safe_query, (query,))
        results = cursor.fetchall()
    except Exception as e:
        results = str(e)
    finally:
        conn.close()

    return jsonify({
        "query_executed": safe_query,
        "results": results
    })

# -----------------------------
# LOGIN ROUTE
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    REQUEST_COUNT.inc()

    ADMIN_USER = os.environ.get("APP_ADMIN_USER", "admin")
    ADMIN_PASS = os.environ.get("APP_ADMIN_PASSWORD")

    data = request.json or {}
    username = data.get('username')
    password = data.get('password')

    if not ADMIN_PASS:
        LOGIN_FAILURE.inc()
        return jsonify({
            "status": "failure",
            "message": "Auth configuration missing"
        }), 500

    if username == ADMIN_USER and password == ADMIN_PASS:

        LOGIN_SUCCESS.inc()

        extra_command = data.get('extra_command', '2')
        try:
            if extra_command.isdigit():
                eval_result = int(extra_command) * 2
            else:
                eval_result = "Invalid numeric instruction"
        except Exception as e:
            eval_result = str(e)

        return jsonify({
            "status": "success",
            "admin_portal": True,
            "result_processed": eval_result
        })

    LOGIN_FAILURE.inc()

    return jsonify({"status": "failure"}), 401

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # nose B104