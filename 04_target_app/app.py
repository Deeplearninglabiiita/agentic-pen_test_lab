from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
app.config["DEBUG"] = True

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn

_db = get_db()
_db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, email TEXT, role TEXT)")
_db.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, account_number TEXT, balance REAL)")
_db.executemany("INSERT INTO users VALUES (?,?,?,?,?)", [
    (1, "admin",    "$2b$12$fake_hash_admin",    "admin@lab.local",    "admin"),
    (2, "testuser", "$2b$12$fake_hash_testuser", "test@lab.local",     "user"),
    (3, "researcher","$2b$12$fake_hash_researcher","research@lab.local","user"),
])
_db.executemany("INSERT INTO customers VALUES (?,?,?,?)", [
    (1, "Alice Demo", "ACC-001", 50000.00),
    (2, "Bob Demo",   "ACC-002", 12000.00),
    (3, "Charlie Demo","ACC-003", 98000.00),
])
_db.commit()

@app.route("/")
def index():
    return """<h2>LabBank Demo — Intentionally Vulnerable Lab Target</h2>
    <p>Routes: <a href='/search?q=admin'>/search?q=admin</a> |
    <a href='/api/customers'>/api/customers</a> |
    <a href='/api/status'>/api/status</a></p>"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    error = ""
    if q:
        try:
            cursor = _db.execute(f"SELECT * FROM users WHERE username LIKE '%{q}%'")
            results = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            error = str(e)
    return f"""<h2>Search</h2>
    <form><input name='q' value='{q}'><button type='submit'>Search</button></form>
    {'<p style="color:red">Error: '+error+'</p>' if error else ''}
    <p>Results for: {q}</p>
    {''.join(f"<div>{r['username']} — {r['email']} ({r['role']})</div>" for r in results)}"""

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        msg = f"Login attempted for: {request.form.get('username', '')}"
    return f"""<h2>Login</h2>
    <form method='POST'>
    <input name='username' placeholder='Username'><br>
    <input type='password' name='password' placeholder='Password'><br>
    <button type='submit'>Login</button></form>
    {'<p>'+msg+'</p>' if msg else ''}"""

@app.route("/api/customers")
def api_customers():
    cursor = _db.execute("SELECT * FROM customers")
    return jsonify({"note": "Lab demo data only", "customers": [dict(r) for r in cursor.fetchall()]})

@app.route("/api/status")
def status():
    return jsonify({"status": "running", "version": "1.0.0",
                    "framework": "Flask/Werkzeug 2.3.0", "python": "3.11",
                    "database": "SQLite", "environment": "development"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
