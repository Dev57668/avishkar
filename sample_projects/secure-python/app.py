"""
Secure counterpart of vulnerable-python: the same features written with safe patterns.
Educational sample: a scan of this project is expected to report no findings from Avishkar's detectors.
That does NOT prove it is secure; it only means none of the patterns Avishkar knows about were found.
"""

import ast
import hashlib
import json
import os
import sqlite3
import subprocess

from flask import Flask, jsonify, request

# Secrets come from the environment (injected at deploy time), never from source code.
API_KEY = os.environ["API_KEY"]
JWT_SECRET = os.environ["JWT_SECRET"]

app = Flask(__name__)


def login(username, password_hash):
    """Parameterized query: user input is passed as data, never concatenated into SQL."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (username, password_hash))
    result = cursor.fetchone()
    conn.close()
    return result


def ping_host(host):
    """Argument list, no shell: shell metacharacters in `host` stay inert."""
    return subprocess.run(["ping", "-c", "1", host], check=False).returncode


def hash_password(password):
    """Salted, slow key derivation instead of MD5."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return salt.hex() + ":" + digest.hex()


def read_file(filename):
    """Resolve the final path and require it to stay inside the uploads directory."""
    base = os.path.realpath("/uploads")
    filepath = os.path.realpath(os.path.join(base, filename))
    if not filepath.startswith(base + os.sep):
        raise ValueError("invalid path")
    with open(filepath, "r") as f:
        return f.read()


def calculate(expression):
    """Literals only: ast.literal_eval cannot call functions or touch the system."""
    return ast.literal_eval(expression)


def load_user_data(data):
    """A data-only format instead of pickle."""
    return json.loads(data)


@app.route("/api/ping", methods=["POST"])
def api_ping():
    data = request.json
    return jsonify({"result": ping_host(data["host"])})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
