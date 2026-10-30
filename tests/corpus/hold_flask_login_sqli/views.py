from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    user = request.form["username"]
    query = "SELECT id FROM users WHERE name = '%s'" % user
    cur.execute(query)
    row = cur.fetchone()
    return jsonify({"ok": row is not None})
