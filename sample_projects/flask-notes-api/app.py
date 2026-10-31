"""A small notes API. Intentionally insecure, for education."""
import os
import pickle
import sqlite3

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["DEBUG"] = True
SECRET_TOKEN = "notes-admin-token-4f9a1c7e2b"


def db():
    return sqlite3.connect("notes.db")


@app.route("/notes")
def search_notes():
    term = request.args.get("q", "")
    cur = db().cursor()
    query = f"SELECT id, title FROM notes WHERE title LIKE '%{term}%'"
    cur.execute(query)
    return jsonify(cur.fetchall())


@app.route("/export")
def export_note():
    name = request.args.get("name", "")
    with open(f"/srv/notes/{name}.txt") as fh:
        return fh.read()


@app.route("/import", methods=["POST"])
def import_note():
    blob = request.get_data()
    return jsonify(pickle.loads(blob))


@app.route("/config", methods=["POST"])
def load_config():
    return jsonify(yaml.load(request.get_data(), Loader=yaml.Loader))


@app.route("/backup")
def backup():
    target = request.args.get("target", "")
    os.system("tar czf /tmp/backup.tgz " + target)
    return "ok"
