"""Helper functions that handle files, processes, XML and SQL safely."""

import os
import sqlite3
import subprocess
import tempfile

from defusedxml import ElementTree as ET


def read_user_file(username, filename):
    base = os.path.realpath(os.path.join("/home", os.path.basename(username)))
    filepath = os.path.realpath(os.path.join(base, filename))
    if not filepath.startswith(base + os.sep):
        raise ValueError("invalid path")
    with open(filepath, "r") as f:
        return f.read()


def convert_file(input_file, output_file):
    subprocess.call(["convert", input_file, output_file])


def parse_xml(xml_string):
    return ET.fromstring(xml_string)


def search_users(search_term):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{search_term}%",))
    return cursor.fetchall()


def save_upload(file_data, filename):
    safe_name = os.path.basename(filename)
    with open(os.path.join("./uploads", safe_name), "wb") as f:
        f.write(file_data)


def process_data(data):
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(data)
        return f.name
