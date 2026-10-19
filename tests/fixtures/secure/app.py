import json, subprocess, hashlib

def run(args):
    return subprocess.run(args, shell=False, check=True)

def lookup(db, name):
    return db.execute("SELECT * FROM users WHERE name = ?", (name,))

def load(blob):
    return json.loads(blob)

def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()
