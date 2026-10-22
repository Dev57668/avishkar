import json, hashlib, subprocess, yaml

def run(args):
    return subprocess.run(args, shell=False, check=True)

def q(db, n):
    return db.execute('SELECT * FROM u WHERE n = ?', (n,))

def cfg(s):
    return yaml.safe_load(s)

def h(b):
    return hashlib.sha256(b).hexdigest()

def load(b):
    return json.loads(b)
