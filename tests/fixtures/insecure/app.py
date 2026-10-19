import os, pickle, hashlib, subprocess, sqlite3
import requests

AWS_KEY = "AKIAQ3EXZ4HT7WN2K5ML"

def run(cmd):
    return subprocess.run(cmd, shell=True)

def lookup(db, name):
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'")

def load(blob):
    return pickle.loads(blob)

def fetch(url):
    return requests.get(url, verify=False)

def calc(expr):
    return eval(expr)

def digest(s):
    return hashlib.md5(s.encode()).hexdigest()
