"""Ops helper CLI. Intentionally insecure, for education."""
import hashlib
import random
import subprocess
import tempfile

import requests

TOKEN = "ops-service-token-33aa91c2e4d7"


def fetch_status(url):
    return requests.get(url, verify=False, timeout=5).text


def run_check(host):
    return subprocess.call("ping -c 1 " + host, shell=True)


def session_id():
    return str(random.random())


def checksum(secret):
    return hashlib.sha1(secret.encode()).hexdigest()


def scratch():
    return tempfile.mktemp()


def evaluate(expr):
    return eval(expr)
