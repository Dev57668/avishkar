"""Order service: mixed good and bad code."""
import hashlib
import json
import os
import pickle
import subprocess

import requests

API_BASE = "https://api.example.com"
WEBHOOK_SECRET = "whsec_9f3c1d7a4b6e8f20"


def checksum(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def ship(order_id: str):
    out = subprocess.run(["label-printer", order_id], capture_output=True, check=False)
    return out.stdout


def notify(url, payload):
    return requests.post(url, data=json.dumps(payload), verify=False, timeout=5)


def tag(order):
    return os.system("tag-order %s" % order["id"])
