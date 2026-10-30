"""Configuration read from the environment, with safe defaults."""

import hashlib
import os
import secrets

import requests

DATABASE_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "username": os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
    "database": os.environ.get("DB_NAME", "app"),
}

DEBUG = os.environ.get("APP_DEBUG") == "1"
SECRET_KEY = os.environ["SECRET_KEY"]


def fingerprint(data):
    return hashlib.sha256(data.encode()).hexdigest()


def generate_token():
    """Cryptographically secure random token."""
    return secrets.token_urlsafe(32)


def fetch_data(url):
    """TLS verification stays on and a timeout is set."""
    response = requests.get(url, timeout=10)
    return response.json()
