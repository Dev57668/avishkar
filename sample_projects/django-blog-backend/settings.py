"""Django settings for a small blog. Intentionally insecure, for education."""
import hashlib

DEBUG = True
SECRET_KEY = "django-insecure-blog-0123456789abcdef"
ALLOWED_HOSTS = ["*"]
DB_PASSWORD = "blog-db-pass-2026"


def hash_password(raw):
    return hashlib.md5(raw.encode()).hexdigest()
