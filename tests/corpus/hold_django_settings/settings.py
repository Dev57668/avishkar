import os

SECRET_KEY = "django-insecure-8x!k2m9q#w7z$r5t1y3u6i0o"
DEBUG = True
ALLOWED_HOSTS = ["*"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "shop",
        "USER": "shop",
        "PASSWORD": "pg_pass_Zq81xK02",
        "HOST": "db.internal",
    }
}

EMAIL_HOST_PASSWORD = os.environ["EMAIL_HOST_PASSWORD"]
STATIC_URL = "/static/"
SECRET_KEY_FALLBACKS_NOTE = "see the deployment runbook"
