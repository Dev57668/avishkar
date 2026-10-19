"""Authentication primitives: scrypt passwords, signed session tokens, hashed API keys, roles."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass

import jwt

ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}
TOKEN_TTL = 8 * 3600
MIN_PASSWORD = 10


@dataclass(frozen=True)
class Principal:
    id: str
    org_id: str
    role: str
    email: str | None = None
    via: str = "token"  # token | api_key

    def has(self, role: str) -> bool:
        return _RANK[self.role] >= _RANK[role]


def hash_password(pw: str) -> str:
    if len(pw) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


def new_api_key() -> tuple[str, str]:
    """Returns (plaintext shown once, sha256 hash stored). Keys are high-entropy so a fast hash is adequate."""
    key = "avk_" + secrets.token_urlsafe(32)
    return key, hash_api_key(key)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class TokenService:
    def __init__(self, secret: str, ttl: int = TOKEN_TTL):
        self.secret, self.ttl = secret, ttl

    def issue(self, user: dict) -> tuple[str, float]:
        exp = time.time() + self.ttl
        tok = jwt.encode({"sub": user["id"], "org": user["organization_id"], "role": user["role"],
                          "exp": int(exp), "iat": int(time.time())}, self.secret, algorithm="HS256")
        return tok, exp

    def verify(self, token: str) -> dict | None:
        try:
            return jwt.decode(token, self.secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
        except jwt.PyJWTError:
            return None


class LoginThrottle:
    """Lock an email out after repeated failures (in-memory; use a shared store with multiple API replicas)."""

    def __init__(self, max_fail=5, window=900):
        self.max_fail, self.window, self.fails = max_fail, window, {}

    def blocked(self, key: str) -> bool:
        now = time.time()
        recent = [t for t in self.fails.get(key, []) if now - t < self.window]
        self.fails[key] = recent
        return len(recent) >= self.max_fail

    def fail(self, key: str):
        self.fails.setdefault(key, []).append(time.time())

    def ok(self, key: str):
        self.fails.pop(key, None)
