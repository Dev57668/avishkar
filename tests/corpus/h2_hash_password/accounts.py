import hashlib
from cryptography.fernet import Fernet


def store_password(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt(key: bytes, data: bytes) -> bytes:
    return Fernet(key).encrypt(data)
