import hashlib


def etag(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
