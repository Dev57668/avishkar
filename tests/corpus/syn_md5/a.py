import hashlib

def h(p):
    return hashlib.md5(p).hexdigest()
