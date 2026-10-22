import hashlib

def h(p):
    return hashlib.new('sha1', p).hexdigest()
