import os

def go(h):
    return os.popen('ls ' + h).read()
