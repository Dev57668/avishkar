import base64
import os
import pickle


def run_report(cmd):
    return os.popen(cmd).read()


def restore(blob):
    return pickle.loads(base64.b64decode(blob))
