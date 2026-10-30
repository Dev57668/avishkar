import os
from flask import send_file

UPLOAD_DIR = "/srv/uploads"


def download(filename):
    return send_file(os.path.join(UPLOAD_DIR, filename))
