"""Blog views. Intentionally insecure, for education."""
import random
import subprocess

from django.db import connection
from django.http import HttpResponse


def post_by_author(request):
    author = request.GET.get("author", "")
    with connection.cursor() as cur:
        cur.execute("SELECT * FROM posts WHERE author = '%s'" % author)
        rows = cur.fetchall()
    return HttpResponse(str(rows))


def reset_token(request):
    return HttpResponse(str(random.randint(100000, 999999)))


def thumbnail(request):
    name = request.GET.get("file", "")
    subprocess.run("convert " + name + " -resize 128x128 out.png", shell=True)
    return HttpResponse("ok")
