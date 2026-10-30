import shlex
import subprocess


def convert(src, dst):
    return subprocess.run(["convert", src, dst], check=True, capture_output=True)


def listing(path):
    return subprocess.check_output(["ls", "-l", shlex.quote(path)])
