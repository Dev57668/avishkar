import requests

session = requests.Session()
session.verify = False


def fetch(url):
    return session.get(url, timeout=5)
