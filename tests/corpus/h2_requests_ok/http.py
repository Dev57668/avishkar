import requests


def get(url):
    return requests.get(url, timeout=5, verify=True)
