import random
import string


def generate_password(n=16):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def pick_greeting():
    return random.choice(["hi", "hello", "hey"])
