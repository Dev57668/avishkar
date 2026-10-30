"""Email verification and password reset, against a mocked Resend API (not the live service)."""
import json
import re

import httpx

from avishkar.adapters.mailer import Mailer
from avishkar.demo import DemoSettings

from .conftest import Env

PW = "long-enough-pw"


class Outbox:
    def __init__(self, status=200):
        self.sent, self.status = [], status

    def __call__(self, req: httpx.Request):
        assert req.headers["authorization"] == "Bearer re_test"
        self.sent.append(json.loads(req.content))
        return httpx.Response(self.status, json={"id": "x"})

    def token(self, n=-1):
        return re.search(r"token=([\w-]+)", self.sent[n]["text"]).group(1)


def env(tmp_path, status=200, signup=True, mail=True):
    box = Outbox(status)
    m = Mailer("re_test", "Avishkar <no-reply@example.test>", "https://site.example", transport=httpx.MockTransport(box)) if mail else None
    e = Env(tmp_path, demo=DemoSettings(enabled=True, uploads="admin", signup=signup, password="demo-viewer-123"), mailer=m)
    return e, box


def reg(e, email="n@x.co", pw=PW):
    return e.client.post("/v1/auth/register", json={"email": email, "password": pw})


def test_signup_needs_mailer_and_is_not_advertised_without_it(tmp_path):
    e, _ = env(tmp_path, mail=False)
    assert e.client.get("/v1/public/status").json()["signup"] is False
    assert reg(e).status_code == 403


def test_cannot_login_until_verified_then_can(tmp_path):
    e, box = env(tmp_path)
    assert reg(e).status_code == 202
    assert box.sent[0]["to"] == ["n@x.co"] and "https://site.example/#/verify?token=" in box.sent[0]["text"]
    r = e.client.post("/v1/auth/login", json={"email": "n@x.co", "password": PW})
    assert r.status_code == 403 and r.json()["error"]["code"] == "email_not_verified"
    wrong = e.client.post("/v1/auth/login", json={"email": "n@x.co", "password": "nope-nope-nope"})
    assert wrong.status_code == 401  # a wrong password reveals nothing about verification
    assert e.client.post("/v1/auth/verify", json={"token": box.token()}).json()["status"] == "verified"
    assert e.login("n@x.co", PW)


def test_verification_link_is_single_use_and_garbage_is_rejected(tmp_path):
    e, box = env(tmp_path)
    reg(e)
    t = box.token()
    assert e.client.post("/v1/auth/verify", json={"token": t}).status_code == 200
    assert e.client.post("/v1/auth/verify", json={"token": t}).status_code == 400
    assert e.client.post("/v1/auth/verify", json={"token": "x" * 30}).status_code == 400
    assert e.client.post("/v1/auth/verify", json={"token": "short"}).status_code == 422


def test_expired_link_is_rejected(tmp_path):
    e, box = env(tmp_path)
    reg(e)
    e.store.d.execute("UPDATE email_token SET expires_at=1")
    assert e.client.post("/v1/auth/verify", json={"token": box.token()}).status_code == 400


def test_tokens_are_stored_hashed(tmp_path):
    e, box = env(tmp_path)
    reg(e)
    assert box.token() not in json.dumps(e.store.d.query("SELECT * FROM email_token"))


def test_resend_is_uniform_rate_limited_and_invalidates_the_old_link(tmp_path):
    e, box = env(tmp_path)
    reg(e)
    old = box.token()
    for _ in range(5):
        assert e.client.post("/v1/auth/resend", json={"email": "n@x.co"}).status_code == 202
    assert len(box.sent) == 1 + 3  # capped at 3 per hour
    assert e.client.post("/v1/auth/verify", json={"token": old}).status_code == 400  # superseded
    n = len(box.sent)
    assert e.client.post("/v1/auth/resend", json={"email": "ghost@x.co"}).status_code == 202  # same answer, nothing sent
    assert len(box.sent) == n


def test_password_reset_flow_and_old_password_stops_working(tmp_path):
    e, box = env(tmp_path)
    reg(e)
    e.client.post("/v1/auth/verify", json={"token": box.token()})
    assert e.client.post("/v1/auth/forgot", json={"email": "n@x.co"}).status_code == 202
    assert "reset" in box.sent[-1]["subject"].lower()
    r = e.client.post("/v1/auth/reset", json={"token": box.token(), "password": "brand-new-password"})
    assert r.json()["status"] == "password_changed"
    assert e.client.post("/v1/auth/login", json={"email": "n@x.co", "password": PW}).status_code == 401
    assert e.login("n@x.co", "brand-new-password")
    assert e.client.post("/v1/auth/reset", json={"token": box.token(), "password": "another-password-1"}).status_code == 400


def test_reset_not_offered_for_admins_unverified_or_unknown(tmp_path):
    e, box = env(tmp_path)
    reg(e)  # unverified
    for em in ("admin@acme.test", "n@x.co", "ghost@x.co"):
        assert e.client.post("/v1/auth/forgot", json={"email": em}).status_code == 202
    assert len(box.sent) == 1  # only the verification mail


def test_mail_provider_failure_is_reported_and_does_not_leak_secrets(tmp_path):
    e, box = env(tmp_path, status=500)
    r = reg(e)
    assert r.status_code == 502 and "re_test" not in r.text
    assert e.client.post("/v1/auth/login", json={"email": "n@x.co", "password": PW}).status_code == 403  # still unverified


def test_duplicate_email_and_existing_admin_login_unaffected(tmp_path):
    e, _ = env(tmp_path)
    assert reg(e).status_code == 202 and reg(e).status_code == 409
    assert reg(e, "admin@acme.test").status_code == 409
    assert e.login("admin@acme.test")  # users without an email_state row stay verified
