from avishkar.demo import DemoSettings

from .conftest import Env


def env(tmp_path, **kw):
    return Env(tmp_path, demo=DemoSettings(enabled=True, uploads="admin", signup=kw.get("signup", True), password="demo-viewer-123"))


def test_status_advertises_guest_but_not_signup_without_a_mailer(tmp_path):
    # Sign-up now requires email verification; its behaviour is covered in test_email.py.
    s = env(tmp_path).client.get("/v1/public/status").json()
    assert s["guest"] is True and s["signup"] is False


def test_signup_disabled_by_default_and_outside_demo_mode(tmp_path):
    assert env(tmp_path, signup=False).client.post("/v1/auth/register", json={"email": "a@b.co", "password": "long-enough-pw"}).status_code == 403
    plain = Env(tmp_path / "p") if (tmp_path / "p").mkdir() is None else None
    assert plain.client.post("/v1/auth/register", json={"email": "a@b.co", "password": "long-enough-pw"}).status_code == 403


def test_guest_session_is_the_readonly_demo_viewer(tmp_path):
    e = env(tmp_path)
    e.add_user(e.org["id"], "demo@avishkar.dev", "viewer")
    r = e.client.post("/v1/auth/guest")
    assert r.status_code == 200
    h = {"Authorization": "Bearer " + r.json()["token"]}
    assert e.client.get("/v1/auth/me", headers=h).json()["role"] == "viewer"
    assert e.client.get("/v1/users", headers=h).status_code == 403


def test_guest_disabled_without_demo_mode(tmp_path):
    assert Env(tmp_path).client.post("/v1/auth/guest").status_code == 403
