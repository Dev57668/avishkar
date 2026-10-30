from avishkar.demo import DemoSettings

from .conftest import Env


def env(tmp_path, **kw):
    return Env(tmp_path, demo=DemoSettings(enabled=True, uploads="admin", signup=kw.get("signup", True), password="demo-viewer-123"))


def test_status_advertises_signup_and_guest(tmp_path):
    e = env(tmp_path)
    s = e.client.get("/v1/public/status").json()
    assert s["signup"] is True and s["guest"] is True
    off = env(tmp_path / "x", signup=False) if (tmp_path / "x").mkdir() is None else None
    assert off.client.get("/v1/public/status").json()["signup"] is False


def test_signup_creates_readonly_viewer_who_cannot_upload_or_admin(tmp_path):
    e = env(tmp_path)
    r = e.client.post("/v1/auth/register", json={"email": "New@Example.com", "password": "long-enough-pw"})
    assert r.status_code == 201 and r.json()["user"]["role"] == "viewer"
    h = {"Authorization": "Bearer " + r.json()["token"]}
    assert e.client.get("/v1/auth/me", headers=h).json()["role"] == "viewer"
    assert e.client.get("/v1/users", headers=h).status_code == 403
    assert e.client.post("/v1/analyses", headers=h, data={"repository": "a/b"}, files={"archive": ("a.zip", b"PK")}).status_code == 403
    assert e.login("new@example.com", "long-enough-pw")  # can sign in again, email is case-insensitive


def test_signup_rejects_duplicates_weak_passwords_and_bad_fields(tmp_path):
    e = env(tmp_path)
    body = {"email": "a@b.co", "password": "long-enough-pw"}
    assert e.client.post("/v1/auth/register", json=body).status_code == 201
    assert e.client.post("/v1/auth/register", json=body).status_code == 409
    assert e.client.post("/v1/auth/register", json={"email": "c@d.co", "password": "short"}).status_code == 422
    assert e.client.post("/v1/auth/register", json={**body, "role": "admin"}).status_code == 422  # no role field accepted


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
