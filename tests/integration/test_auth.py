import time

import jwt
import pytest

from avishkar.api.security import (LoginThrottle, TokenService, hash_password, verify_password)

from .conftest import FIX, PW, Env, zip_dir


def test_password_hashing():
    h = hash_password(PW)
    assert h.startswith("scrypt$") and PW not in h
    assert verify_password(PW, h) and not verify_password("wrong password!!", h)
    assert hash_password(PW) != h  # unique salt
    with pytest.raises(ValueError):
        hash_password("short")
    assert not verify_password("x", "garbage")


def test_login_and_me(env):
    me = env.client.get("/v1/auth/me", headers=env.h).json()
    assert me["role"] == "admin" and me["email"] == "admin@acme.test"
    bad = env.client.post("/v1/auth/login", json={"email": "admin@acme.test", "password": "nope-nope-nope"})
    assert bad.status_code == 401
    unknown = env.client.post("/v1/auth/login", json={"email": "ghost@acme.test", "password": "nope-nope-nope"})
    assert unknown.status_code == 401 and unknown.json()["error"]["message"] == bad.json()["error"]["message"]


def test_login_throttle(env):
    for _ in range(5):
        env.client.post("/v1/auth/login", json={"email": "admin@acme.test", "password": "wrong-wrong-1"})
    r = env.client.post("/v1/auth/login", json={"email": "admin@acme.test", "password": PW})
    assert r.status_code == 429


def test_throttle_unit():
    t = LoginThrottle(max_fail=2, window=60)
    t.fail("a"); assert not t.blocked("a")
    t.fail("a"); assert t.blocked("a")
    t.ok("a"); assert not t.blocked("a")


def test_token_expiry_and_tamper():
    ts = TokenService("k" * 40, ttl=-1)
    tok, _ = ts.issue({"id": "u", "organization_id": "o", "role": "admin"})
    assert ts.verify(tok) is None
    good, _ = TokenService("k" * 40).issue({"id": "u", "organization_id": "o", "role": "admin"})
    assert TokenService("k" * 40).verify(good)["sub"] == "u"
    assert TokenService("other" * 10).verify(good) is None
    none_alg = jwt.encode({"sub": "u", "exp": int(time.time()) + 99}, "", algorithm="none")
    assert TokenService("k" * 40).verify(none_alg) is None


def test_roles_enforced(env):
    env.add_user(env.org["id"], "view@acme.test", "viewer")
    env.add_user(env.org["id"], "ana@acme.test", "analyst")
    v, a = env.login("view@acme.test"), env.login("ana@acme.test")
    assert env.client.get("/v1/repositories", headers=v).status_code == 200
    assert env.scan("r/x", zip_dir(FIX / "secure"), headers=v, drain=False).status_code == 403
    assert env.scan("r/x", zip_dir(FIX / "secure"), headers=a, drain=False).status_code == 202
    assert env.client.get("/v1/users", headers=a).status_code == 403
    assert env.client.post("/v1/users", headers=a, json={"email": "n@a.test", "password": PW, "role": "viewer"}).status_code == 403
    assert env.client.get("/v1/audit", headers=v).status_code == 403


def test_admin_user_management_and_immediate_deactivation(env):
    r = env.client.post("/v1/users", headers=env.h, json={"email": "new@acme.test", "password": PW, "role": "analyst"})
    assert r.status_code == 201
    dup = env.client.post("/v1/users", headers=env.h, json={"email": "new@acme.test", "password": PW, "role": "analyst"})
    assert dup.status_code == 409
    weak = env.client.post("/v1/users", headers=env.h, json={"email": "w@acme.test", "password": "short", "role": "viewer"})
    assert weak.status_code == 422
    tok = env.login("new@acme.test")
    assert env.client.get("/v1/auth/me", headers=tok).status_code == 200
    assert env.client.delete(f"/v1/users/{r.json()['id']}", headers=env.h).status_code == 200
    assert env.client.get("/v1/auth/me", headers=tok).status_code == 401  # token dies with the account
    assert env.client.delete(f"/v1/users/{env.admin['id']}", headers=env.h).status_code == 422


def test_api_keys_shown_once_hashed_and_revocable(env):
    r = env.client.post("/v1/api-keys", headers=env.h, json={"label": "ci", "role": "analyst"}).json()
    key = r["key"]
    assert key.startswith("avk_")
    stored = env.client.get("/v1/api-keys", headers=env.h).json()["items"]
    assert key not in str(stored)
    assert env.client.get("/v1/auth/me", headers={"X-API-Key": key}).json()["via"] == "api_key"
    env.client.delete(f"/v1/api-keys/{r['id']}", headers=env.h)
    assert env.client.get("/v1/auth/me", headers={"X-API-Key": key}).status_code == 401


def test_cross_tenant_isolation(env):
    other = env.store.create_org("globex")
    env.add_user(other["id"], "eve@globex.test", "admin")
    eve = env.login("eve@globex.test")
    q = env.scan("acme/secret-repo", zip_dir(FIX / "insecure"))
    rid, run_id = q.json()["repositoryId"], q.json()["runId"]
    fid = env.client.get(f"/v1/repositories/{rid}/findings", headers=env.h).json()["items"][0]["id"]
    for path in (f"/v1/repositories/{rid}/analyses", f"/v1/repositories/{rid}/analyses/{run_id}",
                 f"/v1/repositories/{rid}/findings", f"/v1/findings/{fid}", f"/v1/analyses/{run_id}/score"):
        r = env.client.get(path, headers=eve)
        assert r.status_code == 404, path
    assert env.client.post(f"/v1/findings/{fid}/dispositions", headers=eve,
                           json={"type": "false_positive", "rationale": "mine now", "expected_version": 1}).status_code == 404
    assert env.client.get("/v1/repositories", headers=eve).json()["items"] == []
    assert env.client.get("/v1/jobs", headers=eve).json()["items"] == []
    assert all("acme" not in str(i) for i in env.client.get("/v1/audit", headers=eve).json()["items"])
    # same repo name in another org is a different repository
    q2 = env.scan("acme/secret-repo", zip_dir(FIX / "secure"), headers=eve)
    assert q2.json()["repositoryId"] != rid
