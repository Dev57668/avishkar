import hashlib
import hmac
import io
import json
import zipfile

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from avishkar.adapters import github as gh

from .conftest import FIX, Env

SECRET = "whsec_test"
SHA = "a" * 40
SHA2 = "b" * 40


@pytest.fixture(scope="module")
def keypair():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


class FakeGitHub:
    """Records API calls; serves a zipball with a GitHub-style top-level directory."""

    def __init__(self, pub, fixture="insecure", fail_zip=False):
        self.calls, self.pub, self.fixture, self.fail_zip = [], pub, fixture, fail_zip
        self.checks = {}

    def zipball(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for p in (FIX / self.fixture).rglob("*"):
                if p.is_file():
                    z.write(p, "acme-app-abc123/" + p.relative_to(FIX / self.fixture).as_posix())
        return buf.getvalue()

    def __call__(self, req: httpx.Request):
        path = req.url.path
        self.calls.append((req.method, path))
        auth = req.headers.get("authorization", "")
        if path.endswith("/access_tokens"):
            claims = jwt.decode(auth[7:], self.pub, algorithms=["RS256"])  # proves RS256 App JWT
            assert claims["iss"] == "123" and claims["exp"] - claims["iat"] <= 600
            return httpx.Response(201, json={"token": "ghs_shortlived"})
        assert auth == "Bearer ghs_shortlived"  # installation token, never the JWT or a PAT
        if "/zipball/" in path:
            return httpx.Response(500) if self.fail_zip else httpx.Response(200, content=self.zipball())
        if req.method == "POST" and path.endswith("/check-runs"):
            cid = 100 + len(self.checks)
            self.checks[cid] = {"create": json.loads(req.content)}
            return httpx.Response(201, json={"id": cid})
        if req.method == "PATCH" and "/check-runs/" in path:
            self.checks[int(path.rsplit("/", 1)[1])]["final"] = json.loads(req.content)
            return httpx.Response(200, json={})
        return httpx.Response(404)


def make_env(tmp_path, keypair, **kw):
    priv, pub = keypair
    fake = FakeGitHub(pub, **kw)
    client = gh.GitHubClient("123", priv, "https://api.github.test", transport=httpx.MockTransport(fake))
    e = Env(tmp_path, github=client, webhook_secret=SECRET)
    return e, fake


def deliver(e, event, payload, delivery="d1", secret=SECRET, sig=None, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    sig = sig or "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return e.client.post("/v1/github/webhook", content=body, headers={
        "X-GitHub-Event": event, "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sig,
        "Content-Type": "application/json"})


def pr_payload(sha=SHA, action="synchronize", inst=777, repo="acme/app", number=5):
    return {"action": action, "installation": {"id": inst}, "repository": {"full_name": repo},
            "pull_request": {"number": number, "head": {"sha": sha, "repo": {"full_name": repo}}}}


def link(e):
    assert e.client.post("/v1/github/installations", headers=e.h,
                         json={"installation_id": "777", "account": "acme"}).status_code == 201


# ---------------------------------------------------------------- signature & replay
def test_signature_unit():
    body = b'{"a":1}'
    good = "sha256=" + hmac.new(b"s", body, hashlib.sha256).hexdigest()
    assert gh.verify_signature("s", body, good)
    assert not gh.verify_signature("s", body + b" ", good)
    assert not gh.verify_signature("s", body, None) and not gh.verify_signature("", body, good)
    assert not gh.verify_signature("s", body, "sha1=abc") and not gh.verify_signature("other", body, good)


def test_webhook_disabled_without_secret(tmp_path):
    e = Env(tmp_path, webhook_secret="")
    assert deliver(e, "ping", {}, secret="x").status_code == 503


def test_forged_and_altered_requests_rejected_without_parsing(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair)
    link(e)
    assert deliver(e, "pull_request", pr_payload(), sig="sha256=" + "0" * 64).status_code == 401
    assert deliver(e, "pull_request", pr_payload(), secret="wrong").status_code == 401
    assert deliver(e, "pull_request", None, raw=b"not json", sig="sha256=bad").status_code == 401
    assert e.app.state.metrics["webhook_bad_signature"] == 3
    assert e.store.jobs(e.org["id"]) == [] and fake.calls == []


def test_replayed_delivery_is_idempotent(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair)
    link(e)
    r1 = deliver(e, "pull_request", pr_payload(), delivery="same")
    r2 = deliver(e, "pull_request", pr_payload(), delivery="same")
    assert r1.status_code == 202 and r1.json()["status"] == "queued"
    assert r2.json()["status"] == "duplicate"
    assert len(e.store.jobs(e.org["id"])) == 1


def test_redelivery_with_new_id_same_commit_dedupes(tmp_path, keypair):
    e, _ = make_env(tmp_path, keypair)
    link(e)
    deliver(e, "pull_request", pr_payload(), delivery="a")
    r = deliver(e, "pull_request", pr_payload(), delivery="b")
    assert r.json()["status"] == "deduplicated" and len(e.store.jobs(e.org["id"])) == 1


def test_ping_ignored_events_and_malformed(tmp_path, keypair):
    e, _ = make_env(tmp_path, keypair)
    assert deliver(e, "ping", {"zen": "x"}, delivery="p").json()["status"] == "pong"
    assert deliver(e, "issues", {"action": "opened"}, delivery="i").json()["status"] == "ignored"
    assert deliver(e, "pull_request", pr_payload(action="closed"), delivery="c").json()["status"] == "ignored"
    assert deliver(e, "push", {"ref": "refs/tags/v1", "after": SHA}, delivery="t").json()["status"] == "ignored"
    assert deliver(e, "pull_request", None, raw=b"{bad", delivery="m",
                   sig="sha256=" + hmac.new(SECRET.encode(), b"{bad", hashlib.sha256).hexdigest()).status_code == 400


def test_unknown_or_unlinked_installation_is_ignored_silently(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair)
    r = deliver(e, "pull_request", pr_payload(inst=999))
    assert r.status_code == 202 and r.json() == {"status": "ignored"}
    assert e.store.jobs(e.org["id"]) == [] and fake.calls == []


def test_bad_repo_or_sha_rejected(tmp_path, keypair):
    e, _ = make_env(tmp_path, keypair)
    link(e)
    assert deliver(e, "pull_request", pr_payload(sha="notasha"), delivery="1").json()["status"] == "ignored"
    assert deliver(e, "pull_request", pr_payload(repo="../../etc"), delivery="2").json()["status"] == "ignored"


# ---------------------------------------------------------------- end to end
def test_pull_request_end_to_end_check_run(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair)
    link(e)
    assert deliver(e, "pull_request", pr_payload()).status_code == 202
    e.runner.drain()
    (c,) = fake.checks.values()
    assert c["create"]["head_sha"] == SHA and c["create"]["status"] == "in_progress"
    fin = c["final"]
    # report-only policy => would_block is neutral; critical secret present
    assert fin["status"] == "completed" and fin["conclusion"] == "neutral"
    assert "would block" in fin["output"]["summary"].lower()
    assert "AKIAQ3EXZ4HT7WN2K5ML" not in json.dumps(c)  # no raw secret leaves the system
    repos = e.client.get("/v1/repositories", headers=e.h).json()["items"]
    assert repos[0]["name"] == "acme/app" and repos[0]["latestRawUnits"] > 0


def test_clean_pr_conclusion_success(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair, fixture="secure")
    link(e)
    deliver(e, "push", {"ref": "refs/heads/main", "after": SHA, "installation": {"id": 777},
                        "repository": {"full_name": "acme/app"}})
    e.runner.drain()
    assert list(fake.checks.values())[0]["final"]["conclusion"] == "success"


def test_failed_analysis_is_never_success(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair, fail_zip=True)
    link(e)
    q = deliver(e, "pull_request", pr_payload()).json()
    e.runner.drain()  # 3 attempts then dead-letter
    assert e.store.job(q["jobId"])["status"] == "dead"
    finals = [c["final"]["conclusion"] for c in fake.checks.values() if "final" in c]
    assert finals and set(finals) == {"action_required"}  # missing scan is not a pass


def test_stale_commit_cannot_masquerade_as_current(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair)
    link(e)
    deliver(e, "pull_request", pr_payload(sha=SHA), delivery="old")
    deliver(e, "pull_request", pr_payload(sha=SHA2), delivery="new")  # newer head arrives before old job runs
    e.runner.drain()
    by_sha = {c["create"]["head_sha"]: c["final"] for c in fake.checks.values()}
    assert by_sha[SHA]["conclusion"] == "neutral" and "Superseded" in by_sha[SHA]["output"]["summary"]
    assert "Superseded" not in by_sha[SHA2]["output"]["summary"]


def test_revoked_installation_stops_processing(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair)
    link(e)
    deliver(e, "pull_request", pr_payload(), delivery="queued-before-revoke")
    deliver(e, "installation", {"action": "deleted", "installation": {"id": 777}}, delivery="rev")
    e.runner.drain()
    assert not any("zipball" in p for _, p in fake.calls)  # no checkout after revocation
    assert deliver(e, "pull_request", pr_payload(sha=SHA2), delivery="after").json()["status"] == "ignored"


def test_installation_cannot_be_claimed_by_second_org(tmp_path, keypair):
    e, _ = make_env(tmp_path, keypair)
    link(e)
    other = e.store.create_org("globex")
    e.add_user(other["id"], "eve@globex.test", "admin")
    r = e.client.post("/v1/github/installations", headers=e.login("eve@globex.test"),
                      json={"installation_id": "777", "account": "stolen"})
    assert r.status_code == 409
    e.add_user(e.org["id"], "v@acme.test", "viewer")
    assert e.client.post("/v1/github/installations", headers=e.login("v@acme.test"),
                         json={"installation_id": "5", "account": "x"}).status_code == 403


def test_results_land_in_installation_org_only(tmp_path, keypair):
    e, _ = make_env(tmp_path, keypair)
    link(e)
    other = e.store.create_org("globex")
    e.add_user(other["id"], "eve@globex.test", "admin")
    deliver(e, "pull_request", pr_payload())
    e.runner.drain()
    assert e.client.get("/v1/repositories", headers=e.login("eve@globex.test")).json()["items"] == []


def test_conclusion_mapping_unit():
    inc = {"status": "incomplete", "completeness": {"missing": ["secrets"]}, "decision": {}}
    assert gh.conclusion_for(inc, "enforce")[0] == "action_required"
    ok = {"status": "complete", "completeness": {}, "decision": {"outcome": "block", "reasons": ["x"]}}
    assert gh.conclusion_for(ok, "enforce")[0] == "failure"
    ok["decision"]["outcome"] = "pass"
    assert gh.conclusion_for(ok, "enforce")[0] == "success"


def test_installation_token_cached_and_not_persisted(tmp_path, keypair):
    e, fake = make_env(tmp_path, keypair)
    link(e)
    deliver(e, "pull_request", pr_payload(), delivery="1")
    deliver(e, "pull_request", pr_payload(sha=SHA2), delivery="2")
    e.runner.drain()
    assert sum(1 for _, p in fake.calls if p.endswith("/access_tokens")) == 1
    dump = "".join(str(r) for t in ("job", "audit_event", "webhook_delivery")
                   for r in e.store.d.query(f"SELECT * FROM {t}"))
    assert "ghs_shortlived" not in dump
