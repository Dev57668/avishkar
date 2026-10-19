import time

from avishkar.workers.detectors import DETECTORS
from avishkar.workers.sandbox import Sandbox

from .conftest import FIX, Env, zip_dir


def test_auth_required_and_correlation_id(env):
    r = env.client.get("/v1/repositories")
    assert r.status_code == 401 and "correlationId" in r.json()["error"]
    assert env.client.get("/v1/repositories", headers={"X-API-Key": "avk_bad"}).status_code == 401
    assert env.client.get("/v1/repositories", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_scan_goes_through_queue_then_complete(env):
    q = env.scan("org/app", zip_dir(FIX / "insecure"), drain=False, commit_sha="abc123")
    assert q.status_code == 202 and q.json()["status"] == "queued"
    pending = env.run(q)
    assert pending["status"] == "queued" and pending["securityDebt"]["normalizedIndex"] is None
    assert pending["decision"]["outcome"] == "pending"  # not a pass
    env.runner.drain()
    run = env.run(q)
    assert run["status"] == "complete" and run["securityDebt"]["rawUnits"] > 0
    assert run["decision"]["outcome"] in ("would_block", "block")


def test_lifecycle_fix_and_rescan(env):
    q = env.scan("org/app", zip_dir(FIX / "insecure"))
    rid = q.json()["repositoryId"]
    items = env.client.get(f"/v1/repositories/{rid}/findings", headers=env.h).json()["items"]
    assert items and all(i["state"] == "open" for i in items)
    secret = next(i for i in items if i["rule_id"] == "SEC-AWS-KEY")
    assert "AKIAQ3EXZ4HT7WN2K5ML" not in str(secret) and "****" in secret["evidence"]
    r2 = env.run(env.scan("org/app", zip_dir(FIX / "secure")))
    assert r2["securityDebt"]["rawUnits"] == 0
    fixed = env.client.get(f"/v1/repositories/{rid}/findings?state=fixed", headers=env.h).json()["items"]
    assert len(fixed) == len(items)


def test_required_detector_failure_is_incomplete_not_pass(tmp_path):
    sbx = Sandbox("inline")
    sbx.detectors = {**DETECTORS, "dependencies": lambda root, files: (_ for _ in ()).throw(RuntimeError("crash"))}
    e = Env(tmp_path, sandbox=sbx)
    run = e.run(e.scan("org/x", zip_dir(FIX / "secure")))
    assert run["status"] == "incomplete" and run["securityDebt"]["status"] == "not_calculated"
    assert run["securityDebt"]["normalizedIndex"] is None and run["decision"]["outcome"] == "not_evaluated"
    assert run["completeness"]["missing"] == ["dependencies"]


def test_malformed_package_json_incomplete(env):
    run = env.run(env.scan("org/js", zip_dir(FIX / "secure", {"package.json": "{not json"})))
    assert run["status"] == "incomplete" and run["decision"]["outcome"] == "not_evaluated"


def test_zip_traversal_and_bad_zip_incomplete(env):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.py", "x=1")
    assert env.run(env.scan("org/evil", buf.getvalue()))["status"] == "incomplete"
    assert env.run(env.scan("org/bad", b"PK-not-really-a-zip"))["status"] == "incomplete"
    r = env.scan("org/nozip", b"plain text", drain=False)
    assert r.status_code == 422


def test_disposition_flow_and_concurrency(env):
    q = env.scan("org/d", zip_dir(FIX / "insecure"))
    rid = q.json()["repositoryId"]
    first = env.run(q)["securityDebt"]["rawUnits"]
    f = env.client.get(f"/v1/repositories/{rid}/findings", headers=env.h).json()["items"][0]
    body = {"type": "false_positive", "rationale": "Test fixture only", "expected_version": f["version"]}
    ok = env.client.post(f"/v1/findings/{f['id']}/dispositions", headers=env.h, json=body)
    assert ok.status_code == 200 and ok.json()["state"] == "false_positive"
    stale = env.client.post(f"/v1/findings/{f['id']}/dispositions", headers=env.h, json=body)
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "conflict"
    assert env.run(env.scan("org/d", zip_dir(FIX / "insecure")))["securityDebt"]["rawUnits"] < first


def test_accepted_risk_needs_expiry_and_stays_in_gross(env):
    q = env.scan("org/ar", zip_dir(FIX / "insecure"))
    rid = q.json()["repositoryId"]
    base = env.run(q)["securityDebt"]
    f = env.client.get(f"/v1/repositories/{rid}/findings?severity=critical", headers=env.h).json()["items"][0]
    bad = env.client.post(f"/v1/findings/{f['id']}/dispositions", headers=env.h,
                          json={"type": "accepted_risk", "rationale": "business decision", "expected_version": f["version"]})
    assert bad.status_code == 422
    ok = env.client.post(f"/v1/findings/{f['id']}/dispositions", headers=env.h,
                         json={"type": "accepted_risk", "rationale": "business decision",
                               "expires_at": time.time() + 3600, "expected_version": f["version"]})
    assert ok.status_code == 200
    again = env.run(env.scan("org/ar", zip_dir(FIX / "insecure")))["securityDebt"]
    assert again["grossUnits"] == base["grossUnits"] and again["rawUnits"] < again["grossUnits"]


def test_invalid_input_and_404_no_leak(env):
    assert env.client.get("/v1/findings/fnd_nope", headers=env.h).json()["error"]["message"] == "Not found"
    r = env.client.post("/v1/analyses", headers=env.h, data={"repository": "bad repo!"},
                        files={"archive": ("a.zip", b"PK")})
    assert r.status_code == 422


def test_audit_trail(env):
    env.scan("org/au", zip_dir(FIX / "secure"))
    actions = {i["action"] for i in env.client.get("/v1/audit", headers=env.h).json()["items"]}
    assert {"analysis_queued", "analysis_finished", "login"} <= actions


def test_config_reports_sandbox_and_ai(env):
    c = env.client.get("/v1/config", headers=env.h).json()
    assert c["sandbox"]["mode"] == "inline" and c["ai"]["enabled"] is False and c["database"] == "sqlite"
