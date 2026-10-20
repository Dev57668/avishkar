import json
import subprocess
import sys
from pathlib import Path

from avishkar import telemetry
from avishkar.calibration import render_markdown, run_calibration
from avishkar.domain import reporting

from .conftest import FIX, Env, zip_dir
from .test_github import SHA, deliver, keypair, link, make_env, pr_payload  # noqa: F401

CORPUS = Path(__file__).resolve().parents[1] / "corpus"


# ------------------------------------------------------------------ SARIF
def test_sarif_endpoint_structure_and_separate_debt_fields(env):
    q = env.scan("r/s", zip_dir(FIX / "insecure"))
    r = env.client.get(f"/v1/analyses/{q.json()['runId']}/sarif", headers=env.h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/sarif+json")
    s = r.json()
    assert s["version"] == "2.1.0" and s["runs"][0]["tool"]["driver"]["name"] == "Avishkar"
    res = s["runs"][0]["results"]
    assert res and all({"ruleId", "level", "locations", "partialFingerprints"} <= set(x) for x in res)
    ids = {r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]}
    assert all(x["ruleId"] in ids and s["runs"][0]["tool"]["driver"]["rules"][x["ruleIndex"]]["id"] == x["ruleId"] for x in res)
    assert {x["level"] for x in res} <= {"error", "warning", "note"}
    av = s["runs"][0]["properties"]["avishkar"]  # debt fields are NOT mixed into standard SARIF fields
    assert av["calibrated"] is False and av["rawUnits"] > 0 and s["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert "AKIAQ3EXZ4HT7WN2K5ML" not in r.text


def test_sarif_incomplete_run_is_marked_unsuccessful(env, monkeypatch):
    monkeypatch.setattr(env.sandbox, "collect", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    q = env.scan("r/s2", zip_dir(FIX / "secure"))
    s = env.client.get(f"/v1/analyses/{q.json()['runId']}/sarif", headers=env.h).json()
    inv = s["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False and "NOT a pass" in inv["toolExecutionNotifications"][0]["message"]["text"]
    assert s["runs"][0]["properties"]["avishkar"]["normalizedIndex"] is None


def test_sarif_marks_suppressed_and_is_tenant_scoped(env):
    q = env.scan("r/s3", zip_dir(FIX / "insecure"))
    rid = q.json()["repositoryId"]
    f = env.client.get(f"/v1/repositories/{rid}/findings", headers=env.h).json()["items"][0]
    env.client.post(f"/v1/findings/{f['id']}/dispositions", headers=env.h,
                    json={"type": "false_positive", "rationale": "fixture", "expected_version": f["version"]})
    s = env.client.get(f"/v1/analyses/{q.json()['runId']}/sarif", headers=env.h).json()
    assert any(r.get("suppressions") for r in s["runs"][0]["results"])
    other = env.store.create_org("globex")
    env.add_user(other["id"], "eve@globex.test", "viewer")
    assert env.client.get(f"/v1/analyses/{q.json()['runId']}/sarif", headers=env.login("eve@globex.test")).status_code == 404


def test_cli_sarif_and_exit_codes(tmp_path):
    out = tmp_path / "o.sarif"
    root = Path(__file__).resolve().parents[2]
    p = subprocess.run([sys.executable, "-m", "avishkar", "scan", str(FIX / "insecure"), "--sarif", str(out)],
                       cwd=root, capture_output=True, text=True)
    assert p.returncode == 0 and json.loads(out.read_text())["version"] == "2.1.0"
    p = subprocess.run([sys.executable, "-m", "avishkar", "scan", str(FIX / "insecure"), "--fail-on", "block"],
                       cwd=root, capture_output=True, text=True)
    assert p.returncode == 2  # would_block under report-only still fails the CI gate when asked
    p = subprocess.run([sys.executable, "-m", "avishkar", "scan", str(tmp_path / "nope")], cwd=root, capture_output=True, text=True)
    assert p.returncode == 3  # unreadable target is incomplete, not a pass


# ------------------------------------------------------------------ PR comments
class CommentFake:
    def __init__(self):
        self.comments, self.next = [], 1

    def attach(self, fake):
        base = fake.__call__

        def handler(req):
            import httpx
            path = req.url.path
            if "/issues/" in path and path.endswith("/comments"):
                if req.method == "GET":
                    return httpx.Response(200, json=self.comments)
                self.comments.append({"id": self.next, "body": json.loads(req.content)["body"]})
                self.next += 1
                return httpx.Response(201, json={"id": self.next - 1})
            if "/issues/comments/" in path and req.method == "PATCH":
                cid = int(path.rsplit("/", 1)[1])
                for c in self.comments:
                    if c["id"] == cid:
                        c["body"] = json.loads(req.content)["body"]
                return httpx.Response(200, json={})
            return base(req)
        return handler


def test_pr_comment_created_then_updated_in_place(tmp_path, monkeypatch):
    import httpx
    from avishkar.adapters import github as gh
    monkeypatch.setenv("AVISHKAR_PR_COMMENTS", "1")
    from .test_github import FakeGitHub, keypair  # noqa: F401
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    fake = FakeGitHub(pub)
    cf = CommentFake()
    client = gh.GitHubClient("123", priv, "https://api.github.test", transport=httpx.MockTransport(cf.attach(fake)))
    e = Env(tmp_path, github=client, webhook_secret="whsec_test")
    link(e)
    deliver(e, "pull_request", pr_payload(), delivery="1")
    e.runner.drain()
    assert len(cf.comments) == 1 and reporting.MARKER in cf.comments[0]["body"]
    body = cf.comments[0]["body"]
    assert "uncalibrated" in body and "AKIAQ3EXZ4HT7WN2K5ML" not in body and "not a breach probability" in body
    deliver(e, "pull_request", pr_payload(sha="c" * 40), delivery="2")
    e.runner.drain()
    assert len(cf.comments) == 1  # edited in place, not spammed


def test_pr_comment_off_by_default(tmp_path, keypair, monkeypatch):
    monkeypatch.delenv("AVISHKAR_PR_COMMENTS", raising=False)
    e, fake = make_env(tmp_path, keypair)
    link(e)
    deliver(e, "pull_request", pr_payload())
    e.runner.drain()
    assert not any("/comments" in p for _, p in fake.calls)


def test_summary_incomplete_is_not_a_pass():
    md = reporting.render_summary("incomplete", {}, {"outcome": "not_evaluated"}, {"missing": ["secrets"]}, [])
    assert "not a pass" in md and "secrets" in md and md.startswith(reporting.MARKER)
    clean = reporting.render_summary("complete", {"rawUnits": 0, "normalizedIndex": 0, "scoreVersion": "score-v1"},
                                     {"outcome": "pass", "policyVersion": "p", "mode": "report_only"}, {}, [])
    assert "does not prove" in clean


# ------------------------------------------------------------------ telemetry
def test_tracing_records_safe_attributes_only(tmp_path):
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    exp = InMemorySpanExporter()
    assert telemetry.configure_tracing(exp)
    try:
        e = Env(tmp_path)
        e.scan("r/t", zip_dir(FIX / "insecure"))
        spans = {s.name: s for s in exp.get_finished_spans()}
        assert {"job", "sandbox_collect", "assemble", "persist"} <= set(spans)
        assert spans["job"].attributes["kind"] == "archive"
        dump = json.dumps([dict(s.attributes) for s in spans.values()])
        assert "AKIA" not in dump and "app.py" not in dump
        with telemetry.span("x", correlation_id="c1", source_code="SECRET", path="a.py") as _:
            pass
        last = exp.get_finished_spans()[-1]
        assert dict(last.attributes) == {"correlation_id": "c1"}  # non-allowlisted keys dropped
    finally:
        telemetry.disable_tracing()


def test_span_is_noop_without_tracing():
    telemetry.disable_tracing()
    with telemetry.span("noop", job_id="j"):
        pass


def test_span_marks_errors(tmp_path):
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    exp = InMemorySpanExporter()
    telemetry.configure_tracing(exp)
    try:
        try:
            with telemetry.span("boom"):
                raise ValueError("x")
        except ValueError:
            pass
        assert exp.get_finished_spans()[-1].attributes["error.type"] == "ValueError"
    finally:
        telemetry.disable_tracing()


# ------------------------------------------------------------------ calibration
def test_calibration_report_is_evidence_not_approval():
    r = run_calibration(CORPUS)
    assert r["calibrated"] is False and "NOT CALIBRATED" in r["verdict"]
    assert any("adjudicated" in b for b in r["approvalBlockers"]) and any("too small" in b for b in r["approvalBlockers"])
    assert all(v["monotonic"] for v in r["factorSensitivity"].values())
    s = r["stabilityAndGaming"]
    assert s["identicalInputsIdenticalScore"] and s["corpusReplayIdentical"] and s["acceptingRiskDoesNotLowerIndex"] and s["fixingLowersIndex"]
    assert r["detectors"]["byRule"]["PY-EVAL"]["precision"] == 1.0 and r["detectors"]["totalCases"] == 6
    assert "currentK" in r["normalization"] and "indexByCandidateK" in r["normalization"]
    assert "Approval blockers" in render_markdown(r)


def test_calibration_counts_false_positives_and_misses(tmp_path):
    d = tmp_path / "c1"
    d.mkdir()
    (d / "a.py").write_text("x = eval(s)\n")
    (d / "labels.json").write_text(json.dumps({"expected": [{"rule": "PY-SHELL", "path": "a.py"}]}))
    r = run_calibration(tmp_path)
    assert r["detectors"]["byRule"]["PY-EVAL"]["fp"] == 1 and r["detectors"]["byRule"]["PY-SHELL"]["fn"] == 1
