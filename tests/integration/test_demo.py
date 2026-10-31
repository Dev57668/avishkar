from pathlib import Path

import pytest

from avishkar.workers import runner as runner_mod
from avishkar.demo import DemoSettings, seed_demo

from .conftest import FIX, PW, Env, zip_dir

DEMO = DemoSettings(enabled=True, uploads="admin", publish_login=True, email="demo@avishkar.dev", password="demo-view-only-1")


def demo_env(tmp_path, **kw):
    e = Env(tmp_path, demo=kw.pop("demo", DEMO), **kw)
    seed_demo(e.store, e.app.state.cfg, e.app.state.pol, e.sandbox, e.app.state.demo)
    return e


# ---------------------------------------------------------------- public status
def test_public_status_needs_no_auth_and_leaks_no_secrets(tmp_path):
    e = Env(tmp_path, demo=DEMO)
    r = e.client.get("/v1/public/status")
    assert r.status_code == 200
    j = r.json()
    assert j["demo"] is True and j["uploads"] == "admin" and j["calibrated"] is False
    assert j["demoLogin"] == {"email": "demo@avishkar.dev", "password": "demo-view-only-1", "role": "viewer"}
    text = r.text
    assert "s" * 40 not in text and PW not in text and "admin@acme.test" not in text  # no admin/secret material


def test_demo_login_is_hidden_unless_operator_opted_in(tmp_path):
    for s in (DemoSettings(enabled=True, uploads="admin", publish_login=False, password="demo-view-only-1"),
              DemoSettings(enabled=False, publish_login=True, password="demo-view-only-1"),
              DemoSettings(enabled=True, publish_login=True, password="")):
        assert Env(tmp_path / str(id(s)), demo=s).client.get("/v1/public/status").json()["demoLogin"] is None


def test_default_instance_is_not_demo_and_allows_uploads(env):
    j = env.client.get("/v1/public/status").json()
    assert j["demo"] is False and j["uploads"] == "all" and j["demoLogin"] is None


# ---------------------------------------------------------------- upload policy
def test_uploads_admin_only(tmp_path):
    e = demo_env(tmp_path)
    e.add_user(e.org["id"], "ana@acme.test", "analyst")
    analyst = e.login("ana@acme.test")
    r = e.scan("r/x", zip_dir(FIX / "secure"), headers=analyst, drain=False)
    assert r.status_code == 403 and r.json()["error"]["code"] == "uploads_disabled"
    assert e.store.jobs(e.org["id"]) == []
    assert not list(runner_mod.SPOOL_DIR.glob("*.zip"))  # rejected before anything was spooled
    assert e.scan("r/x", zip_dir(FIX / "secure"), headers=e.h, drain=False).status_code == 202  # admin may


def test_uploads_off_blocks_everyone_and_api_keys(tmp_path):
    e = Env(tmp_path, demo=DemoSettings(uploads="off"))
    assert e.scan("r/x", zip_dir(FIX / "secure"), headers=e.h, drain=False).status_code == 403
    key = e.api_key(e.org["id"], "admin")
    assert e.scan("r/x", zip_dir(FIX / "secure"), headers=key, drain=False).status_code == 403


def test_uploads_default_all_unchanged(env):
    assert env.scan("r/x", zip_dir(FIX / "secure"), drain=False).status_code == 202


def test_config_reports_upload_policy(tmp_path):
    e = Env(tmp_path, demo=DEMO)
    assert e.client.get("/v1/config", headers=e.h).json()["uploads"] == "admin"


def test_bad_upload_mode_env_is_rejected(monkeypatch):
    monkeypatch.setenv("AVISHKAR_UPLOADS", "everyone")
    with pytest.raises(ValueError):
        DemoSettings.from_env()


# ---------------------------------------------------------------- seeding & the read-only viewer
def test_seed_is_idempotent_and_real(tmp_path):
    e = demo_env(tmp_path)
    again = seed_demo(e.store, e.app.state.cfg, e.app.state.pol, e.sandbox, DEMO)
    assert again == {"viewer": False, "repos": []}  # nothing duplicated
    v = e.login("demo@avishkar.dev", "demo-view-only-1")
    repos = {r["name"]: r for r in e.client.get("/v1/repositories", headers=v).json()["items"]}
    from avishkar import samples
    assert set(repos) == {f"demo/{sid}" for sid in samples.SAMPLES}  # every bundled sample, including manifest-defined ones
    py = repos["demo/vulnerable-python"]
    assert py["runs"] == 2 and py["latestIndex"] == 0.0  # the all-fixes run is the latest, not the first
    assert repos["demo/secure-python"]["runs"] == 1 and repos["demo/secure-python"]["latestIndex"] == 0.0


def test_seeded_before_after_runs_match_the_published_results_file(tmp_path):
    """The numbers on the landing page (web/demo_results.json) must equal what a real scan produces."""
    import json
    golden = json.loads((Path(__file__).resolve().parents[2] / "web" / "demo_results.json").read_text())
    e = demo_env(tmp_path)
    v = e.login("demo@avishkar.dev", "demo-view-only-1")
    rid = next(r["id"] for r in e.client.get("/v1/repositories", headers=v).json()["items"] if r["name"].endswith("vulnerable-python"))
    runs = e.client.get(f"/v1/repositories/{rid}/analyses", headers=v).json()["items"]
    by = {r["commitSha"]: r["securityDebt"] for r in runs}
    g = golden["samples"]["vulnerable-python"]
    assert by["sample"]["normalizedIndex"] == g["before"]["normalizedIndex"] and by["sample"]["grossUnits"] == g["before"]["grossUnits"]
    after_label = f"sample + {g['fixCount']} fixes"
    assert by[after_label]["normalizedIndex"] == g["after"]["normalizedIndex"] == 0.0
    findings = e.client.get(f"/v1/repositories/{rid}/findings?limit=200", headers=v).json()
    assert findings["total"] == g["before"]["findings"] and {f["state"] for f in findings["items"]} == {"fixed"}


def test_unsupported_java_sample_is_not_evaluated_not_clean(tmp_path):
    e = demo_env(tmp_path)
    v = e.login("demo@avishkar.dev", "demo-view-only-1")
    rid = next(r["id"] for r in e.client.get("/v1/repositories", headers=v).json()["items"] if r["name"].endswith("java"))
    run = e.client.get(f"/v1/repositories/{rid}/analyses", headers=v).json()["items"][0]
    assert run["status"] == "incomplete" and run["decision"]["outcome"] == "not_evaluated"
    assert run["securityDebt"]["normalizedIndex"] is None


def test_demo_viewer_is_strictly_read_only(tmp_path):
    e = demo_env(tmp_path)
    v = e.login("demo@avishkar.dev", "demo-view-only-1")
    assert e.client.get("/v1/auth/me", headers=v).json()["role"] == "viewer"
    rid = next(r["id"] for r in e.client.get("/v1/repositories", headers=v).json()["items"] if r["name"] == "demo/vulnerable-python")
    f = e.client.get(f"/v1/repositories/{rid}/findings", headers=v).json()["items"][0]
    assert e.scan("r/x", zip_dir(FIX / "secure"), headers=v, drain=False).status_code == 403
    assert e.client.post(f"/v1/findings/{f['id']}/dispositions", headers=v,
                         json={"type": "false_positive", "rationale": "vandalism", "expected_version": f["version"]}).status_code == 403
    assert e.client.post(f"/v1/findings/{f['id']}/explanation", headers=v).status_code == 403
    for path in ("/v1/users", "/v1/api-keys", "/v1/audit", "/v1/metrics", "/v1/jobs", "/v1/github/installations"):
        assert e.client.get(path, headers=v).status_code == 403, path
    assert e.client.post("/v1/users", headers=v, json={"email": "x@y.zz", "password": "longenough123", "role": "admin"}).status_code == 403
    assert e.client.get(f"/v1/analyses/{e.store.runs(rid)[0]['id']}/sarif", headers=v).status_code == 200  # read-only export ok


def test_seed_requires_an_organization_first(tmp_path):
    from avishkar.adapters.store import Store
    from avishkar.domain.policy import Policy
    from avishkar.domain.scoring import ScoreConfig
    from avishkar.workers.sandbox import Sandbox
    with pytest.raises(RuntimeError):
        seed_demo(Store(str(tmp_path / "x.db")), ScoreConfig.load(), Policy.load(), Sandbox("inline"), DEMO)


def test_seed_without_password_creates_no_viewer(tmp_path):
    e = Env(tmp_path, demo=DemoSettings(enabled=True, uploads="admin"))
    out = seed_demo(e.store, e.app.state.cfg, e.app.state.pol, e.sandbox, e.app.state.demo)
    assert out["viewer"] is False and e.store.user_by_email("demo@avishkar.dev") is None
