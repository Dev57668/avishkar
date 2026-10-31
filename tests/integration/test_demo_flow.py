import json
from pathlib import Path

import pytest

from avishkar import samples
from avishkar.demo import DemoSettings, demo_results, seed_demo
from avishkar.domain.policy import Policy
from avishkar.domain.scoring import ScoreConfig
from avishkar.workers.pipeline import run_scan

from .conftest import Env

CFG, POL = ScoreConfig.load(), Policy.load()
DEMO = DemoSettings(enabled=True, uploads="off", publish_login=True, password="demo-view-only-1")
GOLDEN = Path(__file__).resolve().parents[2] / "web" / "demo_results.json"


def scan_variant(sid, fixes, tmp_path):
    d = tmp_path / ("v_" + "_".join(fixes)[:40] if fixes else "v_base")
    samples.write_variant(sid, fixes, d)
    return run_scan(d, CFG, POL)


# ------------------------------------------------------------------ the fix packs are real and verified
@pytest.mark.parametrize("sid", [k for k, v in samples.SAMPLES.items() if v.fixes])
def test_every_fix_removes_its_findings_and_adds_none(sid, tmp_path):
    base = scan_variant(sid, [], tmp_path)
    base_fp = {f.fingerprint for f in base["findings"]}
    for fix in samples.SAMPLES[sid].fixes:
        after = scan_variant(sid, [fix.id], tmp_path)
        assert after["status"] == "complete", fix.id
        new = [f for f in after["findings"] if f.fingerprint not in base_fp]
        assert new == [], f"{fix.id} introduced {[(f.raw.rule_id, f.raw.line) for f in new]}"
        for rule in fix.removes:
            before_n = sum(1 for f in base["findings"] if f.raw.rule_id == rule and f.raw.path == fix.file)
            after_n = sum(1 for f in after["findings"] if f.raw.rule_id == rule and f.raw.path == fix.file)
            assert after_n < before_n, f"{fix.id} did not reduce {rule} in {fix.file} ({before_n} -> {after_n})"
        if not fix.removes:  # an honest "scanner cannot see this" fix must not change the score
            assert after["securityDebt"]["grossUnits"] == base["securityDebt"]["grossUnits"], fix.id


@pytest.mark.parametrize("sid", [k for k, v in samples.SAMPLES.items() if v.fixes])
def test_all_fixes_together_clear_the_sample_and_order_does_not_matter(sid, tmp_path):
    ids = [f.id for f in samples.SAMPLES[sid].fixes]
    a = scan_variant(sid, ids, tmp_path)
    assert a["status"] == "complete" and a["findings"] == [] and a["securityDebt"]["normalizedIndex"] == 0.0
    assert samples.variant_files(sid, ids) == samples.variant_files(sid, list(reversed(ids)))


def test_fixes_are_cumulative_and_the_index_never_rises(tmp_path):
    ids = [f.id for f in samples.SAMPLES["vulnerable-python"].fixes]
    last = scan_variant("vulnerable-python", [], tmp_path)["securityDebt"]["normalizedIndex"]
    for n in (3, 8, 14, len(ids)):
        cur = scan_variant("vulnerable-python", ids[:n], tmp_path)["securityDebt"]["normalizedIndex"]
        assert cur <= last
        last = cur
    assert last == 0.0


def test_secure_sample_is_clean_but_not_called_proof_of_safety(tmp_path):
    r = scan_variant("secure-python", [], tmp_path)
    assert r["status"] == "complete" and r["findings"] == [] and r["securityDebt"]["normalizedIndex"] == 0.0
    assert "not proof" in samples.SAMPLES["secure-python"].description.lower()


def test_unsupported_language_sample_is_not_evaluated(tmp_path):
    r = scan_variant("go-http-service", [], tmp_path)
    assert r["status"] == "incomplete" and r["securityDebt"]["normalizedIndex"] is None


def test_variant_helper_rejects_unknown_ids_and_never_mutates_the_originals():
    with pytest.raises(samples.SampleError):
        samples.variant_files("nope")
    with pytest.raises(samples.SampleError):
        samples.variant_files("vulnerable-python", ["py-secrets-app", "does-not-exist"])
    with pytest.raises(samples.SampleError):
        samples.variant_files("vulnerable-python", ["js-secrets"])  # a fix from another sample
    before = (samples.SAMPLES_DIR / "vulnerable-python" / "app.py").read_text()
    samples.variant_files("vulnerable-python", [f.id for f in samples.SAMPLES["vulnerable-python"].fixes])
    assert (samples.SAMPLES_DIR / "vulnerable-python" / "app.py").read_text() == before
    assert "os.system" in samples.variant_files("vulnerable-python")["app.py"]
    assert "os.system" not in samples.variant_files("vulnerable-python", ["py-cmd-ping"])["app.py"]
    assert "import subprocess" in samples.variant_files("vulnerable-python", ["py-cmd-ping"])["app.py"]


def test_fix_diff_is_a_real_unified_diff():
    d = samples.fix_diff("vulnerable-python", "py-eval-calc")
    assert d.startswith("--- a/app.py") and "-    return eval(expression)" in d and "+    return ast.literal_eval(expression)" in d


# ------------------------------------------------------------------ published numbers cannot go stale
def test_published_demo_results_equal_a_fresh_real_scan():
    fresh = json.loads(json.dumps(demo_results()))
    committed = json.loads(GOLDEN.read_text())
    assert committed == fresh, "web/demo_results.json is stale: run `python scripts/gen_demo_results.py` and commit"


# ------------------------------------------------------------------ the API flow a judge follows
def judge_env(tmp_path, demo=DEMO):
    e = Env(tmp_path, demo=demo)
    seed_demo(e.store, e.app.state.cfg, e.app.state.pol, e.sandbox, e.app.state.demo)
    return e, e.login("demo@avishkar.dev", "demo-view-only-1")


def wait(e, q, h):
    e.runner.drain()
    return e.client.get(q.json()["statusUrl"], headers=h).json()


def test_judge_flow_scan_fix_rescan_compare_with_real_results(tmp_path):
    e, v = judge_env(tmp_path)
    cat = e.client.get("/v1/demo/samples", headers=v).json()
    assert cat["scanAllowed"] is True and {s["id"] for s in cat["items"]} >= {"vulnerable-python", "secure-python"}
    py = next(s for s in cat["items"] if s["id"] == "vulnerable-python")
    assert py["fixes"][0]["explanation"] and py["files"][0]["lines"] > 5
    # 1. scan the vulnerable original (a viewer may run demo scans on the public instance)
    q1 = e.client.post("/v1/demo/scan", headers=v, json={"sample": "vulnerable-python"})
    assert q1.status_code == 202 and q1.json()["label"] == "sample"
    assert e.client.get(q1.json()["statusUrl"], headers=v).json()["status"] == "queued"
    r1 = wait(e, q1, v)
    assert r1["status"] == "complete" and r1["securityDebt"]["normalizedIndex"] == 93.8
    # the real stage timeline was recorded
    tl = [s["stage"] for s in r1["stages"]["timeline"]]
    assert tl[:1] == ["queued"] and tl[-1] == "complete" and {"preparing", "scanning", "scoring", "saving"} <= set(tl)
    # 2. apply two fixes to the sample and rescan
    fixes = ["py-eval-calc", "py-cmd-ping"]
    src = e.client.get("/v1/demo/samples/vulnerable-python", params={"fixes": ",".join(fixes)}, headers=v).json()
    assert "ast.literal_eval" in src["files"]["app.py"] and set(src["diffs"]) == set(fixes)
    q2 = e.client.post("/v1/demo/scan", headers=v, json={"sample": "vulnerable-python", "fixes": fixes})
    r2 = wait(e, q2, v)
    assert q2.json()["label"] == "sample + 2 fixes" and r2["securityDebt"]["normalizedIndex"] < 93.8
    # 3. compare: the delta is explained by exactly the removed findings
    cmp = e.client.get(f"/v1/repositories/{q1.json()['repositoryId']}/compare",
                       params={"base": q1.json()["runId"], "head": q2.json()["runId"]}, headers=v).json()
    assert cmp["comparable"] and cmp["reconciles"] and cmp["introduced"] == []
    assert {x["rule"] for x in cmp["fixed"]} == {"PY-EVAL", "PY-SHELL"} and len(cmp["fixed"]) == 2  # the eval call and the ping shell call
    assert cmp["delta"]["index"] < 0


def test_demo_scan_results_equal_direct_pipeline_results(tmp_path):
    e, v = judge_env(tmp_path)
    q = e.client.post("/v1/demo/scan", headers=v, json={"sample": "vulnerable-javascript"})
    r = wait(e, q, v)
    direct = scan_variant("vulnerable-javascript", [], tmp_path)
    assert r["securityDebt"]["normalizedIndex"] == direct["securityDebt"]["normalizedIndex"]
    assert r["securityDebt"]["grossUnits"] == direct["securityDebt"]["grossUnits"]


def test_demo_scan_permissions_validation_and_rate_limit(tmp_path):
    # not a demo instance: viewers may not trigger scans, analysts may
    e = Env(tmp_path)
    e.add_user(e.org["id"], "view@acme.test", "viewer")
    e.add_user(e.org["id"], "ana@acme.test", "analyst")
    assert e.client.post("/v1/demo/scan", headers=e.login("view@acme.test"), json={"sample": "secure-python"}).status_code == 403
    assert e.client.post("/v1/demo/scan", headers=e.login("ana@acme.test"), json={"sample": "secure-python"}).status_code == 202
    assert e.client.get("/v1/demo/samples", headers=e.login("view@acme.test")).json()["scanAllowed"] is False
    assert e.client.post("/v1/demo/scan", json={"sample": "secure-python"}).status_code == 401
    h = e.h
    assert e.client.post("/v1/demo/scan", headers=h, json={"sample": "../etc/passwd"}).status_code == 422
    assert e.client.post("/v1/demo/scan", headers=h, json={"sample": "nope"}).status_code == 404
    assert e.client.post("/v1/demo/scan", headers=h, json={"sample": "secure-python", "fixes": ["x"]}).status_code == 422
    assert e.client.post("/v1/demo/scan", headers=h, json={"sample": "vulnerable-python", "fixes": ["js-secrets"]}).status_code == 422
    assert e.client.post("/v1/demo/scan", headers=h, json={"sample": "secure-python", "extra": 1}).status_code == 422
    assert e.client.post("/v1/demo/scan", headers=h, json={"sample": "secure-python", "fixes": ["a"] * 61}).status_code == 422
    codes = [e.client.post("/v1/demo/scan", headers=h, json={"sample": "secure-python"}).status_code for _ in range(14)]
    assert 429 in codes and codes.count(202) <= 12  # at most 12 per minute per organization
    assert e.client.get("/v1/demo/samples/secure-python", params={"fixes": "a b"}, headers=h).status_code == 422


def test_demo_scans_are_tenant_scoped_and_audited(tmp_path):
    e, v = judge_env(tmp_path)
    q = e.client.post("/v1/demo/scan", headers=v, json={"sample": "secure-python"})
    other = e.store.create_org("globex")
    e.add_user(other["id"], "eve@globex.test", "analyst")
    eve = e.login("eve@globex.test")
    assert e.client.get(q.json()["statusUrl"], headers=eve).status_code == 404
    assert any(i["action"] == "demo_scan_queued" for i in e.client.get("/v1/audit", headers=e.h).json()["items"])


def test_old_demo_runs_are_pruned_but_the_ledger_is_kept(tmp_path):
    e, v = judge_env(tmp_path)
    rid = e.store.get_or_create_repo(e.org["id"], "demo/secure-python")["id"]
    for _ in range(45):
        e.store.create_run(rid, "sample", "c")
    q = e.client.post("/v1/demo/scan", headers=v, json={"sample": "secure-python"})
    wait(e, q, v)
    assert len(e.store.runs(rid, 500)) == 40
    assert e.store.runs(rid, 1)[0]["id"] == q.json()["runId"]
