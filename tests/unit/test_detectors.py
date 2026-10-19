from pathlib import Path

from avishkar.domain.policy import Policy
from avishkar.domain.scoring import ScoreConfig
from avishkar.workers.pipeline import run_scan

FIX = Path(__file__).resolve().parents[1] / "fixtures"
CFG, POL = ScoreConfig.load(), Policy.load()


def rules(res):
    return {f.raw.rule_id for f in res["findings"]}


def test_insecure_fixture_expected_rules():
    res = run_scan(FIX / "insecure", CFG, POL)
    assert {"SEC-AWS-KEY", "PY-EVAL", "PY-SHELL", "PY-SQLI", "PY-PICKLE", "PY-NOVERIFY", "PY-WEAKHASH",
            "JS-EVAL", "JS-INNERHTML", "DEP-DJANGO-OLD", "DEP-PYYAML", "DEP-UNPINNED"} <= rules(res)


def test_secure_fixture_is_clean():
    res = run_scan(FIX / "secure", CFG, POL)
    assert res["status"] == "complete" and not res["findings"]
    assert res["securityDebt"]["rawUnits"] == 0


def test_secrets_never_leak_in_findings():
    res = run_scan(FIX / "insecure", CFG, POL)
    for f in res["findings"]:
        assert "AKIAQ3EXZ4HT7WN2K5ML" not in f.raw.evidence


def test_fingerprint_stable_across_line_moves(tmp_path):
    (tmp_path / "a.py").write_text("x = eval(s)\n")
    a = {f.fingerprint for f in run_scan(tmp_path, CFG, POL)["findings"]}
    (tmp_path / "a.py").write_text("\n\n# note\nx = eval(s)\n")
    b = {f.fingerprint for f in run_scan(tmp_path, CFG, POL)["findings"]}
    assert a == b and a


def test_duplicates_counted_once(tmp_path):
    (tmp_path / "a.py").write_text("x = eval(s)\nx = eval(s)\n")
    res = run_scan(tmp_path, CFG, POL)
    assert len(res["findings"]) == 1


def test_placeholder_secret_is_low_confidence(tmp_path):
    (tmp_path / "c.py").write_text('password = "changeme-placeholder-1234"\n')
    res = run_scan(tmp_path, CFG, POL)
    assert all(f.raw.confidence.value == "low" for f in res["findings"])
    assert res["decision"]["outcome"] == "pass"


def test_symlinks_skipped_and_workspace_cleaned(tmp_path):
    import tempfile, glob, os
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "avishkar-*")))
    (tmp_path / "a.py").write_text("ok = 1\n")
    run_scan(tmp_path, CFG, POL)
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "avishkar-*")))
    assert after <= before


def test_scan_reproducible():
    a = run_scan(FIX / "insecure", CFG, POL)["securityDebt"]
    b = run_scan(FIX / "insecure", CFG, POL)["securityDebt"]
    assert a == b
