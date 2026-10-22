import json
import math
from dataclasses import replace
from pathlib import Path

import pytest

from avishkar import calibration as cal
from avishkar.domain.models import Confidence, Exposure, FindingRecord, RawFinding, Severity
from avishkar.domain.policy import Policy
from avishkar.domain.scoring import ScoreConfig
from avishkar.workers.pipeline import assemble, collect_findings

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "corpus"
CFG, POL = ScoreConfig.load(), Policy.load()


# ---------------------------------------------------------------- statistics
def test_wilson_lower_bound_known_values():
    assert cal.wilson_lower(0, 0) is None
    assert cal.wilson_lower(1, 1) == 0.207          # one success is NOT strong evidence
    assert cal.wilson_lower(50, 50) > 0.92          # many successes is
    assert cal.wilson_lower(8, 10) < cal.wilson_lower(80, 100) < 0.8  # same 80% rate: more data, tighter bound
    assert cal.wilson_lower(5, 10) < 0.5


def test_fit_k_inverts_the_normalization_formula():
    k = cal.fit_k(21.0, 80.0)
    assert round(100 * (1 - math.exp(-21.0 / k)), 6) == pytest.approx(80.0, abs=1e-3)
    for bad in [(0, 50), (-1, 50), (5, 0), (5, 100), (5, 120)]:
        with pytest.raises(ValueError):
            cal.fit_k(*bad)


def test_confidence_tiers_follow_evidence_and_never_trust_small_samples():
    rows = {"R@high": {"tp": 9, "fp": 0, "n": 9, "precision": 1.0, "wilsonLower95": cal.wilson_lower(9, 9)},
            "BIG@high": {"tp": 100, "fp": 0, "n": 100, "precision": 1.0, "wilsonLower95": cal.wilson_lower(100, 100)},
            "MID@high": {"tp": 70, "fp": 30, "n": 100, "precision": 0.7, "wilsonLower95": cal.wilson_lower(70, 100)},
            "BAD@high": {"tp": 20, "fp": 80, "n": 100, "precision": 0.2, "wilsonLower95": cal.wilson_lower(20, 100)},
            "TINY@high": {"tp": 3, "fp": 0, "n": 3, "precision": 1.0, "wilsonLower95": cal.wilson_lower(3, 3)}}
    t = {k: v["tier"] for k, v in cal.propose_rule_confidence(rows).items()}
    assert t == {"R@high": "high" if cal.wilson_lower(9, 9) >= 0.8 else "medium", "BIG@high": "high",
                 "MID@high": "medium", "BAD@high": "low", "TINY@high": "low"}
    assert "insufficient evidence" in cal.propose_rule_confidence(rows)["TINY@high"]["evidence"]


# ---------------------------------------------------------------- cap semantics in the pipeline
def _collected(conf="high", rule="PY-EVAL"):
    f = RawFinding("code-patterns", rule, "injection", Severity.HIGH, Confidence(conf), "t", "a.py", 1, "x = eval(s)",
                   Exposure.UNKNOWN)
    return {"raw": [f.to_dict()], "completed": list(CFG.required_detectors), "failed": {}, "stages": {}, "files": 1,
            "notes": [], "coverage": {"analyzedSourceFiles": 1, "notEvaluated": {}}}


def test_rule_confidence_can_lower_but_never_raise():
    lowered = replace(CFG, rule_confidence={"PY-EVAL@high": "low"})
    assert assemble(lowered, POL, _collected("high"))["findings"][0].raw.confidence.value == "low"
    raised = replace(CFG, rule_confidence={"PY-EVAL@low": "high"})
    assert assemble(raised, POL, _collected("low"))["findings"][0].raw.confidence.value == "low"  # not raised
    other = replace(CFG, rule_confidence={"PY-EVAL@high": "low"})
    assert assemble(other, POL, _collected("medium"))["findings"][0].raw.confidence.value == "medium"  # key mismatch


def test_lowered_confidence_lowers_debt_and_cannot_block():
    full = assemble(CFG, POL, _collected("high", "SEC-AWS-KEY"))
    capped = assemble(replace(CFG, rule_confidence={"SEC-AWS-KEY@high": "low"}), POL, _collected("high", "SEC-AWS-KEY"))
    assert capped["securityDebt"]["rawUnits"] < full["securityDebt"]["rawUnits"]
    enforce = Policy(POL.version, "enforce", POL.predicates)
    f = RawFinding("secrets", "SEC-AWS-KEY", "secret", Severity.CRITICAL, Confidence.HIGH, "t", "a.py", 1, "e")
    col = {**_collected(), "raw": [f.to_dict()]}
    assert assemble(CFG, enforce, col)["decision"]["outcome"] == "block"
    assert assemble(replace(CFG, rule_confidence={"SEC-AWS-KEY@high": "low"}), enforce, col)["decision"]["outcome"] == "pass"


def test_shipped_config_has_no_caps():
    assert CFG.rule_confidence == {} and ScoreConfig.load().version == "score-v1"


# ---------------------------------------------------------------- corpus & harness
def test_corpus_is_well_formed():
    cases = [d for d in CORPUS.iterdir() if d.is_dir()]
    assert len(cases) >= 40
    for d in cases:
        lab = json.loads((d / "labels.json").read_text())
        assert lab["adjudicated"] is False and lab["reviewers"] == 0  # we must never claim human adjudication
        assert lab["source"] in ("independent", "synthetic")
        for v in lab["vulns"]:
            assert (d / v["path"]).exists()
            if v["line"] is not None:
                text = (d / v["path"]).read_text(encoding="utf8").splitlines()
                assert 1 <= v["line"] <= len(text)


def test_independent_cases_are_byte_identical_to_sample_projects():
    for case, src in [("ind_python_app", "vulnerable-python"), ("ind_javascript_app", "vulnerable-javascript")]:
        for f in (CORPUS / case).iterdir():
            orig = ROOT / "sample_projects" / src / f.name
            if f.suffix in (".py", ".js"):
                assert f.read_bytes().replace(b"\r\n", b"\n") == orig.read_bytes().replace(b"\r\n", b"\n"), f


def test_unsupported_language_case_is_not_evaluated_not_clean():
    res = assemble(CFG, POL, collect_findings(CFG.required_detectors, source_dir=CORPUS / "ind_java_unsupported"))
    assert res["status"] == "incomplete" and res["decision"]["outcome"] == "not_evaluated"
    assert res["securityDebt"]["normalizedIndex"] is None
    assert res["securityDebt"]["coverage"]["notEvaluated"] == {".java": 1}
    assert any("NOT EVALUATED" in n for n in res["notes"])


def test_mixed_language_repo_is_complete_but_discloses_coverage(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "B.java").write_text("class B {}\n")
    res = assemble(CFG, POL, collect_findings(CFG.required_detectors, source_dir=tmp_path))
    assert res["status"] == "complete" and res["securityDebt"]["coverage"] == {
        "analyzedSourceFiles": 1, "notEvaluated": {".java": 1}}
    assert any("NOT EVALUATED" in n for n in res["notes"])


def test_report_never_claims_calibration_and_lists_honest_blockers():
    r = cal.run_calibration(CORPUS)
    assert r["calibrated"] is False and "NOT CALIBRATED" in r["verdict"]
    text = " ".join(r["approvalBlockers"])
    assert "adjudicated" in text and "independent" in text and "fewer than" in text
    assert r["detectors"]["statusMismatches"] == []
    assert r["detectors"]["independentCases"] == 3 and r["detectors"]["adjudicatedCases"] == 0


def test_precision_counts_and_known_detector_weaknesses_are_measured():
    d = cal.run_calibration(CORPUS)["detectors"]
    assert d["byRule"]["JS-EVAL"]["fp"] >= 1                     # model.eval() trap
    assert d["recallByKind"]["path-traversal"]["found"] == 0    # no rule exists: must show as missed, not hidden
    assert d["recallByKind"]["sqli"]["missed"] >= 1              # taint through a variable is not detected
    assert d["byRuleConfidence"]["SEC-GENERIC@low"]["fp"] >= 1   # placeholders flagged low, still not credentials


def test_unlabeled_findings_are_not_counted_as_false_positives(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "a.py").write_text("x = eval(s)\nimport pickle\npickle.loads(b)\n")
    (d / "labels.json").write_text(json.dumps({"source": "synthetic", "fully_labeled": False,
                                                "vulns": [{"path": "a.py", "line": 1, "kind": "eval"}]}))
    r = cal.evaluate_detectors(tmp_path, CFG, POL)["byRule"]
    assert r["PY-EVAL"]["tp"] == 1 and r["PY-PICKLE"]["fp"] == 0 and r["PY-PICKLE"]["unlabeled"] == 1


def test_line_must_match_when_given(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "a.py").write_text("x = 1\ny = eval(s)\n")
    (d / "labels.json").write_text(json.dumps({"source": "synthetic", "fully_labeled": True,
                                                "vulns": [{"path": "a.py", "line": 1, "kind": "eval"}]}))
    ev = cal.evaluate_detectors(tmp_path, CFG, POL)
    assert ev["byRule"]["PY-EVAL"]["fp"] == 1 and ev["recallByKind"]["eval"]["missed"] == 1


def test_status_mismatch_is_reported(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "a.py").write_text("x = 1\n")
    (d / "labels.json").write_text(json.dumps({"source": "synthetic", "vulns": [], "expected_status": "incomplete"}))
    assert cal.evaluate_detectors(tmp_path, CFG, POL)["statusMismatches"] == [
        {"case": "c", "expected": "incomplete", "got": "complete"}]


# ---------------------------------------------------------------- candidate generation
def test_candidate_is_marked_unapproved_capped_and_reproducible(tmp_path):
    rep = cal.run_calibration(CORPUS)
    base = ROOT / "config" / "score-v1.json"
    a = cal.build_candidate(rep, base, CORPUS)
    b = cal.build_candidate(cal.run_calibration(CORPUS), base, CORPUS)
    assert a == b                                          # deterministic
    assert a["status"] == "candidate-not-approved" and a["version"] == "score-v1-candidate"
    assert a["calibration"]["anchorIsAHumanDecision"] is True and a["calibration"]["adjudicatedCases"] == 0
    assert "Do NOT enable policy blocking" in a["calibration"]["notes"]
    assert set(a["rule_confidence"].values()) <= {"low", "medium", "high"}
    assert all(v == "low" for v in a["rule_confidence"].values())   # every rule has < MIN_N findings in this corpus
    cfg = ScoreConfig.load(_write(tmp_path, a))
    assert cfg.rule_confidence == a["rule_confidence"] and cfg.k == a["normalization_k"] > 0


def _write(tmp, d):
    p = tmp / "cand.json"
    p.write_text(json.dumps(d))
    return p


def test_candidate_k_makes_reference_case_read_the_anchor(tmp_path):
    rep = cal.run_calibration(CORPUS)
    cand = cal.build_candidate(rep, ROOT / "config" / "score-v1.json", CORPUS, anchor_index=80.0,
                               anchor_case="ind_python_app")
    cfg = ScoreConfig.load(_write(tmp_path, cand))
    res = assemble(cfg, POL, collect_findings(cfg.required_detectors, source_dir=CORPUS / "ind_python_app"))
    assert res["securityDebt"]["normalizedIndex"] == pytest.approx(80.0, abs=0.1)


def test_candidate_rejects_bad_anchor_cases():
    rep = cal.run_calibration(CORPUS)
    base = ROOT / "config" / "score-v1.json"
    with pytest.raises(ValueError):
        cal.build_candidate(rep, base, CORPUS, anchor_case="nope")
    with pytest.raises(ValueError):
        cal.build_candidate(rep, base, CORPUS, anchor_case="syn_clean_empty_ish")  # zero debt cannot anchor


def test_cli_fit_writes_candidate_and_never_touches_shipped_config(tmp_path):
    import subprocess, sys
    before = (ROOT / "config" / "score-v1.json").read_bytes()
    out = tmp_path / "c.json"
    p = subprocess.run([sys.executable, "-m", "avishkar", "calibrate", str(CORPUS), "--fit", str(out)],
                       cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 0 and json.loads(out.read_text())["status"] == "candidate-not-approved"
    assert "NOT CALIBRATED" in p.stdout and (ROOT / "config" / "score-v1.json").read_bytes() == before
