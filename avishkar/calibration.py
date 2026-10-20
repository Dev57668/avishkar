"""Scoring calibration harness (spec Appendix P). Produces *evidence*; it never flips `calibrated` to true.

Corpus layout: <corpus>/<case>/<source files...> and <case>/labels.json:
  {"expected": [{"rule": "PY-EVAL", "path": "app.py"}], "adjudicated": false, "reviewers": 0}
Every finding not matched by an expected label counts as a false positive for its rule.
"""
from __future__ import annotations

import json
import math
import statistics
from dataclasses import replace
from pathlib import Path

from .domain.models import Completeness, Confidence, Exposure, FindingRecord, RawFinding, Severity, State
from .domain.policy import Policy
from .domain.scoring import ScoreConfig, compute_score, debt_units
from .workers.pipeline import assemble, collect_findings

CANDIDATE_K = (10, 20, 40, 80)


def _case_dirs(corpus: Path):
    return sorted(d for d in corpus.iterdir() if d.is_dir() and (d / "labels.json").exists())


def evaluate_detectors(corpus: Path, cfg: ScoreConfig, pol: Policy) -> dict:
    per_rule: dict[str, dict] = {}
    per_sev: dict[str, dict] = {}
    cases, adjudicated = [], 0

    def bucket(d, k):
        return d.setdefault(k, {"tp": 0, "fp": 0, "fn": 0})

    for d in _case_dirs(corpus):
        labels = json.loads((d / "labels.json").read_text())
        adjudicated += 1 if labels.get("adjudicated") and labels.get("reviewers", 0) >= 2 else 0
        res = assemble(cfg, pol, collect_findings(cfg.required_detectors, source_dir=d))
        if res["status"] != "complete":
            cases.append({"case": d.name, "status": "incomplete", "failures": res["completeness"]["failures"]})
            continue
        expected = {(e["rule"], e["path"]) for e in labels.get("expected", [])}
        got = {}
        for f in res["findings"]:
            got.setdefault((f.raw.rule_id, f.raw.path), f.raw.severity.value)
        for key, sev in got.items():
            kind = "tp" if key in expected else "fp"
            bucket(per_rule, key[0])[kind] += 1
            bucket(per_sev, sev)[kind] += 1
        for key in expected - set(got):
            bucket(per_rule, key[0])["fn"] += 1
        cases.append({"case": d.name, "status": "complete", "rawUnits": res["securityDebt"]["rawUnits"],
                      "findings": len(res["findings"])})

    def prf(b):
        p = b["tp"] / (b["tp"] + b["fp"]) if b["tp"] + b["fp"] else None
        r = b["tp"] / (b["tp"] + b["fn"]) if b["tp"] + b["fn"] else None
        return {**b, "precision": p and round(p, 3), "recall": r and round(r, 3)}

    return {"cases": cases, "byRule": {k: prf(v) for k, v in sorted(per_rule.items())},
            "bySeverity": {k: prf(v) for k, v in sorted(per_sev.items())},
            "adjudicatedCases": adjudicated, "totalCases": len(cases)}


def _rec(sev, conf, exp, days=0, state=State.OPEN, n="a"):
    r = RawFinding("d", "R-" + n, "x", sev, conf, "t", "f", 1, "e" + n, exp)
    return FindingRecord(r.fp, r, state, True, days)


def factor_sensitivity(cfg: ScoreConfig) -> dict:
    """One-factor-at-a-time monotonicity checks (P.4). Aging is evaluated as if enabled."""
    on = replace(cfg, aging_enabled=True)
    order = {"impact": [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
             "confidence": [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH],
             "exposure": [Exposure.UNREACHABLE, Exposure.INTERNAL, Exposure.PREREQUISITES, Exposure.CONFIRMED_EXTERNAL],
             "age_days": [0, 30, 60, 90, 365]}
    out = {}
    for name, values in order.items():
        series = []
        for v in values:
            sev, conf, exp, days = Severity.MEDIUM, Confidence.MEDIUM, Exposure.INTERNAL, 0
            if name == "impact":
                sev = v
            elif name == "confidence":
                conf = v
            elif name == "exposure":
                exp = v
            else:
                days = v
            series.append(debt_units(on, _rec(sev, conf, exp, days))["D"])
        out[name] = {"values": [getattr(v, "value", v) for v in values], "debt": series,
                     "monotonic": all(a <= b for a, b in zip(series, series[1:]))}
    return out


def stability_and_gaming(cfg: ScoreConfig, pol: Policy, corpus: Path) -> dict:
    complete = Completeness("complete", cfg.required_detectors, cfg.required_detectors)
    recs = [_rec(Severity.HIGH, Confidence.HIGH, Exposure.UNKNOWN, n=str(i)) for i in range(3)]
    base = compute_score(cfg, recs, complete)
    again = compute_score(cfg, recs, complete)
    accepted = compute_score(cfg, [replace(r, state=State.ACCEPTED_RISK) for r in recs], complete)
    fixed = compute_score(cfg, [replace(r, state=State.FIXED) for r in recs], complete)
    replay = None
    cases = _case_dirs(corpus)
    if cases:
        a = assemble(cfg, pol, collect_findings(cfg.required_detectors, source_dir=cases[0]))["securityDebt"]
        b = assemble(cfg, pol, collect_findings(cfg.required_detectors, source_dir=cases[0]))["securityDebt"]
        replay = a == b
    return {"identicalInputsIdenticalScore": base == again, "corpusReplayIdentical": replay,
            "acceptingRiskDoesNotLowerIndex": accepted["normalizedIndex"] == base["normalizedIndex"],
            "fixingLowersIndex": fixed["normalizedIndex"] < base["normalizedIndex"]}


def k_analysis(case_units: list[float], current_k: float) -> dict:
    """Distribution of raw debt and the index each candidate K would produce (P.5). Does not choose K."""
    if not case_units:
        return {"note": "no complete cases", "currentK": current_k}
    qs = statistics.quantiles(case_units, n=4) if len(case_units) >= 2 else [case_units[0]] * 3
    return {"currentK": current_k,
            "rawUnits": {"min": min(case_units), "p25": qs[0], "median": qs[1], "p75": qs[2], "max": max(case_units)},
            "indexByCandidateK": {str(k): [round(100 * (1 - math.exp(-u / k)), 1) for u in sorted(case_units)]
                                  for k in CANDIDATE_K}}


def run_calibration(corpus: Path, cfg: ScoreConfig | None = None, pol: Policy | None = None) -> dict:
    cfg, pol = cfg or ScoreConfig.load(), pol or Policy.load()
    det = evaluate_detectors(corpus, cfg, pol)
    units = [c["rawUnits"] for c in det["cases"] if c["status"] == "complete"]
    report = {"scoreVersion": cfg.version, "calibrated": False, "detectors": det,
              "factorSensitivity": factor_sensitivity(cfg),
              "stabilityAndGaming": stability_and_gaming(cfg, pol, corpus),
              "normalization": k_analysis(units, cfg.k)}
    blockers = []
    if det["adjudicatedCases"] < det["totalCases"] or det["totalCases"] == 0:
        blockers.append("labels are not adjudicated by >=2 reviewers (App. P.2)")
    if any(not v["monotonic"] for v in report["factorSensitivity"].values()):
        blockers.append("a factor is not monotonic")
    if det["totalCases"] < 30:
        blockers.append(f"corpus too small ({det['totalCases']} cases) for a defensible K")
    if any(c["status"] != "complete" for c in det["cases"]):
        blockers.append("some corpus cases could not be analyzed completely")
    report["approvalBlockers"] = blockers
    report["verdict"] = "NOT CALIBRATED - evidence only; the scoring owner must approve (App. P.7)"
    return report


def render_markdown(r: dict) -> str:
    L = [f"# Calibration report - {r['scoreVersion']}", f"**{r['verdict']}**", "", "## Detector quality by rule",
         "| Rule | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|"]
    for k, v in r["detectors"]["byRule"].items():
        L.append(f"| {k} | {v['tp']} | {v['fp']} | {v['fn']} | {v['precision']} | {v['recall']} |")
    L += ["", "## Factor sensitivity (one factor at a time)"]
    for k, v in r["factorSensitivity"].items():
        L.append(f"- {k}: monotonic={v['monotonic']} debt={v['debt']}")
    L += ["", "## Stability / gaming"] + [f"- {k}: {v}" for k, v in r["stabilityAndGaming"].items()]
    L += ["", "## Normalization constant", "```json", json.dumps(r["normalization"], indent=1), "```", "",
          "## Approval blockers"] + [f"- {b}" for b in r["approvalBlockers"]]
    return "\n".join(L)
