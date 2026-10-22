"""Scoring calibration harness (spec Appendix P). Produces *evidence* and *candidate* configs; it never marks a
score version calibrated or approved - that is the scoring owner's decision (P.7).

Corpus layout: <corpus>/<case>/<source files...> + <case>/labels.json
  {
    "source": "independent" | "synthetic",     # who wrote the code relative to the detectors
    "fully_labeled": true,                      # every real vulnerability in the case is listed
    "vulns": [{"path": "app.py", "line": 35, "kind": "sqli"}],      # line may be omitted = any line
    "expected_status": "complete",              # optional; "incomplete" for unsupported-language cases
    "adjudicated": false, "reviewers": 0        # >=2 human reviewers needed before approval (P.2)
  }
Legacy labels ({"expected": [{"rule","path"}]}) are still read.
A finding is a true positive if a labeled vulnerability of the same kind sits on the same path and line.
Findings without a match are false positives only in fully_labeled cases (else "unlabeled", not scored).
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

# Which vulnerability kind a rule is evidence for. Rules not listed here are scored as kind "other".
RULE_KIND = {
    "PY-EVAL": "eval", "JS-EVAL": "eval", "PY-SHELL": "cmdi", "JS-CMDI": "cmdi", "PY-SQLI": "sqli",
    "PY-PICKLE": "pickle", "PY-YAML": "deserialization", "PY-WEAKHASH": "weakhash", "PY-NOVERIFY": "noverify",
    "JS-TLS": "noverify", "PY-DEBUG": "debug", "JS-INNERHTML": "xss", "ANY-CORS": "cors",
    "SEC-AWS-KEY": "secret", "SEC-GH-TOKEN": "secret", "SEC-SLACK": "secret", "SEC-PRIVKEY": "secret",
    "SEC-GENERIC": "secret", "DEP-UNPINNED": "dependency", "DEP-NOLOCK": "dependency",
}
# Confidence tiers proposed from measured precision (Wilson 95% lower bound, minimum sample).
MIN_N = 8
HIGH_LB, MEDIUM_LB = 0.80, 0.50


def kind_of(rule_id: str) -> str:
    if rule_id in RULE_KIND:
        return RULE_KIND[rule_id]
    if rule_id.startswith(("DEP-",)):
        return "dependency"
    if rule_id.startswith(("GL:",)):
        return "secret"
    return "other"


def wilson_lower(tp: int, n: int, z: float = 1.96) -> float | None:
    """95% lower confidence bound on precision. Small samples get wide intervals, as they should."""
    if n == 0:
        return None
    p = tp / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return round((centre - margin) / d, 3)


def _case_dirs(corpus: Path):
    return sorted(d for d in corpus.iterdir() if d.is_dir() and (d / "labels.json").exists())


def _vulns(labels: dict) -> list[dict]:
    if "vulns" in labels:
        return list(labels["vulns"])
    return [{"path": e["path"], "line": None, "kind": kind_of(e["rule"])} for e in labels.get("expected", [])]


def evaluate_detectors(corpus: Path, cfg: ScoreConfig, pol: Policy) -> dict:
    rules: dict[str, dict] = {}
    rule_conf: dict[str, dict] = {}
    kinds: dict[str, dict] = {}
    sev: dict[str, dict] = {}
    cases, adjudicated, status_mismatch = [], 0, []

    def b(d, k, fields):
        return d.setdefault(k, {f: 0 for f in fields})

    for d in _case_dirs(corpus):
        labels = json.loads((d / "labels.json").read_text())
        adjudicated += 1 if labels.get("adjudicated") and labels.get("reviewers", 0) >= 2 else 0
        res = assemble(cfg, pol, collect_findings(cfg.required_detectors, source_dir=d))
        want = labels.get("expected_status", "complete")
        if res["status"] != want:
            status_mismatch.append({"case": d.name, "expected": want, "got": res["status"]})
        if res["status"] != "complete":
            cases.append({"case": d.name, "status": res["status"], "source": labels.get("source", "unknown")})
            continue
        vulns = _vulns(labels)
        fully = bool(labels.get("fully_labeled", "vulns" not in labels))
        used = set()
        seen = set()
        for f in res["findings"]:
            key = (f.raw.rule_id, f.raw.path, f.raw.line)
            if key in seen:
                continue
            seen.add(key)
            k = kind_of(f.raw.rule_id)
            hit = next((i for i, v in enumerate(vulns) if v["path"] == f.raw.path and v["kind"] == k
                        and (v.get("line") is None or v["line"] == f.raw.line)), None)
            r = b(rules, f.raw.rule_id, ("tp", "fp", "unlabeled"))
            rc = b(rule_conf, f"{f.raw.rule_id}@{f.raw.confidence.value}", ("tp", "fp", "unlabeled"))
            s_ = b(sev, f.raw.severity.value, ("tp", "fp", "unlabeled"))
            if hit is not None:
                used.add(hit)
                r["tp"] += 1
                rc["tp"] += 1
                s_["tp"] += 1
            elif fully:
                r["fp"] += 1
                rc["fp"] += 1
                s_["fp"] += 1
            else:
                r["unlabeled"] += 1
                rc["unlabeled"] += 1
                s_["unlabeled"] += 1
        for i, v in enumerate(vulns):
            kk = b(kinds, v["kind"], ("found", "missed"))
            kk["found" if i in used else "missed"] += 1
        cases.append({"case": d.name, "status": "complete", "source": labels.get("source", "unknown"),
                      "rawUnits": res["securityDebt"]["rawUnits"], "findings": len(res["findings"]),
                      "labeledVulns": len(vulns), "fullyLabeled": fully})

    def prec(v):
        n = v["tp"] + v["fp"]
        return {**v, "n": n, "precision": round(v["tp"] / n, 3) if n else None, "wilsonLower95": wilson_lower(v["tp"], n)}

    def rec(v):
        n = v["found"] + v["missed"]
        return {**v, "recall": round(v["found"] / n, 3) if n else None}

    return {"cases": cases, "byRule": {k: prec(v) for k, v in sorted(rules.items())},
            "byRuleConfidence": {k: prec(v) for k, v in sorted(rule_conf.items())},
            "bySeverity": {k: prec(v) for k, v in sorted(sev.items())},
            "recallByKind": {k: rec(v) for k, v in sorted(kinds.items())},
            "statusMismatches": status_mismatch, "adjudicatedCases": adjudicated, "totalCases": len(cases),
            "independentCases": sum(1 for c in cases if c.get("source") == "independent")}


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
    cases = [c for c in _case_dirs(corpus)]
    if cases:
        a = assemble(cfg, pol, collect_findings(cfg.required_detectors, source_dir=cases[0]))["securityDebt"]
        b = assemble(cfg, pol, collect_findings(cfg.required_detectors, source_dir=cases[0]))["securityDebt"]
        replay = a == b
    return {"identicalInputsIdenticalScore": base == again, "corpusReplayIdentical": replay,
            "acceptingRiskDoesNotLowerIndex": accepted["normalizedIndex"] == base["normalizedIndex"],
            "fixingLowersIndex": fixed["normalizedIndex"] < base["normalizedIndex"]}


def k_analysis(case_units: list[float], current_k: float) -> dict:
    """Distribution of raw debt and the index each candidate K gives at the distribution's landmarks (P.5).
    Does not choose K."""
    if not case_units:
        return {"note": "no complete cases", "currentK": current_k}
    qs = statistics.quantiles(case_units, n=4) if len(case_units) >= 2 else [case_units[0]] * 3
    marks = {"p25": qs[0], "median": qs[1], "p75": qs[2], "max": max(case_units)}
    return {"currentK": current_k, "cases": len(case_units),
            "rawUnits": {"min": min(case_units), **marks},
            "indexAtLandmarks": {str(k): {m: round(100 * (1 - math.exp(-u / k)), 1) for m, u in marks.items()}
                                 for k in sorted({*CANDIDATE_K, current_k})}}


# --------------------------------------------------------------------------- fitting (candidate, never approved)
def propose_rule_confidence(by_rule: dict) -> dict:
    """Map measured precision to a confidence tier. Too little evidence => 'low' (report-only, cannot block)."""
    out = {}
    for rule, v in by_rule.items():
        lb, n = v["wilsonLower95"], v["n"]
        if n < MIN_N or lb is None:
            tier, why = "low", f"insufficient evidence (n={n} < {MIN_N})"
        elif lb >= HIGH_LB:
            tier, why = "high", f"Wilson lower bound {lb} >= {HIGH_LB} at n={n}"
        elif lb >= MEDIUM_LB:
            tier, why = "medium", f"Wilson lower bound {lb} >= {MEDIUM_LB} at n={n}"
        else:
            tier, why = "low", f"Wilson lower bound {lb} < {MEDIUM_LB} at n={n}"
        out[rule] = {"tier": tier, "evidence": why, "precision": v["precision"], "n": n}
    return out


def fit_k(anchor_units: float, anchor_index: float) -> float:
    """Solve 100*(1-exp(-U/K)) = I for K. The anchor (what U should read as I) is a human decision."""
    if not (0 < anchor_index < 100) or anchor_units <= 0:
        raise ValueError("anchor_index must be in (0,100) and anchor_units > 0")
    return round(-anchor_units / math.log(1 - anchor_index / 100), 3)


def build_candidate(report: dict, base_cfg_path: Path, corpus: Path, anchor_index: float = 80.0,
                    anchor_case: str | None = None) -> dict:
    """A *candidate* score version (status 'candidate-not-approved'). Two passes: (1) cap per-rule confidence from
    measured precision, (2) fit K so a REFERENCE case reads as `anchor_index`, using raw debt computed UNDER the caps.
    Why a reference case and not the corpus median: most corpus cases are one-line snippets, so their median says
    nothing about how a real repository should read (App. P.5: representative size). Choosing the reference case and
    its index is the scoring owner's decision; the default is the heaviest independent case reading 80."""
    base = json.loads(base_cfg_path.read_text())
    prc = propose_rule_confidence(report["detectors"]["byRuleConfidence"])
    caps = {r: v["tier"] for r, v in prc.items()}
    cand = dict(base)
    cand["version"] = base["version"] + "-candidate"
    cand["status"] = "candidate-not-approved"
    cand["rule_confidence"] = caps
    cfg2 = replace(ScoreConfig.load(base_cfg_path), rule_confidence=caps)
    det2 = evaluate_detectors(corpus, cfg2, Policy.load())
    complete = {c["case"]: c for c in det2["cases"] if c["status"] == "complete"}
    if anchor_case is None:
        indep = [c for c in complete.values() if c.get("source") == "independent" and c.get("rawUnits")]
        if not indep:
            raise ValueError("no independent complete case to anchor K on; pass anchor_case explicitly")
        anchor_case = max(indep, key=lambda c: c["rawUnits"])["case"]
    if anchor_case not in complete or not complete[anchor_case].get("rawUnits"):
        raise ValueError(f"anchor case {anchor_case!r} is missing, incomplete or has zero debt")
    anchor_units = complete[anchor_case]["rawUnits"]
    cand["normalization_k"] = fit_k(anchor_units, anchor_index)
    under_base = {c["case"]: c["rawUnits"] for c in report["detectors"]["cases"] if c["status"] == "complete"}
    cand["calibration"] = {
        "anchor": f"reference case '{anchor_case}' ({anchor_units} raw units under the capped confidences; "
                  f"{under_base.get(anchor_case)} under the current version) reads as index {anchor_index}",
        "anchorIsAHumanDecision": True, "corpusCases": report["detectors"]["totalCases"],
        "independentCases": report["detectors"]["independentCases"],
        "adjudicatedCases": report["detectors"]["adjudicatedCases"],
        "capSemantics": "tier can only LOWER a finding's confidence, never raise it above the detector's own; "
                        "rules with < %d labeled findings are capped at 'low' (spec P.3)" % MIN_N,
        "ruleEvidence": prc, "approvalBlockers": report["approvalBlockers"],
        "notes": "Generated by `avishkar calibrate --fit`. Do NOT enable policy blocking on this version."}
    return cand


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
    if det["independentCases"] < 10:
        blockers.append(f"only {det['independentCases']} independent (not written by the detector author) cases; "
                        "synthetic cases measure self-consistency, not real-world precision")
    if det["statusMismatches"]:
        blockers.append("some cases did not finish with their expected status")
    weak = [r for r, v in det["byRule"].items() if v["n"] < MIN_N]
    if weak:
        blockers.append(f"{len(weak)} rule(s) have fewer than {MIN_N} labeled findings: confidence stays low")
    report["approvalBlockers"] = blockers
    report["verdict"] = "NOT CALIBRATED - evidence only; the scoring owner must approve (App. P.7)"
    return report


def render_markdown(r: dict) -> str:
    d = r["detectors"]
    L = [f"# Calibration report - {r['scoreVersion']}", f"**{r['verdict']}**", "",
         f"Corpus: {d['totalCases']} cases ({d['independentCases']} independent), "
         f"{d['adjudicatedCases']} adjudicated by >=2 reviewers.", "", "## Precision by rule",
         "| Rule | TP | FP | Unlabeled | n | Precision | Wilson 95% lower |", "|---|---|---|---|---|---|---|"]
    for k, v in d["byRule"].items():
        L.append(f"| {k} | {v['tp']} | {v['fp']} | {v['unlabeled']} | {v['n']} | {v['precision']} | {v['wilsonLower95']} |")
    L += ["", "## Precision by rule @ detector-reported confidence (drives the confidence caps)",
          "| Rule@confidence | TP | FP | n | Wilson 95% lower |", "|---|---|---|---|---|"]
    for k, v in d["byRuleConfidence"].items():
        L.append(f"| {k} | {v['tp']} | {v['fp']} | {v['n']} | {v['wilsonLower95']} |")
    L += ["", "## Recall by vulnerability kind", "| Kind | Found | Missed | Recall |", "|---|---|---|---|"]
    for k, v in d["recallByKind"].items():
        L.append(f"| {k} | {v['found']} | {v['missed']} | {v['recall']} |")
    L += ["", "## Factor sensitivity (one factor at a time)"]
    for k, v in r["factorSensitivity"].items():
        L.append(f"- {k}: monotonic={v['monotonic']} debt={v['debt']}")
    L += ["", "## Stability / gaming"] + [f"- {k}: {v}" for k, v in r["stabilityAndGaming"].items()]
    L += ["", "## Normalization constant", "```json", json.dumps(r["normalization"], indent=1), "```", "",
          "## Approval blockers"] + [f"- {b}" for b in r["approvalBlockers"]]
    return "\n".join(L)
