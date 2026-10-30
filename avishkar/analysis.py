"""Pure read-model functions over stored scan data: score explanation, run comparison, dashboard aggregates.

Nothing here invents a number. Every figure is read from the persisted run (score snapshot, components, completeness,
findings) or derived arithmetically from those values, and each derivation is returned alongside its result so a
reader can re-check it. The score is a prioritization index, never a probability of compromise.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict

from . import knowledge
from .domain.scoring import ScoreConfig

SEV = ["critical", "high", "medium", "low", "informational"]
SEV_RANK = {s: i for i, s in enumerate(SEV)}
DISCLAIMER = ("The index is a prioritization signal computed from provisional, uncalibrated weights. It is not a "
              "probability of compromise, a compliance grade, or proof that code is safe.")


def _meta(rows_by_fp: dict, fp: str) -> dict:
    r = rows_by_fp.get(fp) or {}
    return {"rule": r.get("rule_id"), "title": r.get("title"), "path": r.get("path"), "line": r.get("line_start"),
            "severity": r.get("severity"), "confidence": r.get("confidence"), "category": r.get("category"),
            "findingId": r.get("id")}


def _index(k: float, gross: float) -> float:
    return round(100 * (1 - math.exp(-gross / k)), 1)


def _term(c: dict) -> str:
    """'4 (impact) x 1.0 (exposure) x 0.75 (confidence) x 1.0 (age) = 3.0' with the real numbers of one finding."""
    return (f"{c['I']:g} (impact) × {c['E']:g} (exposure{' — unknown, neutral' if c.get('exposure_unknown') else ''}) × "
            f"{c['C']:g} (confidence) × {c['A']:g} (age) = {c['D']:g}")


# ------------------------------------------------------------------------------------------ score explanation
def explain_score(cfg: ScoreConfig, run: dict, rows: list[dict]) -> dict:
    sd = run["score"] or {}
    method = {
        "scoreVersion": sd.get("scoreVersion", cfg.version),
        "formula": "D_i = I × E × C × A      (per unique unresolved finding)",
        "aggregation": "Gross debt D = Σ D_i over non-excluded findings (open + accepted risk). "
                       "Raw debt counts only open findings.",
        "normalization": f"Index = round(100 × (1 − e^(−D / K)), 1) with K = {sd.get('k', cfg.k):g} fixed for this score version",
        "k": sd.get("k", cfg.k),
        "factors": {
            "impact (I)": dict(cfg.impact), "exposure (E)": dict(cfg.exposure), "confidence (C)": dict(cfg.confidence),
            "age (A)": {"enabled": cfg.aging_enabled,
                        "rule": f"1 + {cfg.aging_max_extra:g} × min(days_open / {cfg.aging_max_days}, 1)" if cfg.aging_enabled
                        else "disabled in this version: A = 1.0"}},
        "notes": [
            "Impact comes from the detector rule's severity, never from a model.",
            "Exposure (E) is the exploitability/reachability proxy. The scanner has no runtime or reachability data, so E is "
            "'unknown' (neutral 1.0) unless a rule supplies evidence; unknown is never treated as safe or as zero.",
            "Confidence (C) is the detector's confidence for the rule (a measured cap can only lower it).",
            "Fix effort is tracked separately and is deliberately NOT part of the score, so an easy-to-fix critical issue "
            "does not look less serious.",
            "Identical inputs and the same score version always give identical numbers.",
        ],
        "calibrated": False, "disclaimer": DISCLAIMER}
    if sd.get("status") != "calculated":
        return {"runId": run["id"], "status": sd.get("status", "pending"), "method": method, "contributions": [],
                "totals": None, "flags": {"uncalibrated": True},
                "reason": "Score not calculated: " + (", ".join(sd.get("missing") or []) or "analysis incomplete")
                          + ". An incomplete analysis is never reported as zero debt."}
    by_fp = {r["fingerprint"]: r for r in rows}
    comps = sd.get("components") or []
    gross = sd.get("grossUnits") or 0.0
    out: list[dict] = []
    excluded: Counter = Counter()
    for c in comps:
        if not c["counted"]:
            excluded[c["state"]] += 1
            continue
        out.append({**_meta(by_fp, c["fingerprint"]), "fingerprint": c["fingerprint"], "state": c["state"],
                    "I": c["I"], "E": c["E"], "C": c["C"], "A": c["A"], "D": c["D"],
                    "exposureUnknown": c.get("exposure_unknown", False),
                    "share": round(100 * c["D"] / gross, 1) if gross else 0.0, "calculation": _term(c)})
    out.sort(key=lambda x: (-x["D"], SEV_RANK.get(x["severity"] or "informational", 9), x["path"] or ""))
    recomputed = _index(sd.get("k", cfg.k), sum(x["D"] for x in out))
    return {"runId": run["id"], "status": "calculated", "method": method, "contributions": out,
            "totals": {"rawUnits": sd["rawUnits"], "grossUnits": gross, "normalizedIndex": sd["normalizedIndex"],
                       "recomputedIndex": recomputed, "reproducible": recomputed == sd["normalizedIndex"],
                       "findingsCounted": len(out), "findingsExcluded": dict(excluded)},
            "flags": {"uncalibrated": True, "exposureUnknown": sum(1 for x in out if x["exposureUnknown"]),
                      "agingEnabled": cfg.aging_enabled,
                      "heuristicShare": round(100 * sum(x["D"] for x in out if _is_heuristic(x["rule"])) / gross, 1) if gross else 0.0}}


def _is_heuristic(rule: str | None) -> bool:
    k = knowledge.RULES.get(rule or "")
    return not k or k["detection"]["assurance"] == "heuristic"


# ------------------------------------------------------------------------------------------ run comparison
def compare_runs(base: dict, head: dict, base_rows: list[dict], head_rows: list[dict]) -> dict:
    bs, hs = base["score"] or {}, head["score"] or {}
    info = lambda r: {"runId": r["id"], "commitSha": r["commit_sha"], "startedAt": r["started_at"], "status": r["status"],
                      "normalizedIndex": (r["score"] or {}).get("normalizedIndex"),
                      "grossUnits": (r["score"] or {}).get("grossUnits"), "rawUnits": (r["score"] or {}).get("rawUnits"),
                      "scoreVersion": (r["score"] or {}).get("scoreVersion")}
    res = {"base": info(base), "head": info(head)}
    if bs.get("status") != "calculated" or hs.get("status") != "calculated":
        return {**res, "comparable": False, "reason": "A run without a calculated score cannot be compared "
                "(incomplete analyses are never treated as zero debt).", "fixed": [], "introduced": [], "changed": [],
                "explanation": []}
    if bs.get("scoreVersion") != hs.get("scoreVersion") or bs.get("k") != hs.get("k"):
        return {**res, "comparable": False, "reason": f"Different score versions ({bs.get('scoreVersion')} K={bs.get('k')} vs "
                f"{hs.get('scoreVersion')} K={hs.get('k')}): the indexes are not equivalent.", "fixed": [], "introduced": [],
                "changed": [], "explanation": []}
    bm = {c["fingerprint"]: c for c in bs["components"] if c["counted"]}
    hm = {c["fingerprint"]: c for c in hs["components"] if c["counted"]}
    brow, hrow = {r["fingerprint"]: r for r in base_rows}, {r["fingerprint"]: r for r in head_rows}
    rows = {**brow, **hrow}

    def item(fp, c, extra=None):
        return {**_meta(rows, fp), "fingerprint": fp, "D": c["D"], **(extra or {})}

    fixed = sorted((item(fp, c) for fp, c in bm.items() if fp not in hm), key=lambda x: -x["D"])
    introduced = sorted((item(fp, c) for fp, c in hm.items() if fp not in bm), key=lambda x: -x["D"])
    changed = sorted((item(fp, hm[fp], {"before": bm[fp]["D"], "after": hm[fp]["D"], "delta": round(hm[fp]["D"] - bm[fp]["D"], 6)})
                      for fp in bm if fp in hm and bm[fp]["D"] != hm[fp]["D"]), key=lambda x: x["delta"])
    unchanged = sum(1 for fp in bm if fp in hm and bm[fp]["D"] == hm[fp]["D"])
    gb, gh = bs["grossUnits"], hs["grossUnits"]
    delta_units = round(gh - gb, 6)
    parts = round(sum(x["D"] for x in introduced) - sum(x["D"] for x in fixed) + sum(x["delta"] for x in changed), 6)
    ib, ih = bs["normalizedIndex"], hs["normalizedIndex"]
    expl = []
    if fixed:
        expl.append(f"{len(fixed)} finding(s) no longer present removed {sum(x['D'] for x in fixed):g} debt units "
                    f"(largest: {fixed[0]['title']} at {fixed[0]['path']}:{fixed[0]['line']}, {fixed[0]['D']:g}).")
    if introduced:
        expl.append(f"{len(introduced)} new finding(s) added {sum(x['D'] for x in introduced):g} units "
                    f"(largest: {introduced[0]['title']} at {introduced[0]['path']}:{introduced[0]['line']}).")
    if changed:
        expl.append(f"{len(changed)} existing finding(s) changed weight by {sum(x['delta'] for x in changed):+g} units "
                    "(confidence, age or state changed).")
    if not (fixed or introduced or changed):
        expl.append("The set of findings and their weights is identical; the score did not change.")
    expl.append(f"Gross debt {gb:g} → {gh:g} ({delta_units:+g}); the index moves {ib} → {ih} "
                f"({round(ih - ib, 1):+g}) through the saturating curve with K = {hs['k']:g}, so equal debt changes move the "
                "index less at higher debt.")
    detection_note = None
    if base["completeness"] and head["completeness"] and base["policy_version"] != head["policy_version"]:
        detection_note = "Policy versions differ; decisions may not be comparable."
    return {**res, "comparable": True, "reason": None, "delta": {"grossUnits": delta_units, "index": round(ih - ib, 1),
            "rawUnits": round((hs["rawUnits"] or 0) - (bs["rawUnits"] or 0), 6)},
            "fixed": fixed, "introduced": introduced, "changed": changed, "unchanged": unchanged,
            "reconciles": abs(delta_units - parts) < 1e-6, "explanation": expl, "note": detection_note,
            "disclaimer": DISCLAIMER}


# ------------------------------------------------------------------------------------------ dashboard
def _health(latest: dict | None, open_by_sev: Counter) -> dict:
    if not latest:
        return {"status": "no_data", "label": "No analysis yet", "reason": "Run a scan to see repository health."}
    if latest["status"] != "complete":
        return {"status": "incomplete", "label": "Analysis incomplete",
                "reason": "The latest analysis did not complete; this is not a pass."}
    if open_by_sev["critical"]:
        return {"status": "critical", "label": "Critical findings open", "reason": f"{open_by_sev['critical']} critical finding(s) open."}
    if open_by_sev["high"]:
        return {"status": "attention", "label": "High-severity findings open", "reason": f"{open_by_sev['high']} high finding(s) open."}
    if sum(open_by_sev.values()):
        return {"status": "watch", "label": "Lower-severity findings open", "reason": f"{sum(open_by_sev.values())} finding(s) open."}
    return {"status": "none_detected", "label": "No findings detected",
            "reason": "No open findings from the supported detectors. This does not prove the code is secure."}


def repo_dashboard(repo: dict, runs: list[dict], findings: list[dict], latest_rows: list[dict], activity: list[dict]) -> dict:
    """runs: newest first (decoded). findings: ledger rows for the repo. latest_rows: run_findings of the latest complete run."""
    complete = [r for r in runs if r["status"] == "complete" and (r["score"] or {}).get("status") == "calculated"]
    latest = runs[0] if runs else None
    latest_c = complete[0] if complete else None
    open_f = [f for f in findings if f["state"] == "open"]
    open_by_sev = Counter(f["severity"] for f in open_f)
    sd = (latest_c or {}).get("score") or {}
    comps = {c["fingerprint"]: c for c in (sd.get("components") or []) if c["counted"]}
    by_file: dict[str, dict] = defaultdict(lambda: {"findings": 0, "debt": 0.0, "worst": "informational"})
    for r in latest_rows:
        c = comps.get(r["fingerprint"])
        if not c:
            continue
        e = by_file[r["path"]]
        e["findings"] += 1
        e["debt"] = round(e["debt"] + c["D"], 6)
        if SEV_RANK[r["severity"]] < SEV_RANK[e["worst"]]:
            e["worst"] = r["severity"]
    top_files = sorted(({"path": p, **v} for p, v in by_file.items()), key=lambda x: (-x["debt"], x["path"]))[:10]
    trend = [{"runId": r["id"], "startedAt": r["started_at"], "commitSha": r["commit_sha"], "status": r["status"],
              "normalizedIndex": (r["score"] or {}).get("normalizedIndex"), "grossUnits": (r["score"] or {}).get("grossUnits"),
              "findings": sum(1 for c in ((r["score"] or {}).get("components") or []) if c["counted"])}
             for r in reversed(runs[:30])]
    prev = complete[1] if len(complete) > 1 else None
    cov = sd.get("coverage") or {}
    return {
        "repository": {"id": repo["id"], "name": repo["name"]},
        "latest": None if not latest else {"runId": latest["id"], "status": latest["status"], "startedAt": latest["started_at"],
                                           "commitSha": latest["commit_sha"], "decision": (latest["decision"] or {}).get("outcome")},
        "score": None if not latest_c else {"normalizedIndex": sd["normalizedIndex"], "rawUnits": sd["rawUnits"],
                                            "grossUnits": sd["grossUnits"], "scoreVersion": sd["scoreVersion"], "k": sd["k"],
                                            "calibrated": False,
                                            "previousIndex": None if not prev else prev["score"]["normalizedIndex"],
                                            "delta": None if not prev else round(sd["normalizedIndex"] - prev["score"]["normalizedIndex"], 1)},
        "health": _health(latest, open_by_sev),
        "severity": {s: open_by_sev.get(s, 0) for s in SEV},
        "states": dict(Counter(f["state"] for f in findings)),
        "categories": dict(Counter(f["category"] for f in open_f).most_common()),
        "totalFindings": len(open_f),
        "filesScanned": ((latest_c or {}).get("completeness") or {}).get("filesScanned"),
        "coverage": {"analyzedSourceFiles": cov.get("analyzedSourceFiles"), "notEvaluated": cov.get("notEvaluated") or {}},
        "topFiles": top_files, "trend": trend, "activity": activity[:15], "runs": len(runs),
        "disclaimer": DISCLAIMER,
    }


def org_overview(repos: list[dict]) -> dict:
    """repos: [{id,name,runs,latest_run (decoded)|None, open_by_sev:Counter}]"""
    rows: list[dict] = []
    totals: Counter = Counter()
    for r in repos:
        run = r["latest_run"]
        sd = (run or {}).get("score") or {}
        sev = r["open_by_sev"]
        totals.update(sev)
        rows.append({"id": r["id"], "name": r["name"], "runs": r["runs"], "status": (run or {}).get("status", "no_data"),
                     "normalizedIndex": sd.get("normalizedIndex"), "grossUnits": sd.get("grossUnits"),
                     "severity": {s: sev.get(s, 0) for s in SEV}, "health": _health(run, sev)["status"],
                     "lastScan": (run or {}).get("started_at")})
    scored = [x["normalizedIndex"] for x in rows if x["normalizedIndex"] is not None]
    return {"repositories": sorted(rows, key=lambda x: (-(x["normalizedIndex"] if x["normalizedIndex"] is not None else -1), x["name"])),
            "severity": {s: totals.get(s, 0) for s in SEV}, "repositoryCount": len(rows),
            "scoredRepositories": len(scored), "highestIndex": max(scored) if scored else None, "disclaimer": DISCLAIMER}
