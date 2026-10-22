"""Report renderers: SARIF 2.1.0 (code-scanning interop) and a Markdown PR summary. Pure functions."""
from __future__ import annotations

from .redaction import redact_text

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "informational": "1.0"}
MARKER = "<!-- avishkar-summary -->"


def to_sarif(run: dict, findings: list[dict], tool_version: str = "2.0.0") -> dict:
    """`findings` rows: rule_id,title,severity,confidence,category,remediation,path,line_start,evidence,fingerprint,state.
    Avishkar-specific debt fields live under run.properties, not in standard SARIF fields."""
    rules, seen, results = [], {}, []
    for f in findings:
        rid = f["rule_id"]
        if rid not in seen:
            seen[rid] = len(rules)
            rules.append({"id": rid, "name": rid, "shortDescription": {"text": f["title"]},
                          "help": {"text": f.get("remediation") or f["title"]},
                          "properties": {"category": f["category"], "security-severity": SECURITY_SEVERITY[f["severity"]]}})
        results.append({
            "ruleId": rid, "ruleIndex": seen[rid], "level": LEVEL[f["severity"]],
            "message": {"text": redact_text(f["title"])},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]},
                                                "region": {"startLine": max(1, int(f["line_start"] or 1))}}}],
            "partialFingerprints": {"avishkarFingerprint/v1": f["fingerprint"]},
            "properties": {"confidence": f["confidence"], "state": f["state"]},
            **({"suppressions": [{"kind": "external", "status": "accepted", "justification": f["state"]}]}
               if f["state"] in ("false_positive", "not_applicable", "accepted_risk") else {}),
        })
    complete = run["status"] == "complete"
    sd = run.get("score") or {}
    invocation = {"executionSuccessful": complete}
    if not complete:
        miss = (run.get("completeness") or {}).get("missing") or []
        invocation["toolExecutionNotifications"] = [{
            "level": "error", "message": {"text": "Analysis incomplete (NOT a pass). Missing: " + ", ".join(miss or ["unknown"])}}]
    cov = sd.get("coverage") or {}
    if cov.get("notEvaluated"):
        invocation.setdefault("toolExecutionNotifications", []).append({
            "level": "warning", "message": {"text": "Not evaluated (unsupported language): " +
                                            ", ".join(f"{n} {e}" for e, n in cov["notEvaluated"].items())}})
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Avishkar", "version": tool_version, "rules": rules}},
        "results": results, "invocations": [invocation],
        "properties": {"avishkar": {"runId": run["id"], "commitSha": run.get("commit_sha"),
                                    "scoreVersion": sd.get("scoreVersion"), "scoreStatus": sd.get("status"),
                                    "rawUnits": sd.get("rawUnits"), "normalizedIndex": sd.get("normalizedIndex"),
                                    "calibrated": False, "completeness": run.get("completeness"),
                                    "decision": (run.get("decision") or {}).get("outcome")}}}]}


def render_summary(run_status: str, score: dict, decision: dict, completeness: dict, findings: list[dict],
                   limit: int = 15) -> str:
    """Markdown for the PR comment. No source, no secrets, explicit about incomplete analysis."""
    lines = [MARKER, "### Avishkar security debt"]
    if run_status != "complete":
        miss = ", ".join(completeness.get("missing") or ["unknown"])
        lines += [f"**Analysis incomplete — this is not a pass.** Missing coverage: {miss}.", ""]
    else:
        lines += [f"- Decision: **{decision['outcome'].replace('_', ' ')}** "
                  f"(policy `{decision['policyVersion']}`, {decision['mode'].replace('_', '-')} mode)",
                  f"- Raw debt units: **{score['rawUnits']}** · index {score['normalizedIndex']} "
                  f"(`{score['scoreVersion']}`, uncalibrated)", ""]
        ne = (score.get("coverage") or {}).get("notEvaluated")
        if ne:
            lines += ["> **Not evaluated** (no detector for this language): " +
                      ", ".join(f"{n} `{e}` file(s)" for e, n in ne.items()) + ". Results cover supported languages only.", ""]
        if findings:
            lines += ["| Severity | Finding | Location |", "|---|---|---|"]
            for f in findings[:limit]:
                lines.append(f"| {f['severity']} | {redact_text(f['title'])} (`{f['rule_id']}`) | "
                             f"`{f['path']}:{f['line_start']}` |")
            if len(findings) > limit:
                lines.append(f"\n…and {len(findings) - limit} more.")
        else:
            lines.append("No findings. This does not prove the code is secure.")
    lines += ["", "_The index is a prioritization signal, not a breach probability or proof of safety._"]
    return "\n".join(lines)
