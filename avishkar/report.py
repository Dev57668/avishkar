"""Scan report: a JSON document and a self-contained, print-friendly HTML page ("Save as PDF" from any browser).

Every number and sentence is built from persisted scan data or from the static knowledge base; nothing is estimated,
and the limitations section is generated from what the run actually did (incomplete, unsupported languages,
heuristic rules, uncalibrated score). No PDF library is used on purpose (no extra dependency, no server-side rendering
of untrusted text): the HTML is escaped end to end and styled for print.
"""
from __future__ import annotations

import datetime as dt
import html

from . import knowledge
from .analysis import DISCLAIMER, SEV, SEV_RANK
from .domain.redaction import redact_text

REPORT_VERSION = "report-1"


def _ts(t) -> str | None:
    return None if t is None else dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _limitations(run: dict, findings: list[dict]) -> list[str]:
    out = []
    comp, sd = run.get("completeness") or {}, run.get("score") or {}
    if run["status"] != "complete":
        miss = ", ".join(comp.get("missing") or []) or ", ".join((comp.get("failures") or {}).keys()) or "unknown"
        out.append(f"INCOMPLETE ANALYSIS: required coverage is missing ({miss}). No score was calculated and the result is "
                   "NOT a pass.")
    ne = (sd.get("coverage") or {}).get("notEvaluated") or {}
    if ne:
        out.append("Not evaluated (no detector for these languages): " + ", ".join(f"{n} {e} file(s)" for e, n in ne.items()) + ".")
    heur = [f for f in findings if f["detection"]["assurance"] == "heuristic"]
    if heur:
        out.append(f"{len(heur)} of {len(findings)} findings come from heuristic rules (name/shape based) and may be false "
                   "positives; verify each before acting.")
    out += ["Findings show that a dangerous construct is present. The scanner does not prove exploitability: it performs no "
            "runtime analysis and only limited, same-file data-flow tracking.",
            "Zero findings does not mean the code is secure; detectors only know the patterns they were written for.",
            DISCLAIMER, "The code was never executed; archives are unpacked in isolation with path, size and symlink checks."]
    return out


def build_report(*, repo: dict, run: dict, rows: list[dict], explain: dict, compare: dict | None, cfg, service_version: str,
                 generated_at: float, uploads_note: str | None = None) -> dict:
    sd = run["score"] or {}
    comp = run["completeness"] or {}
    contrib = {c["fingerprint"]: c for c in explain.get("contributions", [])}
    # the ledger's *current* state can differ from the state this run saw (a later scan may have fixed it): the report of a
    # run describes that run, so state comes from the run's own score components when available.
    state_at_run = {c["fingerprint"]: c["state"] for c in (sd.get("components") or [])}
    findings = []
    for r in sorted(rows, key=lambda r: (SEV_RANK.get(r["severity"], 9), r["path"], r["line_start"])):
        k = knowledge.describe(r["rule_id"], r["category"])
        c = contrib.get(r["fingerprint"])
        findings.append({
            "id": r["id"], "ruleId": r["rule_id"], "title": r["title"], "severity": r["severity"],
            "confidence": r["confidence"], "category": r["category"], "state": state_at_run.get(r["fingerprint"], r["state"]),
            "path": r["path"], "line": r["line_start"], "evidence": redact_text(r["evidence"] or ""),
            "cwe": k["cwe"], "owasp": k["owasp"], "detection": k["detection"], "why": k["why"], "impact": k["impact"],
            "remediation": k["remediation"], "secureExample": k["secureExample"],
            "debt": None if not c else {"impact": c["I"], "exposure": c["E"], "confidence": c["C"], "age": c["A"],
                                        "units": c["D"], "shareOfGross": c["share"]}})
    sev = {s: sum(1 for f in findings if f["severity"] == s and f["state"] == "open") for s in SEV}
    open_n = sum(sev.values())
    if sd.get("status") == "calculated":
        summary = (f"Second Read analyzed {comp.get('filesScanned', '?')} file(s) of {repo['name']}"
                   f"{' at commit ' + run['commit_sha'][:12] if run.get('commit_sha') else ''}. The security debt index is "
                   f"{sd['normalizedIndex']} out of 100 ({sd['scoreVersion']}, uncalibrated), from {sd['grossUnits']:g} debt units "
                   f"across {open_n} open finding(s): {sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, "
                   f"{sev['low']} low. Policy outcome ({(run['decision'] or {}).get('mode', '').replace('_', '-')}): "
                   f"{(run['decision'] or {}).get('outcome', 'n/a').replace('_', ' ')}.")
    else:
        summary = (f"Second Read could not complete the analysis of {repo['name']}, so no security debt index was calculated. "
                   "This is not a pass.")
    return {
        "reportVersion": REPORT_VERSION, "generatedAt": _ts(generated_at),
        "executiveSummary": summary + " " + DISCLAIMER,
        "repository": {"id": repo["id"], "name": repo["name"]},
        "scan": {"runId": run["id"], "status": run["status"], "commitSha": run.get("commit_sha"),
                 "startedAt": _ts(run["started_at"]), "completedAt": _ts(run.get("completed_at")),
                 "durationSeconds": None if not run.get("completed_at") else round(run["completed_at"] - run["started_at"], 2),
                 "service": f"avishkar {service_version}", "scoreVersion": sd.get("scoreVersion"),
                 "policyVersion": run.get("policy_version"), "knowledgeBase": knowledge.KB_VERSION,
                 "requiredDetectors": comp.get("requiredDetectors"), "completedDetectors": comp.get("completedDetectors"),
                 "filesScanned": comp.get("filesScanned"), "failures": comp.get("failures") or {},
                 "coverage": sd.get("coverage"), "notes": run.get("notes") or []},
        "securityDebt": {k: sd.get(k) for k in ("status", "normalizedIndex", "rawUnits", "grossUnits", "scoreVersion", "k", "calibrated")},
        "decision": run.get("decision"),
        "severityDistribution": sev, "openFindings": open_n,
        "scoreExplanation": {"method": explain.get("method"), "totals": explain.get("totals"), "flags": explain.get("flags")},
        "findings": findings,
        "comparison": compare,
        "limitations": _limitations(run, findings),
    }


# ------------------------------------------------------------------------------------------------ HTML
CSS = """
:root{color-scheme:light}*{box-sizing:border-box}body{font:14px/1.55 system-ui,Segoe UI,Roboto,sans-serif;color:#111827;margin:0;background:#f4f5f7}
main{max-width:920px;margin:0 auto;background:#fff;padding:36px 44px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:30px 0 8px;
border-bottom:2px solid #111827;padding-bottom:4px}h3{font-size:15px;margin:0 0 4px}.mut{color:#4b5563}code,pre{font:12px/1.5 ui-monospace,Consolas,monospace}
pre{background:#0b1220;color:#e5e7eb;padding:10px 12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse}th,td{border:1px solid #d1d5db;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f3f4f6}
.kpi{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}.kpi div{border:1px solid #d1d5db;border-radius:8px;padding:10px 14px;min-width:130px}
.kpi b{display:block;font-size:24px}.sev{font-weight:700;text-transform:uppercase;font-size:11px;border:1px solid currentColor;border-radius:4px;padding:1px 6px}
.critical{color:#b91c1c}.high{color:#c2410c}.medium{color:#a16207}.low{color:#1d4ed8}.informational{color:#4b5563}
.warn{border-left:4px solid #b91c1c;background:#fef2f2;padding:8px 12px;margin:10px 0}.find{border:1px solid #d1d5db;border-radius:8px;padding:12px 14px;margin:12px 0;
break-inside:avoid}.tag{font-size:12px;border:1px solid #9ca3af;border-radius:4px;padding:0 6px;margin-right:4px}
@media print{body{background:#fff}main{padding:0;max-width:none}.find{page-break-inside:avoid}a{color:inherit;text-decoration:none}}
"""


def _e(x) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def render_html(rep: dict) -> str:
    sd, scan = rep["securityDebt"], rep["scan"]
    parts = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             f"<title>Second Read report — {_e(rep['repository']['name'])}</title><style>{CSS}</style></head><body><main>",
             f"<h1>Security debt report</h1><div class=\"mut\">{_e(rep['repository']['name'])} · generated {_e(rep['generatedAt'])} · "
             f"{_e(scan['service'])} · {_e(rep['reportVersion'])}</div>"]
    if scan["status"] != "complete":
        parts.append("<div class=\"warn\"><b>Incomplete analysis.</b> No score was calculated. This is not a pass.</div>")
    parts.append(f"<h2>Executive summary</h2><p>{_e(rep['executiveSummary'])}</p>")
    idx = sd.get("normalizedIndex")
    parts.append("<div class=\"kpi\">"
                 f"<div><span class=\"mut\">Security debt index</span><b>{_e(idx if idx is not None else 'n/a')}</b>{_e(sd.get('scoreVersion') or '')} · uncalibrated</div>"
                 f"<div><span class=\"mut\">Gross debt units</span><b>{_e(sd.get('grossUnits') if sd.get('grossUnits') is not None else 'n/a')}</b></div>"
                 f"<div><span class=\"mut\">Open findings</span><b>{_e(rep['openFindings'])}</b></div>"
                 f"<div><span class=\"mut\">Files scanned</span><b>{_e(scan.get('filesScanned') if scan.get('filesScanned') is not None else 'n/a')}</b></div></div>")
    parts.append("<h2>Severity distribution</h2><table><tr>" + "".join(f"<th>{s}</th>" for s in SEV) + "</tr><tr>" +
                 "".join(f"<td>{rep['severityDistribution'][s]}</td>" for s in SEV) + "</tr></table>")
    parts.append("<h2>Scan metadata</h2><table>" + "".join(
        f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in (
            ("Run id", scan["runId"]), ("Status", scan["status"]), ("Commit", scan.get("commitSha") or "n/a"),
            ("Started", scan["startedAt"]), ("Duration (s)", scan.get("durationSeconds")), ("Score version", scan.get("scoreVersion")),
            ("Policy version", scan.get("policyVersion")), ("Knowledge base", scan["knowledgeBase"]),
            ("Detectors", f"{scan.get('completedDetectors')}/{scan.get('requiredDetectors')} required completed"),
            ("Policy outcome", (rep.get("decision") or {}).get("outcome")))) + "</table>")
    ex = rep["scoreExplanation"]
    if ex.get("method"):
        m = ex["method"]
        parts.append(f"<h2>How the index is calculated</h2><p><code>{_e(m['formula'])}</code><br>{_e(m['aggregation'])}<br>"
                     f"<code>{_e(m['normalization'])}</code></p><ul>" + "".join(f"<li>{_e(n)}</li>" for n in m["notes"]) + "</ul>")
    cmp = rep.get("comparison")
    if cmp:
        parts.append("<h2>Before and after</h2>")
        if cmp.get("comparable"):
            d = cmp["delta"]
            parts.append(f"<p>Previous run {_e(cmp['base']['runId'])}: index {_e(cmp['base']['normalizedIndex'])} → this run: "
                         f"{_e(cmp['head']['normalizedIndex'])} (<b>{_e(d['index'])}</b>). </p><ul>" +
                         "".join(f"<li>{_e(x)}</li>" for x in cmp["explanation"]) + "</ul>")
        else:
            parts.append(f"<p>{_e(cmp.get('reason'))}</p>")
    parts.append(f"<h2>Findings ({len(rep['findings'])})</h2>")
    for f in rep["findings"]:
        cwe = ", ".join(f"{c['id']}" for c in f["cwe"]) or "no CWE mapped"
        debt = f["debt"]
        parts.append(
            f"<div class=\"find\"><h3><span class=\"sev {_e(f['severity'])}\">{_e(f['severity'])}</span> {_e(f['title'])}</h3>"
            f"<div class=\"mut\"><span class=\"tag\">{_e(f['ruleId'])}</span><span class=\"tag\">{_e(cwe)}</span>"
            f"<span class=\"tag\">confidence {_e(f['confidence'])}</span><span class=\"tag\">{_e(f['detection']['method'])} · {_e(f['detection']['assurance'])}</span>"
            f"<span class=\"tag\">state {_e(f['state'])}</span></div>"
            f"<p><code>{_e(f['path'])}:{_e(f['line'])}</code></p><pre>{_e(f['evidence'])}</pre>"
            f"<p><b>Why it matters.</b> {_e(f['why'])}</p><p><b>Impact.</b> {_e(f['impact'])}</p><p><b>Fix.</b> {_e(f['remediation'])}</p>"
            + (f"<pre>{_e(f['secureExample']['code'])}</pre>" if f.get("secureExample") else "")
            + (f"<p class=\"mut\">Debt: {_e(debt['impact'])} × {_e(debt['exposure'])} × {_e(debt['confidence'])} × {_e(debt['age'])} = "
               f"<b>{_e(debt['units'])}</b> units ({_e(debt['shareOfGross'])}% of total)</p>" if debt else "") + "</div>")
    parts.append("<h2>Limitations</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in rep["limitations"]) + "</ul>")
    parts.append("</main></body></html>")
    return "".join(parts)
