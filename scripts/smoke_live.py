"""Opt-in live smoke checks. Prints PASS/FAIL/SKIP per check; exits 1 only on FAIL (never on SKIP).

  ANTHROPIC_API_KEY                      -> real model returns a schema-valid, evidence-citing explanation
  GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY
  + GITHUB_SMOKE_INSTALLATION_ID         -> App JWT is accepted and an installation token can be minted
  + GITHUB_SMOKE_REPO (owner/name)       -> the repo's default branch zipball can be downloaded within limits
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
results = []


def record(name, status, detail=""):
    results.append((name, status))
    print(f"{status}: {name} {detail}")


def smoke_ai():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return record("anthropic explanation", "SKIP", "(no ANTHROPIC_API_KEY)")
    os.environ["AVISHKAR_AI_ENABLED"] = "1"
    from avishkar.adapters.ai import ExplanationService
    f = {"rule_id": "PY-EVAL", "title": "Dynamic code execution (eval/exec)", "category": "injection",
         "instances": [{"path": "app.py", "line_start": 3, "evidence": "x = eval(user_input)"}]}
    status, content, model = ExplanationService().explain(f)
    ok = status == "ok" and content and content["cited_rule_id"] == "PY-EVAL"
    record("anthropic explanation", "PASS" if ok else "FAIL", f"status={status} model={model}")


def smoke_github():
    need = ("GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY", "GITHUB_SMOKE_INSTALLATION_ID")
    if not all(os.environ.get(k) for k in need):
        return record("github app token", "SKIP", "(credentials not configured)")
    from avishkar.adapters.github import GitHubClient
    c = GitHubClient.from_env()
    try:
        tok = c.installation_token(os.environ["GITHUB_SMOKE_INSTALLATION_ID"])
        record("github app token", "PASS" if tok else "FAIL")
    except Exception as e:
        return record("github app token", "FAIL", type(e).__name__)
    repo = os.environ.get("GITHUB_SMOKE_REPO")
    if not repo:
        return record("github zipball", "SKIP", "(no GITHUB_SMOKE_REPO)")
    try:
        r = c._req("GET", f"/repos/{repo}", tok)
        branch = r.json()["default_branch"]
        sha = c._req("GET", f"/repos/{repo}/commits/{branch}", tok).json()["sha"]
        data = c.download_zipball(os.environ["GITHUB_SMOKE_INSTALLATION_ID"], repo, sha)
        record("github zipball", "PASS" if data[:2] == b"PK" else "FAIL", f"{len(data)} bytes")
    except Exception as e:
        record("github zipball", "FAIL", type(e).__name__)


if __name__ == "__main__":
    smoke_ai()
    smoke_github()
    sys.exit(1 if any(s == "FAIL" for _, s in results) else 0)
