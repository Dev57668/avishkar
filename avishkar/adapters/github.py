"""GitHub App integration (spec §16): signature verification, short-lived installation tokens,
snapshot download at an exact commit, and check-run publication.

Configuration (environment):
  GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY (PEM text) or GITHUB_APP_PRIVATE_KEY_PATH,
  GITHUB_WEBHOOK_SECRET, GITHUB_API_URL (default https://api.github.com)
Required GitHub App permissions (least privilege): Contents: read, Metadata: read, Pull requests: read,
Checks: write. Subscribe to events: pull_request, push, installation, installation_repositories.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import time

import httpx
import jwt

MAX_ARCHIVE = 25_000_000
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}$")
ALLOWED_EVENTS = {"ping", "pull_request", "push", "installation", "installation_repositories"}
PR_ACTIONS = {"opened", "synchronize", "reopened"}
CHECK_NAME = "Avishkar security debt"


class GitHubError(Exception):
    pass


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    """Constant-time check of X-Hub-Signature-256 over the unmodified request body."""
    if not secret or not header or not header.startswith("sha256="):
        return False
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)


def conclusion_for(run: dict, policy_mode: str) -> tuple[str, str]:
    """Map a run to a check conclusion. Analysis failure is never a pass (spec §16)."""
    if run["status"] != "complete":
        return "action_required", "Analysis incomplete — this is NOT a pass. Missing: " + \
            ", ".join(run["completeness"].get("missing") or ["unknown"])
    outcome = run["decision"]["outcome"]
    if outcome == "pass":
        return "success", "No policy predicates matched."
    if outcome == "warn":
        return "neutral", "Warning: " + ", ".join(run["decision"]["reasons"])
    if outcome == "block":
        return "failure", "Blocked by policy: " + ", ".join(run["decision"]["reasons"])
    return "neutral", f"Report-only: would block ({', '.join(run['decision']['reasons'])})"


class GitHubClient:
    def __init__(self, app_id: str, private_key: str, api_url: str = "https://api.github.com",
                 transport: httpx.BaseTransport | None = None):
        self.app_id, self.private_key, self.api = app_id, private_key, api_url.rstrip("/")
        self._http = httpx.Client(transport=transport, timeout=30, follow_redirects=True)
        self._tokens: dict[str, tuple[str, float]] = {}  # in memory only, never persisted

    @classmethod
    def from_env(cls) -> "GitHubClient | None":
        app_id = os.environ.get("GITHUB_APP_ID")
        key = os.environ.get("GITHUB_APP_PRIVATE_KEY")
        path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")
        if path and not key:
            key = open(path).read()
        if not (app_id and key):
            return None
        return cls(app_id, key, os.environ.get("GITHUB_API_URL", "https://api.github.com"))

    def _app_jwt(self) -> str:
        now = int(time.time())
        return jwt.encode({"iat": now - 30, "exp": now + 540, "iss": self.app_id}, self.private_key, algorithm="RS256")

    def _req(self, method, path, token, **kw):
        r = self._http.request(method, self.api + path, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}, **kw)
        if r.status_code >= 400:
            raise GitHubError(f"GitHub {method} {path} -> {r.status_code}")
        return r

    def installation_token(self, installation_id: str) -> str:
        cached = self._tokens.get(installation_id)
        if cached and cached[1] > time.time() + 60:
            return cached[0]
        r = self._req("POST", f"/app/installations/{installation_id}/access_tokens", self._app_jwt())
        tok = r.json()["token"]
        self._tokens[installation_id] = (tok, time.time() + 3000)
        return tok

    def download_zipball(self, installation_id: str, repo: str, sha: str) -> bytes:
        if not REPO_RE.match(repo) or not SHA_RE.match(sha):
            raise GitHubError("invalid repository or commit identifier")
        tok = self.installation_token(installation_id)
        with self._http.stream("GET", f"{self.api}/repos/{repo}/zipball/{sha}", headers={
                "Authorization": f"Bearer {tok}", "Accept": "application/vnd.github+json"}) as r:
            if r.status_code >= 400:
                raise GitHubError(f"zipball -> {r.status_code}")
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_ARCHIVE:
                    raise GitHubError("repository archive exceeds size limit")
            return bytes(buf)

    def create_check_run(self, installation_id: str, repo: str, sha: str, status="in_progress") -> int:
        tok = self.installation_token(installation_id)
        r = self._req("POST", f"/repos/{repo}/check-runs", tok,
                      json={"name": CHECK_NAME, "head_sha": sha, "status": status})
        return r.json()["id"]

    def upsert_pr_comment(self, installation_id: str, repo: str, pr_number: int, body: str, marker: str) -> str:
        """Edit our previous summary comment in place (found by hidden marker) or create one. Returns created|updated."""
        if not REPO_RE.match(repo) or not isinstance(pr_number, int):
            raise GitHubError("invalid repository or pull request number")
        tok = self.installation_token(installation_id)
        r = self._req("GET", f"/repos/{repo}/issues/{pr_number}/comments?per_page=100", tok)
        mine = next((c for c in r.json() if marker in (c.get("body") or "")), None)
        if mine:
            self._req("PATCH", f"/repos/{repo}/issues/comments/{mine['id']}", tok, json={"body": body})
            return "updated"
        self._req("POST", f"/repos/{repo}/issues/{pr_number}/comments", tok, json={"body": body})
        return "created"

    def complete_check_run(self, installation_id: str, repo: str, check_id: int, conclusion: str, summary: str,
                           text: str = ""):
        tok = self.installation_token(installation_id)
        self._req("PATCH", f"/repos/{repo}/check-runs/{check_id}", tok, json={
            "status": "completed", "conclusion": conclusion,
            "output": {"title": CHECK_NAME, "summary": summary[:1000], "text": text[:60000]}})


def pr_comments_enabled() -> bool:
    """Needs the extra 'Pull requests: write' permission, so it is opt-in (AVISHKAR_PR_COMMENTS=1)."""
    return os.environ.get("AVISHKAR_PR_COMMENTS") == "1"


def normalize_event(event: str, payload: dict) -> dict | None:
    """Reduce a provider payload to the few trusted fields we use. Nothing else is forwarded."""
    inst = str((payload.get("installation") or {}).get("id") or "")
    repo = (payload.get("repository") or {}).get("full_name")
    if event == "pull_request":
        if payload.get("action") not in PR_ACTIONS:
            return None
        pr = payload.get("pull_request") or {}
        return {"kind": "pull_request", "installation": inst, "repo": repo, "sha": (pr.get("head") or {}).get("sha"),
                "ref": f"pr/{pr.get('number')}", "pr": pr.get("number"),
                "fork": ((pr.get("head") or {}).get("repo") or {}).get("full_name") != repo}
    if event == "push":
        if payload.get("deleted") or not str(payload.get("ref", "")).startswith("refs/heads/"):
            return None
        return {"kind": "push", "installation": inst, "repo": repo, "sha": payload.get("after"),
                "ref": payload["ref"], "pr": None, "fork": False}
    return None
