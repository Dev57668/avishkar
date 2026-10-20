"""FastAPI control plane. Handlers validate input and call use cases; scoring lives in domain/.
Untrusted repository content is never parsed here -- it is spooled and handled by the sandboxed worker."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from ..adapters import github as gh
from ..adapters.ai import ExplanationService
from ..adapters.store import Store
from .. import telemetry
from ..domain import reporting
from ..domain.policy import Policy
from ..domain.scoring import ScoreConfig
from ..workers import runner as runner_mod
from ..workers.detectors import SUPPORT_MATRIX
from ..workers.runner import JobRunner, WorkerThread
from ..workers.sandbox import Sandbox
from .security import (ROLES, LoginThrottle, Principal, TokenService, hash_api_key, hash_password, new_api_key,
                       verify_password)

WEB_DIR = Path(__file__).resolve().parents[2] / "web"
MAX_UPLOAD = 25_000_000
MAX_WEBHOOK_BODY = 5_000_000


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=1, max_length=200)


class UserIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=200)
    password: str = Field(min_length=10, max_length=200)
    role: str = Field(pattern="^(viewer|analyst|admin)$")


class ApiKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=100)
    role: str = Field(default="analyst", pattern="^(viewer|analyst|admin)$")


class InstallationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    installation_id: str = Field(pattern=r"^\d{1,20}$")
    account: str = Field(min_length=1, max_length=100)


class DispositionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern="^(false_positive|not_applicable|duplicate|accepted_risk|open)$")
    rationale: str = Field(min_length=5, max_length=2000)
    expires_at: float | None = None
    expected_version: int


def bootstrap_admin(store: Store, org_name: str = "default", email: str | None = None,
                    password: str | None = None) -> dict | None:
    """Create the first organization + admin if none exist. Returns generated credentials if any."""
    if store.org_count():
        return None
    email = email or os.environ.get("AVISHKAR_ADMIN_EMAIL") or "admin@avishkar.local"
    generated = None
    password = password or os.environ.get("AVISHKAR_ADMIN_PASSWORD")
    if not password:
        password = generated = secrets.token_urlsafe(14)
    org = store.create_org(org_name)
    store.create_user(org["id"], email, hash_password(password), "admin")
    return {"email": email, "password": generated} if generated else {"email": email, "password": None}


def create_app(db_url: str | None = None, *, secret_key: str | None = None, score_cfg: ScoreConfig | None = None,
               policy: Policy | None = None, sandbox: Sandbox | None = None, github: gh.GitHubClient | None = None,
               ai: ExplanationService | None = None, start_worker: bool | None = None,
               webhook_secret: str | None = None, max_active_jobs: int | None = None) -> FastAPI:
    telemetry.configure_logging()
    telemetry.configure_tracing()
    cfg = score_cfg or ScoreConfig.load()
    pol = policy or Policy.load()
    store = Store(db_url or os.environ.get("DATABASE_URL", "data/avishkar_v2.db"))
    tokens = TokenService(secret_key or os.environ.get("AVISHKAR_SECRET_KEY") or secrets.token_urlsafe(48))
    sbx = sandbox or Sandbox()
    github = github if github is not None else gh.GitHubClient.from_env()
    ai = ai or ExplanationService()
    wh_secret = webhook_secret if webhook_secret is not None else os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    quota = max_active_jobs or int(os.environ.get("AVISHKAR_MAX_ACTIVE_JOBS", "20"))
    throttle = LoginThrottle(store)
    dummy_hash = hash_password(secrets.token_urlsafe(12))
    runner = JobRunner(store, cfg, pol, sbx, github)
    if start_worker is None:
        start_worker = os.environ.get("AVISHKAR_EMBEDDED_WORKER", "1") != "0"
    worker = WorkerThread(runner)
    def count(k):
        store.incr_metric(k)

    @asynccontextmanager
    async def lifespan(app):
        if start_worker:
            worker.start()
        yield
        if start_worker:
            worker.stop()

    app = FastAPI(title="Avishkar", version="2.0.0", lifespan=lifespan,
                  description="AI Generated Code Security Debt Scorer. The score is a prioritization "
                              "signal, not proof of safety.")
    app.state.store, app.state.runner, app.state.tokens = store, runner, tokens

    @app.middleware("http")
    async def correlation(request: Request, call_next):
        request.state.cid = "corr_" + uuid.uuid4().hex[:12]
        resp = await call_next(request)
        resp.headers["X-Correlation-Id"] = request.state.cid
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(ApiError)
    async def api_error(request: Request, e: ApiError):
        return JSONResponse({"error": {"code": e.code, "message": e.message,
                                       "correlationId": request.state.cid}}, status_code=e.status)

    @app.exception_handler(422)
    async def invalid(request: Request, e):
        return JSONResponse({"error": {"code": "invalid_input", "message": "Request validation failed",
                                       "correlationId": request.state.cid}}, status_code=422)

    # ------------------------------------------------------------ auth
    def principal(request: Request, authorization: str | None = Header(default=None),
                  x_api_key: str | None = Header(default=None)) -> Principal:
        if x_api_key:
            k = store.api_key(hash_api_key(x_api_key))
            if k:
                return Principal(k["id"], k["organization_id"], k["role"], None, "api_key")
        elif authorization and authorization.lower().startswith("bearer "):
            claims = tokens.verify(authorization[7:])
            if claims:
                u = store.user(claims["sub"])  # re-check so deactivation/role change takes effect immediately
                if u:
                    return Principal(u["id"], u["organization_id"], u["role"], u["email"], "token")
        raise ApiError(401, "unauthorized", "Missing or invalid credentials")

    def need(role: str):
        def dep(p: Principal = Depends(principal)) -> Principal:
            if not p.has(role):
                raise ApiError(403, "forbidden", f"Requires role {role}")
            return p
        return dep

    viewer, analyst, admin = need("viewer"), need("analyst"), need("admin")

    def repo_or_404(repo_id: str, p: Principal) -> dict:
        r = store.repo(repo_id, p.org_id)
        if not r:  # same response for missing and other-tenant: do not reveal existence
            raise ApiError(404, "not_found", "Not found")
        return r

    @app.post("/v1/auth/login")
    def login(body: LoginIn, request: Request):
        key = body.email.lower()
        if throttle.blocked(key):
            raise ApiError(429, "rate_limited", "Too many failed attempts; try again later")
        u = store.user_by_email(key)
        ok = verify_password(body.password, u["password_hash"]) if u else \
            verify_password(body.password, "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$" + "A" * 43 + "=")  # equalize timing
        if not (u and ok):
            throttle.fail(key)
            store.audit(key, "login", "user", key, "denied", request.state.cid)
            raise ApiError(401, "unauthorized", "Invalid email or password")
        throttle.ok(key)
        tok, exp = tokens.issue(u)
        store.audit(u["email"], "login", "user", u["id"], "ok", request.state.cid, org=u["organization_id"])
        return {"token": tok, "expiresAt": exp, "user": {"id": u["id"], "email": u["email"], "role": u["role"]}}

    @app.get("/v1/auth/me")
    def me(p: Principal = Depends(principal)):
        return {"id": p.id, "organizationId": p.org_id, "role": p.role, "email": p.email, "via": p.via}

    @app.get("/v1/users")
    def users(p: Principal = Depends(admin)):
        return {"items": store.users(p.org_id)}

    @app.post("/v1/users", status_code=201)
    def add_user(body: UserIn, request: Request, p: Principal = Depends(admin)):
        if store.user_by_email(body.email):
            raise ApiError(409, "conflict", "User already exists")
        u = store.create_user(p.org_id, body.email, hash_password(body.password), body.role)
        store.audit(p.email or p.id, "user_created", "user", u["id"], "ok", request.state.cid, {"role": body.role}, p.org_id)
        return u

    @app.delete("/v1/users/{uid}")
    def del_user(uid: str, request: Request, p: Principal = Depends(admin)):
        if uid == p.id:
            raise ApiError(422, "invalid_input", "You cannot deactivate yourself")
        if not store.deactivate_user(p.org_id, uid):
            raise ApiError(404, "not_found", "Not found")
        store.audit(p.email or p.id, "user_deactivated", "user", uid, "ok", request.state.cid, org=p.org_id)
        return {"status": "deactivated"}

    @app.get("/v1/api-keys")
    def keys(p: Principal = Depends(admin)):
        return {"items": store.api_keys(p.org_id)}

    @app.post("/v1/api-keys", status_code=201)
    def add_key(body: ApiKeyIn, request: Request, p: Principal = Depends(admin)):
        key, h = new_api_key()
        kid = store.create_api_key(p.org_id, body.role, body.label, h)
        store.audit(p.email or p.id, "api_key_created", "api_key", kid, "ok", request.state.cid, org=p.org_id)
        return {"id": kid, "key": key, "note": "Store this key now; it cannot be shown again."}

    @app.delete("/v1/api-keys/{kid}")
    def revoke_key(kid: str, p: Principal = Depends(admin)):
        if not store.revoke_api_key(p.org_id, kid):
            raise ApiError(404, "not_found", "Not found")
        return {"status": "revoked"}

    # ------------------------------------------------------------ meta
    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/v1/config")
    def config(p: Principal = Depends(viewer)):
        return {"scoreVersion": cfg.version, "k": cfg.k, "calibrated": False, "agingEnabled": cfg.aging_enabled,
                "requiredDetectors": list(cfg.required_detectors), "policyVersion": pol.version,
                "policyMode": pol.mode, "supportMatrix": SUPPORT_MATRIX, "sandbox": sbx.describe(),
                "ai": ai.status(), "github": {"configured": github is not None and bool(wh_secret)},
                "database": "postgresql" if store.d.pg else "sqlite",
                "disclaimer": "Index is a prioritization signal, not a breach probability or proof of safety."}

    @app.get("/v1/metrics")
    def get_metrics(p: Principal = Depends(admin)):
        return {"counters": store.metrics()}

    # ------------------------------------------------------------ repositories & analyses
    def _run_out(r: dict, repo_id: str):
        sd = r["score"] or {"status": "pending", "rawUnits": None, "normalizedIndex": None, "scoreVersion": cfg.version}
        return {"id": r["id"], "repositoryId": repo_id, "status": r["status"], "commitSha": r["commit_sha"],
                "policyVersion": r["policy_version"],
                "completeness": r["completeness"] or {"state": "pending", "missing": []},
                "securityDebt": {k: v for k, v in sd.items() if k != "components"},
                "decision": r["decision"] or {"outcome": "pending", "reasons": [], "mode": pol.mode},
                "stages": r["stages"], "notes": r["notes"], "startedAt": r["started_at"],
                "completedAt": r["completed_at"], "findingsUrl": f"/v1/repositories/{repo_id}/findings",
                "scoreUrl": f"/v1/analyses/{r['id']}/score"}

    @app.get("/v1/repositories")
    def repos(p: Principal = Depends(viewer)):
        out = []
        for r in store.repos(p.org_id):
            sc = json.loads(r["latest_score"]) if r["latest_score"] else None
            out.append({"id": r["id"], "name": r["name"], "runs": r["runs"],
                        "latestIndex": sc and sc["normalizedIndex"], "latestRawUnits": sc and sc["rawUnits"]})
        return {"items": out}

    def _enqueue(p, repo, kind, payload, commit_sha, corr, idem=None):
        if store.active_job_count(p.org_id) >= quota:
            count("quota_rejected")
            raise ApiError(429, "rate_limited", "Too many queued analyses for this organization")
        if idem:
            ex = store.job_by_idem(p.org_id, idem)
            if ex:
                return ex["run_id"], ex, False
        run_id = store.create_run(repo["id"], commit_sha, corr)
        job, created = store.enqueue(p.org_id, repo["id"], run_id, kind, payload, idem)
        return job["run_id"], job, created

    @app.post("/v1/analyses", status_code=202)
    async def create_analysis(request: Request, repository: str = Form(pattern=r"^[\w.\-/]{1,100}$"),
                              commit_sha: str | None = Form(default=None, pattern=r"^[0-9a-fA-F]{4,64}$"),
                              archive: UploadFile = File(), idempotency_key: str | None = Header(default=None),
                              p: Principal = Depends(analyst)):
        data = await archive.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise ApiError(413, "too_large", "Archive exceeds upload limit")
        if data[:2] != b"PK":
            raise ApiError(422, "invalid_input", "Upload must be a zip archive")
        repo = store.get_or_create_repo(p.org_id, repository)
        runner_mod.SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        spool = runner_mod.SPOOL_DIR / f"up_{uuid.uuid4().hex}.zip"
        spool.write_bytes(data)
        try:
            run_id, job, created = _enqueue(p, repo, "archive", {"spool_path": str(spool.resolve())}, commit_sha,
                                            request.state.cid, idempotency_key)
        except Exception:
            spool.unlink(missing_ok=True)
            raise
        if not created:
            spool.unlink(missing_ok=True)
        store.audit(p.email or p.id, "analysis_queued", "analysis_run", run_id, "ok", request.state.cid, org=p.org_id)
        return {"jobId": job["id"], "runId": run_id, "repositoryId": repo["id"], "status": "queued",
                "deduplicated": not created, "statusUrl": f"/v1/repositories/{repo['id']}/analyses/{run_id}"}

    @app.get("/v1/repositories/{repo_id}/analyses")
    def analyses(repo_id: str, p: Principal = Depends(viewer)):
        repo_or_404(repo_id, p)
        return {"items": [_run_out(r, repo_id) for r in store.runs(repo_id)]}

    @app.get("/v1/repositories/{repo_id}/analyses/{run_id}")
    def analysis(repo_id: str, run_id: str, p: Principal = Depends(viewer)):
        repo_or_404(repo_id, p)
        r = store.run(run_id)
        if not r or r["repository_id"] != repo_id:
            raise ApiError(404, "not_found", "Not found")
        return _run_out(r, repo_id)

    @app.get("/v1/analyses/{run_id}/score")
    def score(run_id: str, p: Principal = Depends(viewer)):
        r = store.run(run_id)
        if not r or not store.repo(r["repository_id"], p.org_id):
            raise ApiError(404, "not_found", "Not found")
        return r["score"] or {"status": "pending"}

    @app.get("/v1/analyses/{run_id}/sarif")
    def sarif(run_id: str, p: Principal = Depends(viewer)):
        r = store.run(run_id)
        if not r or not store.repo(r["repository_id"], p.org_id):
            raise ApiError(404, "not_found", "Not found")
        return JSONResponse(reporting.to_sarif(r, store.run_findings(run_id)),
                            media_type="application/sarif+json")

    @app.get("/v1/repositories/{repo_id}/findings")
    def findings(repo_id: str, state: str | None = None, severity: str | None = None,
                 cursor: str | None = None, limit: int = 50, p: Principal = Depends(viewer)):
        repo_or_404(repo_id, p)
        store.expire_exceptions(p.org_id)
        rows, nxt = store.findings(repo_id, state, severity, cursor, max(1, min(limit, 200)))
        return {"items": rows, "nextCursor": nxt}

    @app.get("/v1/findings/{fid}")
    def finding(fid: str, p: Principal = Depends(viewer)):
        f = store.finding(fid, p.org_id)
        if not f:
            raise ApiError(404, "not_found", "Not found")
        return f

    @app.post("/v1/findings/{fid}/dispositions")
    def disposition(fid: str, body: DispositionIn, request: Request, p: Principal = Depends(analyst)):
        if body.type == "accepted_risk" and not body.expires_at:
            raise ApiError(422, "invalid_input", "accepted_risk requires expires_at (bounded exception)")
        if body.expires_at and body.expires_at <= time.time():
            raise ApiError(422, "invalid_input", "expires_at must be in the future")
        actor = p.email or p.id
        status, f = store.disposition(fid, p.org_id, body.type, body.rationale, actor, body.expires_at,
                                      body.expected_version)
        if status == "not_found":
            raise ApiError(404, "not_found", "Not found")
        if status == "conflict":
            store.audit(actor, "disposition", "finding", fid, "conflict", request.state.cid, org=p.org_id)
            raise ApiError(409, "conflict", f"Stale version; current version is {f['version']}")
        store.audit(actor, f"disposition:{body.type}", "finding", fid, "ok", request.state.cid,
                    {"rationale": body.rationale}, p.org_id)
        return f

    # ------------------------------------------------------------ AI explanations (optional, advisory only)
    @app.post("/v1/findings/{fid}/explanation")
    def explain(fid: str, request: Request, p: Principal = Depends(analyst)):
        f = store.finding(fid, p.org_id)
        if not f:
            raise ApiError(404, "not_found", "Not found")
        status, content, model = ai.explain(f)
        if status != "disabled":
            store.save_explanation(fid, status, content, model, "explain-v1")
            store.audit(p.email or p.id, "ai_explanation", "finding", fid, status, request.state.cid, org=p.org_id)
        return {"status": status, "content": content, "model": model,
                "advisory": "AI text never changes severity, state, score or policy outcome."}

    # ------------------------------------------------------------ jobs
    @app.get("/v1/jobs")
    def jobs(status: str | None = None, p: Principal = Depends(analyst)):
        return {"items": [{k: v for k, v in j.items() if k != "payload"} for j in store.jobs(p.org_id, status)]}

    @app.post("/v1/jobs/{jid}/requeue")
    def requeue(jid: str, p: Principal = Depends(admin)):
        if not store.requeue_dead(p.org_id, jid):
            raise ApiError(404, "not_found", "No dead job with that id")
        return {"status": "queued"}

    # ------------------------------------------------------------ GitHub App
    @app.get("/v1/github/installations")
    def installs(p: Principal = Depends(admin)):
        return {"items": store.installations(p.org_id)}

    @app.post("/v1/github/installations", status_code=201)
    def link(body: InstallationIn, request: Request, p: Principal = Depends(admin)):
        if not store.link_installation(p.org_id, body.installation_id, body.account):
            raise ApiError(409, "conflict", "Installation is already linked to another organization")
        store.audit(p.email or p.id, "installation_linked", "installation", body.installation_id, "ok",
                    request.state.cid, org=p.org_id)
        return {"installationId": body.installation_id, "account": body.account}

    @app.post("/v1/github/webhook")
    async def webhook(request: Request, x_hub_signature_256: str | None = Header(default=None),
                      x_github_event: str | None = Header(default=None),
                      x_github_delivery: str | None = Header(default=None)):
        if not wh_secret:
            raise ApiError(503, "unavailable", "GitHub integration is not configured")
        body = await request.body()
        if len(body) > MAX_WEBHOOK_BODY:
            raise ApiError(413, "too_large", "Payload too large")
        if not gh.verify_signature(wh_secret, body, x_hub_signature_256):
            count("webhook_bad_signature")
            raise ApiError(401, "unauthorized", "Invalid signature")  # no body parsed before this point
        if not x_github_delivery or not x_github_event:
            raise ApiError(422, "invalid_input", "Missing delivery headers")
        if x_github_event not in gh.ALLOWED_EVENTS:
            count("webhook_ignored_event")
            return JSONResponse({"status": "ignored"}, status_code=202)
        if not store.record_delivery("github", x_github_delivery, x_github_event, hashlib.sha256(body).hexdigest()):
            count("webhook_replay")
            return {"status": "duplicate"}
        try:
            payload = json.loads(body)
            assert isinstance(payload, dict)
        except Exception:
            count("webhook_malformed")
            raise ApiError(400, "invalid_input", "Malformed JSON")
        if x_github_event == "ping":
            return {"status": "pong"}
        if x_github_event in ("installation", "installation_repositories"):
            iid = str((payload.get("installation") or {}).get("id") or "")
            if payload.get("action") in ("deleted", "suspend") and iid:
                store.deactivate_installation(iid)
            store.set_delivery_outcome("github", x_github_delivery, "installation_event")
            return JSONResponse({"status": "ok"}, status_code=202)
        ev = gh.normalize_event(x_github_event, payload)
        if not ev or not ev["repo"] or not gh.REPO_RE.match(ev["repo"]) or not gh.SHA_RE.match(str(ev["sha"] or "")):
            count("webhook_ignored_event")
            return JSONResponse({"status": "ignored"}, status_code=202)
        inst = store.installation(ev["installation"])
        if not inst:
            count("webhook_unknown_installation")
            return JSONResponse({"status": "ignored"}, status_code=202)  # do not reveal tenant state
        org = inst["organization_id"]
        repo = store.get_or_create_repo(org, ev["repo"])
        store.set_ref_head(repo["id"], ev["ref"], ev["sha"])
        pr = Principal("github", org, "analyst", None, "api_key")
        run_id, job, created = _enqueue(
            pr, repo, "github", {"installation": ev["installation"], "repo": ev["repo"], "sha": ev["sha"],
                                 "ref": ev["ref"], "pr": ev["pr"]}, ev["sha"], request.state.cid,
            f"gh:{ev['repo']}:{ev['sha']}")
        count("webhook_accepted")
        store.set_delivery_outcome("github", x_github_delivery, "queued" if created else "deduplicated")
        return JSONResponse({"status": "queued" if created else "deduplicated", "jobId": job["id"]}, status_code=202)

    @app.get("/v1/audit")
    def audit(p: Principal = Depends(admin)):
        return {"items": store.audit_log(p.org_id)}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    return app
