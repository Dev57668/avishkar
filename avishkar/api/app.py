"""FastAPI control plane. Handlers validate input and call use cases; scoring lives in domain/.
Untrusted repository content is never parsed here -- it is spooled and handled by the sandboxed worker."""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..adapters import github as gh
from ..adapters.ai import ExplanationService
from ..adapters.mailer import MailError, Mailer
from ..adapters.store import Store
from ..demo import DemoSettings
from .. import analysis, assistant as assistant_mod, knowledge, report as report_mod, samples as samples_mod, telemetry
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
MAX_UPLOAD = int(os.environ.get("AVISHKAR_MAX_UPLOAD_MB", "100")) * 1_000_000  # admin zip size cap; the unpacker still enforces file-count and uncompressed-size limits
LIMITED = {"zip_bytes": 2_000_000, "files": 300, "declared_bytes": 10_000_000, "per_hour": 3}  # non-admin uploads in "limited" mode
MAX_WEBHOOK_BODY = 5_000_000


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=1, max_length=200)


class SignupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=200)
    password: str = Field(min_length=10, max_length=200)


class EmailIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=200)


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=20, max_length=100, pattern=r"^[\w\-]+$")


class ResetIn(TokenIn):
    password: str = Field(min_length=10, max_length=200)


class UserIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=200)
    password: str = Field(min_length=10, max_length=200)
    role: str = Field(pattern="^(viewer|analyst|admin)$")


class ApiKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=100)
    role: str = Field(default="analyst", pattern="^(viewer|analyst|admin)$")


class GitHubScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    installation: str = Field(pattern=r"^\d{1,20}$")
    repo: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}$")
    branch: str = Field(min_length=1, max_length=200, pattern=r"^[\w.\-/]+$")

    @field_validator("repo")
    @classmethod
    def _repo(cls, v: str) -> str:
        if not gh.REPO_RE.match(v):
            raise ValueError("invalid repository name")
        return v


class InstallationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    installation_id: str = Field(pattern=r"^\d{1,20}$")
    account: str = Field(min_length=1, max_length=100)


class AssistantIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repositoryId: str = Field(pattern=r"^repo_\w{1,40}$")
    runId: str | None = Field(default=None, pattern=r"^run_\w{1,40}$")
    findingId: str | None = Field(default=None, pattern=r"^fnd_\w{1,40}$")
    mode: str = Field(pattern="^(ask|explain_cwe|prioritize|secure_alternative|review_fix)$")
    question: str = Field(min_length=1, max_length=600)
    proposedFix: str | None = Field(default=None, max_length=4000)
    includeSnippets: bool = False
    consent: bool = False


class DemoScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample: str = Field(pattern=r"^[a-z0-9\-]{1,40}$")
    fixes: list[str] = Field(default_factory=list, max_length=60)


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
               webhook_secret: str | None = None, max_active_jobs: int | None = None,
               demo: DemoSettings | None = None, mailer: Mailer | None = None) -> FastAPI:
    telemetry.configure_logging()
    telemetry.configure_tracing()
    cfg = score_cfg or ScoreConfig.load()
    demo = demo or DemoSettings.from_env()
    pol = policy or Policy.load()
    store = Store(db_url or os.environ.get("DATABASE_URL", "data/avishkar_v2.db"))
    tokens = TokenService(secret_key or os.environ.get("AVISHKAR_SECRET_KEY") or secrets.token_urlsafe(48))
    sbx = sandbox or Sandbox()
    github = github if github is not None else gh.GitHubClient.from_env()
    ai = ai or ExplanationService()
    mail = mailer if mailer is not None else Mailer.from_env()
    wh_secret = webhook_secret if webhook_secret is not None else os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    quota = max_active_jobs or int(os.environ.get("AVISHKAR_MAX_ACTIVE_JOBS", "20"))
    throttle = LoginThrottle(store)
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
    app.state.cfg, app.state.pol, app.state.sandbox, app.state.demo = cfg, pol, sbx, demo

    @app.middleware("http")
    async def correlation(request: Request, call_next):
        request.state.cid = "corr_" + uuid.uuid4().hex[:12]
        resp = await call_next(request)
        resp.headers["X-Correlation-Id"] = request.state.cid
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        path = request.url.path
        if path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-cache"  # public assets: revalidate (ETag) instead of re-downloading or serving stale code
        else:
            resp.headers["Cache-Control"] = "no-store"  # API responses and authenticated reports are never cached
        if resp.headers.get("content-type", "").startswith("text/html"):
            resp.headers["Content-Security-Policy"] = (  # the page uses only same-origin scripts; no inline script is allowed
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
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
        if store.is_unverified(u["id"]):
            raise ApiError(403, "email_not_verified", "Confirm your email first: open the link we sent you")
        throttle.ok(key)
        tok, exp = tokens.issue(u)
        store.audit(u["email"], "login", "user", u["id"], "ok", request.state.cid, org=u["organization_id"])
        return {"token": tok, "expiresAt": exp, "user": {"id": u["id"], "email": u["email"], "role": u["role"]}}

    def _public_org() -> str:
        org = store.d.query("SELECT id FROM organization ORDER BY created_at LIMIT 1")
        return org[0]["id"]

    def _send_link(u: dict, purpose: str, ttl: float) -> None:
        tok = secrets.token_urlsafe(32)
        store.add_email_token(u["id"], purpose, hashlib.sha256(tok.encode()).hexdigest(), time.time() + ttl)
        assert mail is not None  # callers check the mailer first
        (mail.send_verification if purpose == "verify" else mail.send_reset)(u["email"], tok)

    def _mail_budget(org: str, action: str, key: str, per_hour: int) -> bool:
        return store.recent_audit_count(org, key, action, time.time() - 3600) < per_hour

    @app.post("/v1/auth/register", status_code=202)
    def register(body: SignupIn, request: Request):
        """Self sign-up for the public demo. The person gets a private one-user organization (role analyst there), and the account cannot sign in until the emailed
        link is opened. Needs the mailer (Resend) and AVISHKAR_SIGNUP=1 in demo mode; otherwise it is refused."""
        if not (demo.enabled and demo.signup and mail):
            raise ApiError(403, "signup_disabled", "Sign-up is not enabled on this instance")
        org = _public_org()
        if not _mail_budget(org, "signup", "signup", 30):
            raise ApiError(429, "rate_limited", "Too many sign-ups right now; try again later")
        email = body.email.lower()
        if store.user_by_email(email):
            raise ApiError(409, "conflict", "That email cannot be registered")
        # Each self-registered account gets its OWN organization (existing tenant isolation), so its uploads, findings and
        # runs are visible to nobody else. Analyst is therefore safe inside that private org.
        own = store.create_org("user-" + secrets.token_hex(8))
        u = store.create_user(own["id"], email, hash_password(body.password), "analyst")
        store.mark_unverified(u["id"])
        store.audit("signup", "signup", "user", u["id"], "ok", request.state.cid, org=org)
        try:
            _send_link(u, "verify", 86400)
        except MailError:
            raise ApiError(502, "email_failed", "Account created but the verification email could not be sent; use resend")
        return {"status": "verification_sent"}

    @app.post("/v1/auth/resend", status_code=202)
    def resend(body: EmailIn, request: Request):
        """Same response whether or not the address exists, so this cannot be used to probe for accounts."""
        u = store.user_by_email(body.email) if mail else None
        org = _public_org()
        if u and store.is_unverified(u["id"]) and _mail_budget(org, "resend", body.email.lower(), 3):
            store.audit(body.email.lower(), "resend", "user", u["id"], "ok", request.state.cid, org=org)
            try:
                _send_link(u, "verify", 86400)
            except MailError:
                pass
        return {"status": "ok"}

    @app.post("/v1/auth/forgot", status_code=202)
    def forgot(body: EmailIn, request: Request):
        """Password reset by email, only for self-registered accounts (admins/operators use the CLI). Uniform response."""
        u = store.user_by_email(body.email) if mail else None
        org = _public_org()
        if u and store.self_registered(u["id"]) and not store.is_unverified(u["id"]) and _mail_budget(org, "forgot", body.email.lower(), 3):
            store.audit(body.email.lower(), "forgot", "user", u["id"], "ok", request.state.cid, org=org)
            try:
                _send_link(u, "reset", 3600)
            except MailError:
                pass
        return {"status": "ok"}

    @app.post("/v1/auth/verify")
    def verify_email(body: TokenIn, request: Request):
        uid = store.consume_email_token(hashlib.sha256(body.token.encode()).hexdigest(), "verify")
        if not uid:
            raise ApiError(400, "invalid_token", "This link is invalid, expired or already used")
        store.verify_user(uid)
        store.audit("email", "email_verified", "user", uid, "ok", request.state.cid)
        return {"status": "verified"}

    @app.post("/v1/auth/reset")
    def reset_password(body: ResetIn, request: Request):
        uid = store.consume_email_token(hashlib.sha256(body.token.encode()).hexdigest(), "reset")
        if not uid:
            raise ApiError(400, "invalid_token", "This link is invalid, expired or already used")
        store.set_password(uid, hash_password(body.password))
        store.audit("email", "password_reset", "user", uid, "ok", request.state.cid)
        return {"status": "password_changed"}

    @app.post("/v1/auth/guest")
    def guest(request: Request):
        """One-click read-only session as the shared demo viewer. Same privileges as the published demo login."""
        if not (demo.enabled and demo.password):
            raise ApiError(403, "guest_disabled", "Guest access is not enabled on this instance")
        u = store.user_by_email(demo.email)
        if not u or u["role"] != "viewer":
            raise ApiError(403, "guest_disabled", "Guest access is not enabled on this instance")
        org = u["organization_id"]
        if store.recent_audit_count(org, "guest", "guest_session", time.time() - 60) >= 60:
            raise ApiError(429, "rate_limited", "Too many guest sessions; wait a minute")
        store.audit("guest", "guest_session", "user", u["id"], "ok", request.state.cid, org=org)
        tok, exp = tokens.issue(u)
        return {"token": tok, "expiresAt": exp, "user": {"id": u["id"], "email": u["email"], "role": "viewer"}}

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

    @app.get("/v1/public/status")
    def public_status():
        """Unauthenticated, tiny and secret-free: lets the web page pick live / demo / static mode. The demo login is
        included only when the operator opted in AND it is a viewer (read-only) account."""
        st = demo.public_status(sbx.describe(), cfg.version)
        st["signup"] = bool(st["signup"] and mail)  # never advertise sign-up without a working mailer
        return st

    @app.get("/v1/config")
    def config(p: Principal = Depends(viewer)):
        return {"scoreVersion": cfg.version, "k": cfg.k, "calibrated": False, "agingEnabled": cfg.aging_enabled,
                "requiredDetectors": list(cfg.required_detectors), "policyVersion": pol.version,
                "policyMode": pol.mode, "supportMatrix": SUPPORT_MATRIX, "sandbox": sbx.describe(),
                "ai": ai.status(), "uploads": demo.uploads, "github": {"configured": github is not None and bool(wh_secret)},
                "database": "postgresql" if store.d.pg else "sqlite", "uploadLimitMb": MAX_UPLOAD // 1_000_000,
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
        if demo.uploads == "off" or (demo.uploads == "admin" and not p.has("admin")):
            raise ApiError(403, "uploads_disabled",
                           "Uploads are disabled on this instance" + (" for non-admin users" if demo.uploads == "admin" else ""))
        capped = demo.uploads == "limited" and not p.has("admin")
        data = await archive.read((LIMITED["zip_bytes"] if capped else MAX_UPLOAD) + 1)
        if len(data) > (LIMITED["zip_bytes"] if capped else MAX_UPLOAD):
            raise ApiError(413, "too_large", "Archive exceeds the upload limit"
                           + (f" ({LIMITED['zip_bytes'] // 1_000_000} MB on this instance)" if capped else ""))
        if data[:2] != b"PK":
            raise ApiError(422, "invalid_input", "Upload must be a zip archive")
        if capped:
            if store.recent_audit_count(p.org_id, p.email or p.id, "analysis_queued", time.time() - 3600) >= LIMITED["per_hour"]:
                raise ApiError(429, "rate_limited", f"Upload limit reached ({LIMITED['per_hour']} per hour on this instance)")
            try:  # cheap pre-check of the central directory; the extractor still enforces the real limits while unpacking
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    infos = z.infolist()
                if len(infos) > LIMITED["files"] or sum(i.file_size for i in infos) > LIMITED["declared_bytes"]:
                    raise ApiError(413, "too_large", f"Archive has too many files or is too large uncompressed "
                                   f"(max {LIMITED['files']} files, {LIMITED['declared_bytes'] // 1_000_000} MB)")
            except zipfile.BadZipFile:
                raise ApiError(422, "invalid_input", "Upload must be a valid zip archive")
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
    def analyses(repo_id: str, limit: int = Query(50, ge=1, le=200), p: Principal = Depends(viewer)):
        repo_or_404(repo_id, p)
        return {"items": [_run_out(r, repo_id) for r in store.runs(repo_id, limit)]}

    @app.get("/v1/repositories/{repo_id}/analyses/{run_id}")
    def analysis_run(repo_id: str, run_id: str, p: Principal = Depends(viewer)):
        repo_or_404(repo_id, p)
        r = store.run(run_id)
        if not r or r["repository_id"] != repo_id:
            raise ApiError(404, "not_found", "Not found")
        return _run_out(r, repo_id)

    def run_or_404(run_id: str, p: Principal) -> dict:
        r = store.run(run_id)
        if not r or not store.repo(r["repository_id"], p.org_id):
            raise ApiError(404, "not_found", "Not found")
        return r

    @app.get("/v1/analyses/{run_id}/score")
    def score(run_id: str, p: Principal = Depends(viewer)):
        return run_or_404(run_id, p)["score"] or {"status": "pending"}

    # ------------------------------------------------------------ one-click demo (real scans of bundled samples)
    def demo_allowed(p: Principal) -> bool:
        return demo.enabled or p.has("analyst")

    @app.get("/v1/demo/samples")
    def demo_samples(p: Principal = Depends(viewer)):
        return {"scanAllowed": demo_allowed(p),
                "items": [samples_mod.describe(s) for s in samples_mod.SAMPLES.values()],
                "note": "Scans run the real pipeline on the bundled, trusted sample files. Nothing is simulated."}

    @app.get("/v1/demo/samples/{sample_id}")
    def demo_sample(sample_id: str, fixes: str | None = Query(None, max_length=1500, pattern=r"^[a-z0-9\-,]*$"),
                    p: Principal = Depends(viewer)):
        applied = [x for x in (fixes or "").split(",") if x]
        try:
            files = samples_mod.variant_files(sample_id, applied)
            diffs = {f: samples_mod.fix_diff(sample_id, f) for f in dict.fromkeys(applied)}
        except samples_mod.SampleError:
            raise ApiError(404, "not_found", "Unknown sample or fix")
        return {"sample": samples_mod.describe(samples_mod.SAMPLES[sample_id]), "applied": applied,
                "files": {k: v for k, v in files.items() if not k.endswith(".md")}, "diffs": diffs}

    @app.post("/v1/demo/scan", status_code=202)
    def demo_scan(body: DemoScanIn, request: Request, p: Principal = Depends(viewer)):
        """Queue a real scan of a bundled sample, optionally with fix-pack edits applied to a copy of it."""
        if not demo_allowed(p):
            raise ApiError(403, "forbidden", "Demo scans need the analyst role on this instance")
        sample = samples_mod.SAMPLES.get(body.sample)
        if not sample:
            raise ApiError(404, "not_found", "Unknown sample")
        try:
            samples_mod.variant_files(body.sample, body.fixes)  # validate ids and that every edit still applies
        except samples_mod.SampleError:
            raise ApiError(422, "invalid_input", "Unknown fix for this sample")
        if store.recent_job_count(p.org_id, "sample", time.time() - 60) >= 12:
            count("demo_rate_limited")
            raise ApiError(429, "rate_limited", "Too many demo scans; wait a minute")
        repo = store.get_or_create_repo(p.org_id, f"demo/{sample.id}")
        label = ("sample" if not body.fixes else f"sample + {len(set(body.fixes))} fix{'es' if len(set(body.fixes)) != 1 else ''}")
        run_id, job, _ = _enqueue(p, repo, "sample", {"sample": sample.id, "fixes": list(dict.fromkeys(body.fixes))}, label,
                                  request.state.cid)
        store.audit(p.email or p.id, "demo_scan_queued", "analysis_run", run_id, "ok", request.state.cid,
                    {"sample": sample.id, "fixes": len(body.fixes)}, p.org_id)
        return {"jobId": job["id"], "runId": run_id, "repositoryId": repo["id"], "label": label, "status": "queued",
                "statusUrl": f"/v1/repositories/{repo['id']}/analyses/{run_id}"}

    @app.get("/v1/analyses/{run_id}/explain")
    def explain_score(run_id: str, p: Principal = Depends(viewer)):
        """Why this score: the method, every finding's factors and its share of the total."""
        r = run_or_404(run_id, p)
        return analysis.explain_score(cfg, r, store.run_findings(run_id))

    @app.get("/v1/analyses/{run_id}/sarif")
    def sarif(run_id: str, p: Principal = Depends(viewer)):
        r = run_or_404(run_id, p)
        return JSONResponse(reporting.to_sarif(r, store.run_findings(run_id)), media_type="application/sarif+json")

    def _complete_runs(repo_id: str, limit: int = 30) -> list[dict]:
        return [r for r in store.runs(repo_id, limit)
                if r["status"] == "complete" and (r["score"] or {}).get("status") == "calculated"]

    def _compare(repo_id: str, base: str | None, head: str | None) -> dict:
        done = _complete_runs(repo_id)
        by_id = {r["id"]: r for r in store.runs(repo_id, 200)}
        h = by_id.get(head) if head else (done[0] if done else None)
        b = by_id.get(base) if base else (next((r for r in done if h and r["id"] != h["id"] and r["started_at"] <= h["started_at"]), None))
        if head and not h or base and not b:
            raise ApiError(404, "not_found", "Run not found in this repository")
        if not h or not b:
            raise ApiError(422, "invalid_input", "At least two analyses are needed to compare")
        return analysis.compare_runs(b, h, store.run_findings(b["id"]), store.run_findings(h["id"]))

    @app.get("/v1/repositories/{repo_id}/compare")
    def compare(repo_id: str, base: str | None = Query(None, pattern=r"^run_\w{1,40}$"),
                head: str | None = Query(None, pattern=r"^run_\w{1,40}$"), p: Principal = Depends(viewer)):
        """Before/after: defaults to the latest complete run against the previous complete one."""
        repo_or_404(repo_id, p)
        return _compare(repo_id, base, head)

    @app.get("/v1/repositories/{repo_id}/dashboard")
    def repo_dashboard(repo_id: str, p: Principal = Depends(viewer)):
        repo = repo_or_404(repo_id, p)
        runs = store.runs(repo_id, 60)
        done = [r for r in runs if r["status"] == "complete" and (r["score"] or {}).get("status") == "calculated"]
        rows = store.run_findings(done[0]["id"]) if done else []
        return analysis.repo_dashboard(repo, runs, store.all_findings(repo_id), rows, store.repo_activity(repo_id))

    @app.get("/v1/overview")
    def overview(p: Principal = Depends(viewer)):
        counts = store.open_counts(p.org_id)
        repos_ = [{"id": r["id"], "name": r["name"], "runs": r["runs"], "latest_run": store.latest_run(r["id"]),
                   "open_by_sev": __import__("collections").Counter(counts.get(r["id"], {}))} for r in store.repos(p.org_id)]
        return analysis.org_overview(repos_)

    @app.get("/v1/analyses/{run_id}/report")
    def report(run_id: str, format: str = Query("json", pattern="^(json|html)$"), p: Principal = Depends(viewer)):
        """Executive summary, metadata, findings with CWE/remediation, before/after and limitations, from real scan data."""
        r = run_or_404(run_id, p)
        repo = store.repo(r["repository_id"], p.org_id)
        rows = store.run_findings(run_id)
        try:
            cmp = _compare(r["repository_id"], None, run_id) if r["status"] == "complete" else None
        except ApiError:
            cmp = None  # first analysis: nothing to compare against
        rep = report_mod.build_report(repo=repo, run=r, rows=rows, explain=analysis.explain_score(cfg, r, rows), compare=cmp,
                                      cfg=cfg, service_version=app.version, generated_at=time.time())
        if format == "html":
            return HTMLResponse(report_mod.render_html(rep))
        return JSONResponse(rep)

    # ------------------------------------------------------------ optional AI assistant (advisory, consent-gated)
    def _assistant_package(body: AssistantIn, p: Principal) -> tuple[dict, dict]:
        repo = repo_or_404(body.repositoryId, p)
        done = _complete_runs(repo["id"], 30)
        run = store.run(body.runId) if body.runId else (done[0] if done else None)
        if not run or run["repository_id"] != repo["id"]:
            raise ApiError(404, "not_found", "No completed analysis for this repository")
        if body.mode in ("secure_alternative",) and not body.findingId:
            raise ApiError(422, "invalid_input", "This mode needs a finding")
        if body.mode == "review_fix" and not body.proposedFix:
            raise ApiError(422, "invalid_input", "Paste the proposed fix to review")
        comps = {c["fingerprint"]: c for c in ((run["score"] or {}).get("components") or []) if c["counted"]}
        rows = [r for r in store.run_findings(run["id"]) if r["fingerprint"] in comps]
        focus = None
        if body.findingId:
            focus = next((r for r in rows if r["id"] == body.findingId), None)
            if focus is None:
                raise ApiError(404, "not_found", "Finding is not part of this analysis")
        return assistant_mod.build_package(repo=repo, run=run, rows=rows, components=comps, focus=focus, mode=body.mode,
                                           question=body.question, include_snippets=body.includeSnippets,
                                           proposed_fix=body.proposedFix), repo

    @app.get("/v1/assistant/status")
    def assistant_status(p: Principal = Depends(viewer)):
        st = assistant_mod.status(ai)
        return {**st, "consentRequired": True, "defaultContext": "finding metadata only (no code)",
                "allowedRoles": ["analyst", "admin"] + (["viewer"] if os.environ.get("AVISHKAR_ASSISTANT_VIEWERS") == "1" else []),
                "canAsk": st["available"] and (p.has("analyst") or os.environ.get("AVISHKAR_ASSISTANT_VIEWERS") == "1")}

    @app.post("/v1/assistant/preview")
    def assistant_preview(body: AssistantIn, p: Principal = Depends(viewer)):
        """Exactly what would leave the server if the user consents. Nothing is sent by this call."""
        pkg, _ = _assistant_package(body, p)
        return {"payload": pkg, "bytes": len(json.dumps(pkg)), "sendsCodeLines": bool(body.includeSnippets or body.proposedFix),
                "provider": assistant_mod.status(ai)}

    @app.post("/v1/assistant/ask")
    def assistant_ask(body: AssistantIn, request: Request, p: Principal = Depends(viewer)):
        if not (p.has("analyst") or os.environ.get("AVISHKAR_ASSISTANT_VIEWERS") == "1"):
            raise ApiError(403, "forbidden", "The assistant needs the analyst role on this instance")
        if not body.consent:
            raise ApiError(403, "consent_required", "Consent is required before any scan data is sent to an AI provider")
        pkg, repo = _assistant_package(body, p)
        if not assistant_mod.status(ai)["available"]:
            return assistant_mod.ask(ai, pkg)  # honest unavailable state; nothing is sent
        if store.recent_audit_count(p.org_id, p.email or p.id, "assistant_ask", time.time() - 60) >= 10:
            raise ApiError(429, "rate_limited", "Too many assistant questions; wait a minute")
        res = assistant_mod.ask(ai, pkg)
        store.audit(p.email or p.id, "assistant_ask", "repository", repo["id"], res["status"], request.state.cid,
                    {"mode": body.mode, "findings": len(pkg["findings"]), "bytes": len(json.dumps(pkg)),
                     "codeLines": bool(body.includeSnippets), "userCode": bool(body.proposedFix)}, p.org_id)
        return res

    @app.get("/v1/rules")
    def rules(p: Principal = Depends(viewer)):
        return {"kbVersion": knowledge.KB_VERSION, "items": [knowledge.describe(rid) for rid in knowledge.rule_ids()]}

    @app.get("/v1/rules/{rule_id}")
    def rule(rule_id: str, p: Principal = Depends(viewer)):
        if rule_id not in knowledge.RULES:
            raise ApiError(404, "not_found", "Not found")
        return knowledge.describe(rule_id)

    def _comps(repo_id: str) -> dict:
        done = _complete_runs(repo_id, 5)
        return {c["fingerprint"]: c for c in ((done[0]["score"] or {}).get("components") or []) if c["counted"]} if done else {}

    def _enrich(f: dict, comps: dict) -> dict:
        k = knowledge.RULES.get(f["rule_id"])
        c = comps.get(f["fingerprint"])
        return {**f, "cwe": [f"CWE-{x}" for x in (k["cwe"] if k else [])],
                "assurance": k["detection"]["assurance"] if k else "heuristic",
                "detectionMethod": k["detection"]["method"] if k else "external",
                "debt": None if not c else {"impact": c["I"], "exposure": c["E"], "confidence": c["C"], "age": c["A"], "units": c["D"]}}

    @app.get("/v1/repositories/{repo_id}/findings")
    def findings(repo_id: str,
                 state: str | None = Query(None, pattern="^(open|fixed|accepted_risk|false_positive|duplicate|not_applicable)$"),
                 severity: str | None = Query(None, pattern="^(critical|high|medium|low|informational)$"),
                 confidence: str | None = Query(None, pattern="^(high|medium|low)$"),
                 category: str | None = Query(None, max_length=40, pattern=r"^[\w\-]+$"),
                 cwe: str | None = Query(None, pattern=r"^CWE-\d{1,5}$"),
                 q: str | None = Query(None, max_length=100), path: str | None = Query(None, max_length=200),
                 sort: str = Query("id", pattern="^(id|severity|confidence|path|rule|first_seen|last_seen)$"),
                 order: str = Query("asc", pattern="^(asc|desc)$"), offset: int = Query(0, ge=0, le=100000),
                 cursor: str | None = None, limit: int = Query(50, ge=1, le=200), p: Principal = Depends(viewer)):
        repo_or_404(repo_id, p)
        store.expire_exceptions(p.org_id)
        rule_ids = None
        if cwe:
            n = int(cwe[4:])
            rule_ids = [rid for rid, k in knowledge.RULES.items() if n in k["cwe"]] or ["__none__"]
        rows, nxt, next_off, total = store.findings(repo_id, state, severity, cursor, limit, q=q, category=category, path=path,
                                                    confidence=confidence, rule_ids=rule_ids, sort=sort, order=order,
                                                    offset=offset)
        comps = _comps(repo_id)
        return {"items": [_enrich(r, comps) for r in rows], "nextCursor": nxt, "nextOffset": next_off, "total": total}

    @app.get("/v1/findings/{fid}")
    def finding(fid: str, p: Principal = Depends(viewer)):
        f = store.finding(fid, p.org_id)
        if not f:
            raise ApiError(404, "not_found", "Not found")
        out = _enrich(f, _comps(f["repository_id"]))
        out["knowledge"] = knowledge.describe(f["rule_id"], f["category"])
        return out

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

    def _gh_client() -> gh.GitHubClient:
        if github is None:
            raise ApiError(503, "not_configured", "GitHub is not connected on this server (app credentials are missing)")
        return github

    def _own_installation(p: Principal, iid: str) -> None:
        inst = store.installation(iid)
        if not inst or inst["organization_id"] != p.org_id:
            raise ApiError(404, "not_found", "Not found")

    @app.get("/v1/github/repositories")
    def gh_repositories(installation: str = Query(pattern=r"^\d{1,20}$"), p: Principal = Depends(analyst)):
        """Repositories the linked GitHub App installation can read. Never fabricated: 503 when GitHub is not connected."""
        client = _gh_client()
        _own_installation(p, installation)
        try:
            return {"items": client.list_repositories(installation)}
        except gh.GitHubError as e:
            raise ApiError(502, "upstream_error", f"GitHub did not return the repository list: {e}")

    @app.get("/v1/github/branches")
    def gh_branches(installation: str = Query(pattern=r"^\d{1,20}$"), repo: str = Query(pattern=r"^[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}$"),
                    p: Principal = Depends(analyst)):
        client = _gh_client()
        if not gh.REPO_RE.match(repo):
            raise ApiError(422, "invalid_input", "Invalid repository name")
        _own_installation(p, installation)
        try:
            return {"items": client.list_branches(installation, repo)}
        except gh.GitHubError as e:
            raise ApiError(502, "upstream_error", f"GitHub did not return the branch list: {e}")

    @app.post("/v1/github/scan", status_code=202)
    def gh_scan(body: GitHubScanIn, request: Request, p: Principal = Depends(analyst)):
        """Scan the head commit of a branch. The commit SHA is resolved by GitHub, never taken from the client, so the
        scanned snapshot is exactly what the branch pointed to; the job then runs like a webhook-triggered scan."""
        client = _gh_client()
        _own_installation(p, body.installation)
        try:
            br = next((b for b in client.list_branches(body.installation, body.repo) if b["name"] == body.branch), None)
        except gh.GitHubError as e:
            raise ApiError(502, "upstream_error", f"GitHub did not return the branch list: {e}")
        if not br:
            raise ApiError(404, "not_found", "Branch not found")
        repo = store.get_or_create_repo(p.org_id, body.repo)
        store.set_ref_head(repo["id"], f"refs/heads/{body.branch}", br["sha"])
        run_id, job, created = _enqueue(p, repo, "github", {"installation": body.installation, "repo": body.repo, "sha": br["sha"],
                                                              "ref": f"refs/heads/{body.branch}", "pr": None},
                                        br["sha"], request.state.cid, f"gh:{body.repo}:{br['sha']}")
        store.audit(p.email or p.id, "github_scan_queued", "analysis_run", run_id, "ok", request.state.cid, org=p.org_id)
        return {"jobId": job["id"], "runId": run_id, "repositoryId": repo["id"], "commitSha": br["sha"], "status": "queued",
                "deduplicated": not created, "statusUrl": f"/v1/repositories/{repo['id']}/analyses/{run_id}"}

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
