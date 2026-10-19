# Avishkar v2 package (`avishkar/`)

Spec-driven scorer: deterministic detectors → versioned score → explicit policy. Lives beside the older
`backend/`/`frontend/` project and shares nothing with it (own DB at `data/avishkar_v2.db`).
The score is a prioritization signal from provisional, **uncalibrated** weights — not proof of safety.

```bash
pip install -r requirements.txt
python -m avishkar serve                 # API + dashboard + embedded worker; prints first-run admin login
python -m avishkar worker                # standalone worker (run API with AVISHKAR_EMBEDDED_WORKER=0)
python -m avishkar create-user --email a@b.co --role analyst
python -m avishkar scan ./dir [--fail-on warn|block]   # exit 0 ok / 2 policy / 3 incomplete scan
python -m pytest tests/unit tests/integration -q
```

## 1. Multi-user login, organizations, roles
Users belong to one organization; roles `viewer` < `analyst` < `admin`. Passwords: scrypt. Sessions: HS256 JWT
(8 h) that is re-checked against the user row on every request, so deactivation is immediate. CI uses
org-scoped API keys (`avk_…`, stored as SHA-256, shown once). Every repository/finding/run/job/audit query is
scoped by organization; another tenant's ids return the same 404 as missing ones. Login lockout after 5 failures.
Set `AVISHKAR_SECRET_KEY` (otherwise sessions die on restart) and `AVISHKAR_ADMIN_EMAIL/PASSWORD` for first run.

## 2. Durable job queue
`job` table (same DB): `POST /v1/analyses` returns **202** with a job + run id; workers claim with leases,
exponential-backoff retries (3 attempts), dead-letter quarantine (`status=dead`, visible at `/v1/jobs`, requeue
by admin), expired-lease reclaim for crashed workers, `Idempotency-Key` dedupe, per-org active-job quota
(`AVISHKAR_MAX_ACTIVE_JOBS`, default 20 → 429) and fair claiming across organizations. A quarantined job still
produces an explicit *incomplete* run. Multiple workers on PostgreSQL are safe (guarded `UPDATE … WHERE status='queued'`).

## 3. Scan isolation (`AVISHKAR_SANDBOX`)
Untrusted content is parsed only inside the sandbox; the trusted parent re-validates its JSON and does scoring.
* `docker` — `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit --memory --cpus`,
  non-root, source mounted read-only. Build `docker build -f infra/Dockerfile.worker -t avishkar-worker:latest .`
  (set `AVISHKAR_WORKER_IMAGE`, pin by digest). **The only mode that is a security boundary.**
* `process` (default) — separate `python -I` process, credential-free environment, timeout + process-tree kill,
  POSIX rlimits. Not a boundary; the dashboard and `serve` warn about it.
* `inline` — tests only, refused unless `AVISHKAR_ALLOW_INLINE=1`.
Crash, timeout, OOM, malformed output → *incomplete*, never clean. Archives: traversal/symlink/zip-bomb limits.

## 4. GitHub App + webhooks
Set `GITHUB_WEBHOOK_SECRET`, `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY` (or `_PATH`). App permissions: Contents:read,
Metadata:read, Pull requests:read, Checks:write; events: pull_request, push, installation(+_repositories).
Webhook URL `POST /v1/github/webhook`. An admin links the installation to the organization:
`POST /v1/github/installations {"installation_id","account"}` (an installation can belong to one org only).
Enforced: HMAC-SHA256 over the raw body before any parsing; delivery-id replay table; event allowlist; active,
linked installation required (unknown ones are ignored silently); repo/sha format checks; only normalized fields
are used; installation tokens minted from an RS256 App JWT, kept in memory; check runs per commit with stale-head
protection (an older commit's check is marked "Superseded"); a missing/failed analysis is `action_required`, never
`success`; revoked installations stop processing. Policy stays **report-only** (`config/policy.json`).
GitHub sends no timestamp header, so replay protection is by delivery id.

## 5. AI explanations (off by default)
`AVISHKAR_AI_ENABLED=1` + `ANTHROPIC_API_KEY` (model `AVISHKAR_AI_MODEL`). `POST /v1/findings/{id}/explanation`
(analyst). The model receives only {rule id, title, category, path, line, one redacted evidence line}; output must
validate against a strict schema (no severity/state/score fields allowed; must cite the finding's own rule id) or
it is discarded as `unavailable`. Stored beside the finding; cannot change severity, state, score or gate.
Provider outage never affects scan completeness. Kill switch: unset the flag.

## 6. PostgreSQL
`DATABASE_URL=postgresql://user:pw@host/db` + `pip install "psycopg[binary]"`. One SQL source with placeholder/DDL
translation (`adapters/db.py`).

## Not verified here / limitations (be honest before relying on it)
* **Docker sandbox and PostgreSQL were not executed** in this environment (no Docker/Postgres installed). They are
  covered by static tests only (hardened command line, DDL translation). Run the suite and one real scan against
  both before production.
* The GitHub client was tested against a mocked GitHub API, not live GitHub.
* The Anthropic provider was tested via a fake provider; no live API call was made.
* Login throttle and the quota counters are per-process memory. Behind several API replicas, move them to the DB.
* Detectors are regex heuristics + a tiny advisory sample; score weights/K are uncalibrated (spec App. P).
* No MFA/SSO, no SARIF export, no OpenTelemetry, no TLS termination (put it behind a proxy).
