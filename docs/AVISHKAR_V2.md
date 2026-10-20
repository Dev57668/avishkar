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

## 7. Real scanners (Semgrep, Gitleaks)
`config/profiles/full.json` (`AVISHKAR_SCORE_CONFIG=config/profiles/full.json`, version `score-v1-full`) additionally
*requires* Semgrep and Gitleaks. They run inside the sandbox with a pinned local rule pack
(`infra/semgrep-rules.yml`, never `--config auto`), Gitleaks with `--redact`. Missing binary, crash, timeout or bad output
=> the run is incomplete. A secret flagged by two detectors on one line counts once. `infra/Dockerfile.worker` installs
both (pin the base digest and Gitleaks checksum placeholders before use). Python rules now use an AST detector
(`workers/pyast.py`) that resolves aliases and ignores comments/strings; JS/TS still use regex rules.

## 8. Shared state for multiple API replicas
Login lockout and counters are in the database (`login_failure`, `metric_counter`); job quotas and the queue already were.
Multi-statement writes use `Database.transaction()`; `SELECT`s end their transaction on PostgreSQL.

## 9. Interop and operations
* SARIF 2.1.0: `GET /v1/analyses/{id}/sarif`, `python -m avishkar scan DIR --sarif out.sarif`. Debt fields live under
  `runs[0].properties.avishkar`; an incomplete run has `executionSuccessful=false`.
* PR summary comment (opt-in `AVISHKAR_PR_COMMENTS=1`, needs the extra *Pull requests: write* permission): one comment
  per PR, edited in place via a hidden marker; never contains source or secrets.
* Telemetry: JSON logs + optional OpenTelemetry (`AVISHKAR_OTEL=1`, `OTEL_EXPORTER_OTLP_ENDPOINT`). Attribute allowlist:
  no source, paths, secrets or prompts.
* Calibration: `python -m avishkar calibrate tests/corpus` -> precision/recall per rule, one-factor-at-a-time monotonicity,
  replay/gaming checks, candidate-K table, and the list of blockers. It never marks the score calibrated; the shipped
  corpus is 6 synthetic, **un-adjudicated** cases.
* Dashboard: admin tabs for users, API keys, GitHub installations, jobs (requeue dead), audit and counters; SARIF export.
* CI (`.github/workflows/ci.yml`): unit+integration, self-scan, calibration report, the whole integration suite on
  PostgreSQL, and a Docker job that runs the real sandbox/Semgrep/Gitleaks tests. `live-smoke.yml` (manual) checks the
  real Claude API and a real GitHub App. See `docs/MERGE_PLAN.md` for how this package relates to `backend/`.

## Not verified here / limitations (be honest before relying on it)
* **Verified in CI on Linux (GitHub Actions, all three jobs green):** the full integration suite
  on PostgreSQL 16; and in a real container (`--network none`, read-only, non-root, no capabilities, no host secrets,
  OOM => incomplete) the Docker sandbox running Semgrep + Gitleaks under the `full` profile. Those runs found and fixed
  three real bugs (`python -I` ignoring PYTHONPATH in the image, unwritable result dir for uid 65534, a `preexec_fn`
  deadlock). Not verified locally on this Windows machine (no Docker/Postgres; Semgrep's engine does not run here).
  The Dockerfile base image is not yet pinned by digest (TODO in the file).
* The GitHub client was tested against a mocked GitHub API, not live GitHub.
* The Anthropic provider was tested via a fake provider; no live API call was made.
* Detectors are regex heuristics + a tiny advisory sample; score weights/K are uncalibrated (spec App. P).
* No MFA/SSO and no TLS termination (put it behind a proxy). OpenTelemetry export was tested with an in-memory exporter only.
