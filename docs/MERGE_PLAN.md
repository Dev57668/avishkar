# `backend/` vs `avishkar/`: comparison and plan

Both implement the same spec. Nothing in `backend/` was changed or deleted.

| Area | `backend/` (original) | `avishkar/` (v2 package) |
|---|---|---|
| Layout | flat imports (`from scanners.base import …`), run from `backend/` | proper package, domain/adapters/workers/api split |
| Score | `score-v1`, **K = 25**, integer score + `risk_band` column | `score-v1`, **K = 20**, no bands (spec App. P.5 says do not define bands until the pilot supports them) |
| Incomplete scans | `CompletenessState` model; verify end-to-end behavior | enforced: required detector fails ⇒ `not_calculated`/`not_evaluated`, tested |
| Scanners | Semgrep (`--config=auto`, needs network), Gitleaks, custom Python AST rules | built-in regex + **AST** (folded in from `backend/`'s idea), Semgrep/Gitleaks adapters with a pinned offline rule pack, sandboxed |
| Isolation | local workspace helper | sandbox child process / Docker (`--network none`, read-only, non-root) |
| Auth / tenancy | none seen | orgs, roles, hashed API keys, tenant-scoped queries |
| Queue / workers | request-time scan | durable queue, leases, retries, dead-letter, quotas |
| GitHub | `api/github.py` (18 lines), PyGithub | signed webhooks, replay protection, check runs, stale-commit guard |
| DB | SQLite (`schema.sql`, int scores, float confidence, 1–5 integer exposure) | SQLite/PostgreSQL, canonical fingerprints, dispositions, audit log |
| Frontend | `frontend/` has empty `components/`, `pages/api/` | dashboard in `web/` (single page, admin screens) |

## Two things that will bite you if both stay alive
1. **Same version name, different numbers.** Both call themselves `score-v1` but K differs (25 vs 20) and `backend/`
   buckets into risk bands. Scores are not comparable; per spec §8 a K change is a new version.
2. **Two databases and two finding schemas** drift apart (`backend/` stores `exploitability`/`exposure` as integers,
   `avishkar/` stores categorical exposure and ledger states).

## Recommendation
Treat `avishkar/` as the product and retire `backend/` after porting what is still unique:
1. Port `backend/scanners/custom_scanner.py` rules that `workers/pyast.py` does not cover (compare
   `rules/security_rules.json` against the rule table) — as new rule ids with tests, not as a second scanner stack.
2. Decide K once, in `config/score-v1.json`, with the calibration report (`python -m avishkar calibrate tests/corpus`)
   and a new version id if it changes. Drop `risk_band` until the pilot justifies bands.
3. Move any data you care about with a one-off script (projects → repositories, scans → analysis runs); old
   integer scores must be marked non-equivalent, not converted.
4. Delete `backend/` and `frontend/` only after steps 1–3, in its own commit, so it is easy to revert.

Not done here on purpose: porting rules or deleting the original project is your call; I did not want to remove
work you may still be demoing.
