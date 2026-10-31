# Second Read: AI-Generated Code Security Debt Scorer

> Avishkar Industrial-Ready Hackathon project. A working prototype, honest about its limits.

Second Read scans a code snapshot with **deterministic detectors**, turns the evidence into a **0-100 security-debt index**, and shows the exact file and line, CWE, impact, fix and a secure example for every finding. You can fix the code, rescan, and see what moved and why.

**The index is a prioritization signal from provisional, uncalibrated weights. It is not a probability of compromise, a compliance grade, or proof that code is safe. Zero findings is not a pass.**

Live demo: <https://avishkar-red.vercel.app> (static site on Vercel, API on Render's free tier: the first load can take about a minute while it wakes up). Use **Continue as guest** and open the **Demo lab**.

## What it does

| Area | Details |
|---|---|
| Detection | Python AST (alias resolution, same-function flows), JavaScript/TypeScript, Java, Kotlin, Go, C# and PHP token-stream scanners, secrets, dependencies, CORS. 84 documented rules. Unsupported languages (e.g. Rust) are reported as *not evaluated*, never as clean. |
| Scoring | Versioned `score-v1`: `D = I x E x C x A`, `Index = 100(1 - e^(-D/K))`. Every finding's contribution is shown and the total is recomputed for a reproducibility check. Incomplete scans give "not calculated", never zero. |
| Console | Overview, per-repository dashboard (gauge, severity, trend, vulnerable files, activity), before/after comparison, vulnerability explorer (search, filters, sorting, details), admin area. |
| Demo lab | Pick a bundled sample, run a **real** scan, watch the recorded pipeline stages, apply the fix pack, rescan, compare. |
| Reports | PDF, JSON, printable HTML, SARIF 2.1.0 with CWE tags. |
| AI assistant | Optional, off by default, consent-gated, payload preview, secrets redacted, cannot change findings or scores. |
| GitHub | Webhooks, check runs, PR comments, repository/branch browsing, manual branch scans, and scheduled rescans of a branch with an email summary when something changed (tested against mocks). |
| Dependencies | Manifests and lockfiles for PyPI, npm, Maven/Gradle, Go, NuGet, Packagist and RubyGems. With `AVISHKAR_VULN_FEED=osv`, exact versions are checked against live OSV.dev advisories; a failed lookup makes the dependency check incomplete, never clean. Without it only a small built-in list is used. |
| Access | Roles (viewer/analyst/admin), API keys, read-only guest, email sign-up with verification and password reset (needs Resend settings), private organization per self-registered account, capped uploads. |
| Operations | Durable job queue, audit log, login throttle, security headers + CSP, Docker sandbox for real isolation, PostgreSQL support, CI (tests, Postgres, Docker sandbox, API image, lint + types). |

## Run it

```bash
python -m pip install -r requirements.txt
python -m avishkar serve --port 8011 --db data/local.db     # prints a first-run admin login
python -m avishkar scan sample_projects/vulnerable-python   # CLI scan
python -m pytest -q                                         # test suite
```

More: [RUN_LOCALLY.md](RUN_LOCALLY.md) (step by step), [docs/AVISHKAR_V2.md](docs/AVISHKAR_V2.md) (architecture, security model, configuration),
[docs/DEPLOY_ONLINE.md](docs/DEPLOY_ONLINE.md) (Vercel + Render), [docs/CALIBRATION.md](docs/CALIBRATION.md) (what the score evidence does and does not show),
[docs/Avishkar_Features_and_Roadmap.docx](docs/Avishkar_Features_and_Roadmap.docx) (features, pending work, roadmap) and the [demo video](docs/demo/Avishkar_Demo.webm) (1:43, recorded on the live site).

## Honest limitations

* **Detectors miss things.** Held-out recall on our own labelled cases was about 0.8; precision about 0.8 on the same cohort. Detection is heuristic (no full JS or Java parser, no cross-file data flow). The Java, Kotlin, Go, C# and PHP rules each have at most one labelled case written by us (no real-world code in those languages was tested), so their accuracy is largely unmeasured.
* **Not calibrated.** The corpus is 81 small cases written by us with no independent second reviewer. Do not use the index to block releases.
* **Public uploads are small and capped.** On Render the `process` sandbox is not an isolation boundary; the scanner only parses uploaded code and never executes it. Use `AVISHKAR_UPLOADS=admin` to turn public uploads off, or the Docker sandbox for real isolation.
* **Tested against mocks, not live services:** GitHub, the AI provider and email (Resend).

## Repository layout

```
avishkar/        FastAPI app, workers (sandboxed detectors), scoring, reporting, knowledge base
web/             landing page + console (vanilla ES modules, no build step)
config/          score and policy configuration (score-v1), candidate (not approved)
sample_projects/ bundled demo samples (vulnerable and secure)
tests/           unit, integration and the labelled calibration corpus
infra/           Dockerfiles (API, scan worker), Semgrep rule pack
scripts/         static build for Vercel, demo-results and corpus generators
backend/ frontend/   the earlier prototype (kept for history; see docs/MERGE_PLAN.md)
```

## License

MIT. Third-party components: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
