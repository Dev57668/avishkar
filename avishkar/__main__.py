"""CLI: `python -m avishkar serve` or `python -m avishkar scan <dir> [--fail-on warn|block]`."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="avishkar")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--db", default=None, help="SQLite path or postgresql:// URL (or env DATABASE_URL)")
    w = sub.add_parser("worker", help="run a standalone job worker (set AVISHKAR_EMBEDDED_WORKER=0 on the API)")
    w.add_argument("--db", default=None)
    u = sub.add_parser("create-user")
    u.add_argument("--org", default="default")
    u.add_argument("--email", required=True)
    u.add_argument("--role", choices=["viewer", "analyst", "admin"], default="admin")
    u.add_argument("--db", default=None)
    c = sub.add_parser("scan")
    c.add_argument("path")
    c.add_argument("--json", action="store_true")
    c.add_argument("--fail-on", choices=["warn", "block"], default=None)
    a = ap.parse_args(argv)

    if a.cmd == "serve":
        import uvicorn
        from .api.app import bootstrap_admin, create_app
        app = create_app(a.db)
        boot = bootstrap_admin(app.state.store)
        print(f"Avishkar dashboard: http://{a.host}:{a.port}/")
        if boot:
            print(f"First-run admin created: {boot['email']} / "
                  f"{boot['password'] or '(password from AVISHKAR_ADMIN_PASSWORD)'}")
        if not os.environ.get("AVISHKAR_SECRET_KEY"):
            print("WARNING: AVISHKAR_SECRET_KEY not set; sessions are invalidated on restart.")
        if os.environ.get("AVISHKAR_SANDBOX", "process") != "docker":
            print("WARNING: sandbox is not 'docker'; do not scan untrusted repositories (see docs/SANDBOX.md).")
        uvicorn.run(app, host=a.host, port=a.port)
        return 0

    if a.cmd == "worker":
        from .adapters.github import GitHubClient
        from .adapters.store import Store
        from .domain.policy import Policy
        from .domain.scoring import ScoreConfig
        from .workers.runner import JobRunner
        from .workers.sandbox import Sandbox
        import time
        r = JobRunner(Store(a.db or os.environ.get("DATABASE_URL", "data/avishkar_v2.db")), ScoreConfig.load(),
                      Policy.load(), Sandbox(), GitHubClient.from_env())
        print(f"worker {r.worker_id} started (sandbox={r.sandbox.mode})")
        while True:
            if not r.run_once():
                time.sleep(1)

    if a.cmd == "create-user":
        import getpass
        from .adapters.store import Store
        from .api.security import hash_password
        st = Store(a.db or os.environ.get("DATABASE_URL", "data/avishkar_v2.db"))
        org = st.create_org(a.org)
        pw = os.environ.get("AVISHKAR_NEW_PASSWORD") or getpass.getpass("Password (min 10 chars): ")
        print(st.create_user(org["id"], a.email, hash_password(pw), a.role))
        return 0

    from .domain.policy import Policy
    from .domain.scoring import ScoreConfig
    from .workers.pipeline import run_scan
    from .workers.sandbox import Sandbox
    res = run_scan(Path(a.path), ScoreConfig.load(), Policy.load(), sandbox=Sandbox())
    sd, dec = res["securityDebt"], res["decision"]
    if a.json:
        out = {k: v for k, v in res.items() if k not in ("findings", "supportMatrix")}
        out["findings"] = [{"fingerprint": f.fingerprint, "rule": f.raw.rule_id, "severity": f.raw.severity.value,
                            "confidence": f.raw.confidence.value, "path": f.raw.path, "line": f.raw.line,
                            "title": f.raw.title, "evidence": f.raw.evidence} for f in res["findings"]]
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"status={res['status']} files={res['filesScanned']} decision={dec['outcome']}")
        if sd["status"] == "calculated":
            print(f"raw debt={sd['rawUnits']}  index={sd['normalizedIndex']} ({sd['scoreVersion']}, uncalibrated)")
        else:
            print(f"score NOT CALCULATED; missing={sd['missing']} failures={res['completeness']['failures']}")
        for f in sorted(res["findings"], key=lambda f: -f.raw.severity.rank):
            r = f.raw
            print(f"  [{r.severity.value:>8}/{r.confidence.value:<6}] {r.path}:{r.line}  {r.rule_id}  {r.title}")
    if res["status"] != "complete":
        return 3  # missing analysis is never a pass
    if a.fail_on == "block" and dec["outcome"] in ("block", "would_block"):
        return 2
    if a.fail_on == "warn" and dec["outcome"] != "pass":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
