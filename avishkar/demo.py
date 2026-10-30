"""Public demo mode: read-only visitors, pre-scanned bundled samples, no untrusted uploads.

Why: the scanner cannot run an isolation boundary on a PaaS (no Docker daemon), so a public instance must never parse
code that strangers upload. Instead it serves results of the *bundled* sample projects, computed by the real pipeline
from files in this repository, and lets only the owner (admin) upload.

Environment:
  AVISHKAR_DEMO_MODE=1               enable demo seeding (used by `serve`)
  AVISHKAR_UPLOADS=all|admin|off     who may POST /v1/analyses (default: all; demo deployments use admin)
  AVISHKAR_PUBLISH_DEMO_LOGIN=1      expose the demo viewer's login via GET /v1/public/status (viewer role only)
  AVISHKAR_DEMO_EMAIL / AVISHKAR_DEMO_PASSWORD   the read-only demo account (password >= 10 chars)
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .api.security import hash_password
from .domain.policy import Policy
from .domain.scoring import ScoreConfig
from .workers import pipeline

SAMPLES = Path(__file__).resolve().parents[1] / "sample_projects"
UPLOAD_MODES = ("all", "admin", "off")


@dataclass(frozen=True)
class DemoSettings:
    enabled: bool = False
    uploads: str = "all"
    publish_login: bool = False
    email: str = "demo@avishkar.dev"
    password: str = ""

    @classmethod
    def from_env(cls) -> "DemoSettings":
        uploads = os.environ.get("AVISHKAR_UPLOADS", "all").lower()
        if uploads not in UPLOAD_MODES:
            raise ValueError(f"AVISHKAR_UPLOADS must be one of {UPLOAD_MODES}")
        return cls(enabled=os.environ.get("AVISHKAR_DEMO_MODE") == "1", uploads=uploads,
                   publish_login=os.environ.get("AVISHKAR_PUBLISH_DEMO_LOGIN") == "1",
                   email=os.environ.get("AVISHKAR_DEMO_EMAIL", "demo@avishkar.dev").lower(),
                   password=os.environ.get("AVISHKAR_DEMO_PASSWORD", ""))

    def public_status(self, sandbox_info: dict, score_version: str) -> dict:
        login = None
        if self.enabled and self.publish_login and self.password:
            login = {"email": self.email, "password": self.password, "role": "viewer"}
        return {"service": "avishkar", "demo": self.enabled, "uploads": self.uploads, "demoLogin": login,
                "scoreVersion": score_version, "calibrated": False,
                "sandbox": {"mode": sandbox_info["mode"], "isolationBoundary": sandbox_info["isolationBoundary"]}}


def _scan_into(store, cfg: ScoreConfig, pol: Policy, sandbox, repo: dict, src: Path, sha: str):
    run_id = store.create_run(repo["id"], sha, "demo-seed")
    collected = sandbox.collect(cfg.required_detectors, source_dir=src)
    res = pipeline.assemble(cfg, pol, collected, store.baseline(repo["id"]))
    store.save_run(repo["id"], run_id, res)
    return res


def seed_demo(store, cfg: ScoreConfig, pol: Policy, sandbox, settings: DemoSettings, samples: Path = SAMPLES) -> dict:
    """Idempotent. Creates the read-only viewer in the first organization and scans the bundled samples."""
    org = store.d.query("SELECT id FROM organization ORDER BY created_at LIMIT 1")
    if not org:
        raise RuntimeError("create the admin/organization before seeding the demo")
    org_id = org[0]["id"]
    out = {"viewer": False, "repos": []}
    if settings.password and not store.user_by_email(settings.email):
        store.create_user(org_id, settings.email, hash_password(settings.password), "viewer")
        out["viewer"] = True

    py = samples / "vulnerable-python"
    if py.is_dir() and not store.d.query("SELECT 1 AS x FROM repository WHERE organization_id=? AND name=?",
                                         (org_id, "demo/vulnerable-python")):
        repo = store.get_or_create_repo(org_id, "demo/vulnerable-python")
        _scan_into(store, cfg, pol, sandbox, repo, py, "sample-before")
        time.sleep(0.01)
        tmp = Path(tempfile.mkdtemp(prefix="avishkar-demo-"))
        try:  # the one-line fix described on the landing page, applied to a copy
            shutil.copytree(py, tmp / "app", ignore=shutil.ignore_patterns("README.md"))
            f = tmp / "app" / "app.py"
            text = f.read_text(encoding="utf8")
            fixed = text.replace('result = os.system(f"ping {host}")',
                                 'result = subprocess.run(["ping", "-c", "1", host]).returncode')
            if fixed != text:
                f.write_text(fixed.replace("import os\n", "import os\nimport subprocess\n", 1), encoding="utf8")
            _scan_into(store, cfg, pol, sandbox, repo, tmp / "app", "sample-after")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        out["repos"].append(repo["name"])

    for name, folder in (("demo/vulnerable-javascript", "vulnerable-javascript"), ("demo/vulnerable-java", "vulnerable-java")):
        src = samples / folder
        if src.is_dir() and not store.d.query("SELECT 1 AS x FROM repository WHERE organization_id=? AND name=?",
                                              (org_id, name)):
            repo = store.get_or_create_repo(org_id, name)
            _scan_into(store, cfg, pol, sandbox, repo, src, "sample")
            out["repos"].append(name)
    return out
