"""Public demo mode: read-only visitors, pre-scanned bundled samples, no untrusted uploads.

Why: the scanner cannot run an isolation boundary on a PaaS (no Docker daemon), so a public instance must never parse
code that strangers upload. Instead it serves results of the *bundled* sample projects, computed by the real pipeline
from files in this repository, and lets only the owner (admin) upload.

Environment:
  AVISHKAR_DEMO_MODE=1               enable demo seeding (used by `serve`)
  AVISHKAR_UPLOADS=all|admin|limited|off   who may POST /v1/analyses (default: all; "limited" = size/file/rate caps for non-admins)
  AVISHKAR_PUBLISH_DEMO_LOGIN=1      expose the demo viewer's login via GET /v1/public/status (viewer role only)
  AVISHKAR_DEMO_EMAIL / AVISHKAR_DEMO_PASSWORD   the read-only demo account (password >= 10 chars)
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import Any
from pathlib import Path

from .api.security import hash_password
from .domain.policy import Policy
from .domain.scoring import ScoreConfig
from . import samples
from .workers import pipeline

UPLOAD_MODES = ("all", "admin", "limited", "off")  # limited: admins unrestricted, other analysts get small capped uploads


@dataclass(frozen=True)
class DemoSettings:
    enabled: bool = False
    uploads: str = "all"
    publish_login: bool = False
    signup: bool = False
    email: str = "demo@avishkar.dev"
    password: str = ""

    @classmethod
    def from_env(cls) -> "DemoSettings":
        uploads = os.environ.get("AVISHKAR_UPLOADS", "all").lower()
        if uploads not in UPLOAD_MODES:
            raise ValueError(f"AVISHKAR_UPLOADS must be one of {UPLOAD_MODES}")
        return cls(enabled=os.environ.get("AVISHKAR_DEMO_MODE") == "1", uploads=uploads,
                   publish_login=os.environ.get("AVISHKAR_PUBLISH_DEMO_LOGIN") == "1",
                   signup=os.environ.get("AVISHKAR_SIGNUP") == "1",
                   email=os.environ.get("AVISHKAR_DEMO_EMAIL", "demo@avishkar.dev").lower(),
                   password=os.environ.get("AVISHKAR_DEMO_PASSWORD", ""))

    def public_status(self, sandbox_info: dict, score_version: str) -> dict:
        login = None
        if self.enabled and self.publish_login and self.password:
            login = {"email": self.email, "password": self.password, "role": "viewer"}
        return {"service": "avishkar", "demo": self.enabled, "uploads": self.uploads, "demoLogin": login,
                "signup": self.enabled and self.signup, "guest": self.enabled and bool(self.password),
                "scoreVersion": score_version, "calibrated": False,
                "sandbox": {"mode": sandbox_info["mode"], "isolationBoundary": sandbox_info["isolationBoundary"]}}


def variant_label(fixes) -> str:
    n = len(list(fixes))
    return "sample" if not n else f"sample + {n} fix{'es' if n != 1 else ''}"


def _scan_variant(store, cfg: ScoreConfig, pol: Policy, sandbox, repo: dict, sample_id: str, fixes) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="avishkar-demo-"))
    try:
        samples.write_variant(sample_id, fixes, tmp)
        run_id = store.create_run(repo["id"], variant_label(fixes), "demo-seed")
        collected = sandbox.collect(cfg.required_detectors, source_dir=tmp)
        res = pipeline.assemble(cfg, pol, collected, store.baseline(repo["id"]))
        store.save_run(repo["id"], run_id, res)
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def seed_demo(store, cfg: ScoreConfig, pol: Policy, sandbox, settings: DemoSettings, samples_dir: Path | None = None) -> dict:
    """Idempotent. Creates the read-only viewer in the first organization and scans the bundled samples with the real
    pipeline: each vulnerable sample is scanned as shipped and again with every fix applied (a real before/after)."""
    org = store.d.query("SELECT id FROM organization ORDER BY created_at LIMIT 1")
    if not org:
        raise RuntimeError("create the admin/organization before seeding the demo")
    org_id = org[0]["id"]
    out: dict[str, Any] = {"viewer": False, "repos": []}
    if settings.password and not store.user_by_email(settings.email):
        store.create_user(org_id, settings.email, hash_password(settings.password), "viewer")
        out["viewer"] = True
    for sample in samples.SAMPLES.values():
        name = f"demo/{sample.id}"
        if store.d.query("SELECT 1 AS x FROM repository WHERE organization_id=? AND name=?", (org_id, name)):
            continue
        if not (samples.SAMPLES_DIR / sample.folder).is_dir():
            continue
        repo = store.get_or_create_repo(org_id, name)
        _scan_variant(store, cfg, pol, sandbox, repo, sample.id, [])
        if sample.fixes:
            time.sleep(0.01)
            _scan_variant(store, cfg, pol, sandbox, repo, sample.id, [f.id for f in sample.fixes])
        out["repos"].append(name)
    return out


def _summary(res: dict, fixes: int) -> dict:
    sd = res["securityDebt"]
    sev = {s: 0 for s in ("critical", "high", "medium", "low", "informational")}
    for f in res["findings"]:
        sev[f.raw.severity.value] += 1
    return {"status": res["status"], "decision": res["decision"]["outcome"], "fixesApplied": fixes,
            "normalizedIndex": sd["normalizedIndex"], "grossUnits": sd["grossUnits"], "rawUnits": sd["rawUnits"],
            "findings": len(res["findings"]), "severity": sev, "filesScanned": res["filesScanned"],
            "coverage": sd.get("coverage"),
            "items": [{"rule": f.raw.rule_id, "title": f.raw.title, "severity": f.raw.severity.value,
                       "confidence": f.raw.confidence.value, "path": f.raw.path, "line": f.raw.line}
                      for f in sorted(res["findings"], key=lambda f: (f.raw.path, f.raw.line, f.raw.rule_id))]}


def demo_results(cfg: ScoreConfig | None = None, pol: Policy | None = None) -> dict:
    """Real scan results of every bundled sample as shipped and with all fixes applied. Used to publish
    web/demo_results.json (the landing page's numbers) and by a test that fails when the file goes stale."""
    cfg, pol = cfg or ScoreConfig.load(), pol or Policy.load()
    out: dict[str, Any] = {"scoreVersion": cfg.version, "k": cfg.k, "calibrated": False, "samples": {}}
    for sample in samples.SAMPLES.values():
        if not (samples.SAMPLES_DIR / sample.folder).is_dir():
            continue
        entry = {"name": sample.name, "kind": sample.kind, "language": sample.language, "fixCount": len(sample.fixes)}
        for label, fixes in (("before", []), ("after", [f.id for f in sample.fixes])):
            if label == "after" and not fixes:
                continue
            tmp = Path(tempfile.mkdtemp(prefix="avishkar-results-"))
            try:
                samples.write_variant(sample.id, fixes, tmp)
                entry[label] = _summary(pipeline.run_scan(tmp, cfg, pol), len(fixes))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        out["samples"][sample.id] = entry
    return out
