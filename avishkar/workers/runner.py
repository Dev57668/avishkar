"""Job runner: claims durable jobs, runs the sandboxed scan, persists results, publishes GitHub checks."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path

from ..adapters import github as gh
from ..adapters.store import Store
from ..domain.policy import Policy
from ..domain.scoring import ScoreConfig
from . import pipeline
from .sandbox import Sandbox

SPOOL_DIR = Path(os.environ.get("AVISHKAR_SPOOL", "data/spool"))


class JobRunner:
    def __init__(self, store: Store, cfg: ScoreConfig, pol: Policy, sandbox: Sandbox,
                 github: gh.GitHubClient | None = None, lease_seconds: int = 300, retry_delay: float = 5.0):
        self.store, self.cfg, self.pol, self.sandbox, self.github = store, cfg, pol, sandbox, github
        self.lease, self.retry_delay = lease_seconds, retry_delay
        self.worker_id = "wrk_" + uuid.uuid4().hex[:8]

    # ------------------------------------------------------------ public
    def run_once(self) -> bool:
        """Process at most one job. Returns False when the queue is empty."""
        job = self.store.claim(self.worker_id, self.lease)
        if not job:
            return False
        try:
            payload = json.loads(job["payload"])
            if job["kind"] == "archive":
                self._archive(job, payload)
            elif job["kind"] == "github":
                self._github(job, payload)
            else:
                raise ValueError(f"unknown job kind {job['kind']}")
            self.store.complete_job(job["id"])
        except Exception as e:  # infrastructure failure (not a scan verdict): retry, then quarantine
            self.store.fail_job(job["id"], f"{type(e).__name__}: {e}", self.retry_delay)
            after = self.store.job(job["id"])
            if after["status"] == "dead":
                self._finalize_dead(job, str(e))
        return True

    def drain(self, max_jobs: int = 1000) -> int:
        n = 0
        while n < max_jobs and self.run_once():
            n += 1
        return n

    # ------------------------------------------------------------ job kinds
    def _finish(self, job, collected):
        self.store.set_run_status(job["run_id"], "running")
        base = self.store.baseline(job["repository_id"])
        res = pipeline.assemble(self.cfg, self.pol, collected, base)
        self.store.save_run(job["repository_id"], job["run_id"], res)
        self.store.audit("worker", "analysis_finished", "analysis_run", job["run_id"], res["status"],
                         org=job["organization_id"])
        return res

    def _archive(self, job, payload):
        zp = Path(payload["spool_path"])
        collected = self.sandbox.collect(self.cfg.required_detectors, zip_path=zp)
        self._finish(job, collected)
        zp.unlink(missing_ok=True)  # kept across retries; removed on success or when dead-lettered

    def _github(self, job, p):
        if not self.github:
            raise gh.GitHubError("GitHub App is not configured")
        inst, repo, sha, ref = p["installation"], p["repo"], p["sha"], p["ref"]
        if not self.store.installation(inst):
            raise gh.GitHubError("installation no longer active")
        check_id = self.github.create_check_run(inst, repo, sha)
        data = self.github.download_zipball(inst, repo, sha)
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        zp = SPOOL_DIR / f"{job['id']}.zip"
        zp.write_bytes(data)
        try:
            collected = self.sandbox.collect(self.cfg.required_detectors, zip_path=zp)
        finally:
            zp.unlink(missing_ok=True)
        res = self._finish(job, collected)
        head = self.store.ref_head(job["repository_id"], ref)
        if head and head != sha:  # a newer commit arrived: this result must not masquerade as current
            self.github.complete_check_run(inst, repo, check_id, "neutral", "Superseded by a newer commit.")
            return
        concl, summary = gh.conclusion_for(res, self.pol.mode)
        sd = res["securityDebt"]
        text = (f"Raw debt units: {sd['rawUnits']}\nIndex: {sd['normalizedIndex']} ({sd['scoreVersion']}, uncalibrated)\n"
                f"Policy {self.pol.version} ({self.pol.mode}). The index is a prioritization signal, not proof of safety.\n")
        text += "\n".join(f"- [{f.raw.severity.value}] {f.raw.path}:{f.raw.line} {f.raw.title}"
                          for f in sorted(res["findings"], key=lambda f: -f.raw.severity.rank)[:50])
        self.github.complete_check_run(inst, repo, check_id, concl, summary, text)

    def _finalize_dead(self, job, error):
        """A quarantined job still yields an explicit incomplete run so nothing looks clean or pending."""
        collected = pipeline.failed_collection(self.cfg.required_detectors, "job failed: " + error[:150], "job")
        try:
            res = pipeline.assemble(self.cfg, self.pol, collected, {})
            self.store.save_run(job["repository_id"], job["run_id"], res)
            p = json.loads(job["payload"])
            if job["kind"] == "github" and self.github:
                try:
                    cid = self.github.create_check_run(p["installation"], p["repo"], p["sha"])
                    self.github.complete_check_run(p["installation"], p["repo"], cid, "action_required",
                                                   "Analysis could not run — this is NOT a pass.")
                except Exception:
                    pass
            if "spool_path" in p:
                Path(p["spool_path"]).unlink(missing_ok=True)
        except Exception:
            pass


class WorkerThread:
    def __init__(self, runner: JobRunner, interval: float = 1.0):
        self.runner, self.interval = runner, interval
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True, name="avishkar-worker")

    def _loop(self):
        while not self._stop.is_set():
            try:
                busy = self.runner.run_once()
            except Exception:
                busy = False
            if not busy:
                self._stop.wait(self.interval)

    def start(self):
        self._t.start()

    def stop(self):
        self._stop.set()
        self._t.join(timeout=5)
