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
from .. import telemetry
from ..domain import reporting
from . import pipeline
from .sandbox import Sandbox

SPOOL_DIR = Path(os.environ.get("AVISHKAR_SPOOL", "data/spool"))


class JobRunner:
    def __init__(self, store: Store, cfg: ScoreConfig, pol: Policy, sandbox: Sandbox,
                 github: gh.GitHubClient | None = None, lease_seconds: int = 300, retry_delay: float = 5.0, mailer=None):
        self.store, self.cfg, self.pol, self.sandbox, self.github = store, cfg, pol, sandbox, github
        self.mailer = mailer
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
            with telemetry.span("job", job_id=job["id"], run_id=job["run_id"], kind=job["kind"], org_id=job["organization_id"],
                                attempt=job["attempts"]):
                if job["kind"] == "archive":
                    self._archive(job, payload)
                elif job["kind"] == "github":
                    self._github(job, payload)
                elif job["kind"] == "sample":
                    self._sample(job, payload)
                else:
                    raise ValueError(f"unknown job kind {job['kind']}")
            self.store.complete_job(job["id"])
        except Exception as e:  # infrastructure failure (not a scan verdict): retry, then quarantine
            self.store.fail_job(job["id"], f"{type(e).__name__}: {e}", self.retry_delay)
            after = self.store.job(job["id"])
            if after["status"] == "dead":
                self._finalize_dead(job, str(e))
        return True

    # ------------------------------------------------------------ scheduled rescans
    def schedule_tick(self, now: float | None = None) -> int:
        """Queue a scan for every due schedule. Returns how many were queued.

        The commit is resolved by GitHub at queue time. The same commit is rescanned on purpose: advisories in the
        vulnerability database change even when the code does not. A schedule whose installation is gone is switched off,
        and a full org queue postpones the schedule instead of dropping it."""
        now = now or time.time()
        quota = int(os.environ.get("AVISHKAR_MAX_ACTIVE_JOBS", "20"))
        queued = 0
        for s in self.store.due_schedules(now):
            org, hours = s["organization_id"], s["every_hours"]
            try:
                inst = self.store.installation(s["installation_id"])
                if not inst or inst["organization_id"] != org:
                    self.store.delete_schedule(org, s["id"])
                    self.store.audit("scheduler", "schedule_disabled", "schedule", s["id"], "installation_gone", org=org)
                    continue
                if self.store.active_job_count(org) >= quota:
                    continue  # try again on the next tick
                if not self.github:
                    raise gh.GitHubError("GitHub App is not configured")
                head = next((b for b in self.github.list_branches(s["installation_id"], s["repo"]) if b["name"] == s["branch"]), None)
                if head is None:
                    raise gh.GitHubError("branch no longer exists")
                ref = f"refs/heads/{s['branch']}"
                self.store.set_ref_head(s["repository_id"], ref, head["sha"])
                bucket = int(now // (hours * 3600))
                run_id = self.store.create_run(s["repository_id"], head["sha"], "scheduler")
                job, created = self.store.enqueue(org, s["repository_id"], run_id, "github",
                                                  {"installation": s["installation_id"], "repo": s["repo"], "sha": head["sha"], "ref": ref,
                                                   "pr": None, "schedule_id": s["id"]}, f"sched:{s['id']}:{bucket}")
                queued += 1 if created else 0
                self.store.audit("scheduler", "schedule_queued", "analysis_run", job["run_id"], "ok", org=org)
            except Exception as e:  # GitHub outage, deleted branch ...: skip this period, keep the schedule
                self.store.audit("scheduler", "schedule_failed", "schedule", s["id"], type(e).__name__, org=org)
            self.store.set_schedule_next(s["id"], now + hours * 3600)
        return queued

    def _notify_schedule(self, job, p, res):
        """After a scheduled scan: remember the result and, when something changed, email a short summary.

        The email contains counts, rule titles and file:line only (no code or evidence) and goes to an address that
        belongs to a user of the same organization."""
        s = self.store.schedule(p["schedule_id"])
        if not s:
            return
        sd = res["securityDebt"]
        new_index, new_status = sd.get("normalizedIndex"), res["status"]
        old_index, old_status, old_run = s["last_index"], s["last_status"], s["last_run_id"]
        self.store.set_schedule_result(s["id"], job["run_id"], p["sha"], new_index, new_status)
        if old_status is None or not s["notify_email"] or self.mailer is None:
            return  # first run only sets the baseline
        lines = []
        if new_status != old_status:
            lines.append(f"Analysis status changed: {old_status} -> {new_status}."
                         + (" An incomplete analysis is NOT a pass." if new_status != "complete" else ""))
        if new_index is not None and old_index is not None and abs(new_index - old_index) >= 0.1:
            lines.append(f"Security debt index: {old_index:g} -> {new_index:g} ({new_index - old_index:+.1f}).")
        try:
            from .. import analysis
            base, head = self.store.run(old_run), self.store.run(job["run_id"])
            if base and head:
                cmp = analysis.compare_runs(base, head, self.store.run_findings(old_run), self.store.run_findings(job["run_id"]))
                if cmp.get("comparable"):
                    for label, items in (("New findings", cmp["introduced"]), ("Fixed", cmp["fixed"])):
                        if items:
                            lines.append(f"{label} ({len(items)}):")
                            lines += [f"  - [{i['severity']}] {i['title']} ({i['path']}:{i['line']})" for i in items[:10]]
                            if len(items) > 10:
                                lines.append(f"  ... and {len(items) - 10} more")
        except Exception:
            pass
        if not lines:
            return
        base_url = getattr(self.mailer, "public_url", "")
        body = (f"Scheduled scan of {s['repo']} ({s['branch']}, commit {p['sha'][:8]}) found changes since the previous scan.\n\n"
                + "\n".join(lines) + f"\n\nOpen the repository: {base_url}/#/repo/{s['repository_id']}\n\n"
                "The index is a prioritization signal from uncalibrated weights, not proof of safety.")
        try:
            self.mailer.send(s["notify_email"], f"Second Read: changes in {s['repo']} ({s['branch']})", body)
            self.store.audit("scheduler", "schedule_email_sent", "schedule", s["id"], "ok", org=s["organization_id"])
        except Exception as e:  # advisory: a mail failure must not fail an otherwise finished scan
            self.store.audit("scheduler", "schedule_email_failed", "schedule", s["id"], type(e).__name__, org=s["organization_id"])

    def drain(self, max_jobs: int = 1000) -> int:
        n = 0
        while n < max_jobs and self.run_once():
            n += 1
        return n

    # ------------------------------------------------------------ job kinds
    def _finish(self, job, collected):
        self.store.set_run_stage(job["run_id"], "scoring")
        base = self.store.baseline(job["repository_id"])
        with telemetry.span("assemble", stage="assemble", run_id=job["run_id"]):
            res = pipeline.assemble(self.cfg, self.pol, collected, base)
        self.store.set_run_stage(job["run_id"], "saving")
        with telemetry.span("persist", stage="persist", run_id=job["run_id"], status=res["status"]):
            self.store.save_run(job["repository_id"], job["run_id"], res)
        self.store.audit("worker", "analysis_finished", "analysis_run", job["run_id"], res["status"],
                         org=job["organization_id"])
        return res

    def _archive(self, job, payload):
        zp = Path(payload["spool_path"])
        self.store.set_run_stage(job["run_id"], "scanning")
        with telemetry.span("sandbox_collect", stage="collect", run_id=job["run_id"]):
            collected = self.sandbox.collect(self.cfg.required_detectors, zip_path=zp)
        self._finish(job, collected)
        zp.unlink(missing_ok=True)  # kept across retries; removed on success or when dead-lettered

    def _sample(self, job, payload):
        """Scan a bundled sample (optionally with fix-pack edits applied to a copy). The files are ours, never user input."""
        import shutil

        from .. import samples
        self.store.set_run_stage(job["run_id"], "preparing")
        tmp = Path(tempfile.mkdtemp(prefix="avishkar-sample-"))
        try:
            samples.write_variant(payload["sample"], payload.get("fixes", []), tmp)
            self.store.set_run_stage(job["run_id"], "scanning")
            with telemetry.span("sandbox_collect", stage="collect", run_id=job["run_id"]):
                collected = self.sandbox.collect(self.cfg.required_detectors, source_dir=tmp)
            self._finish(job, collected)
            self.store.prune_runs(job["repository_id"], keep=40)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

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
            with telemetry.span("sandbox_collect", stage="collect", run_id=job["run_id"]):
                collected = self.sandbox.collect(self.cfg.required_detectors, zip_path=zp)
        finally:
            zp.unlink(missing_ok=True)
        res = self._finish(job, collected)
        if p.get("schedule_id"):
            self._notify_schedule(job, p, res)
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
        if p.get("pr") and gh.pr_comments_enabled():
            try:  # advisory; a comment failure must not fail an otherwise finished analysis
                rows = sorted(self.store.run_findings(job["run_id"]), key=lambda f: -["informational", "low", "medium", "high", "critical"].index(f["severity"]))
                body = reporting.render_summary(res["status"], sd, res["decision"], res["completeness"], rows)
                self.github.upsert_pr_comment(inst, repo, int(p["pr"]), body, reporting.MARKER)
            except Exception as e:
                telemetry.log.warning("pr_comment_failed", extra={"ctx": {"job_id": job["id"], "outcome": type(e).__name__}})

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
        last_tick = 0.0
        while not self._stop.is_set():
            if time.time() - last_tick >= 30:  # scheduled rescans are checked every 30 s
                last_tick = time.time()
                try:
                    self.runner.schedule_tick()
                except Exception:
                    pass
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
