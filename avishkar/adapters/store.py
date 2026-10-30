"""Persistence use-cases. Every read/write that touches tenant data is scoped by organization_id."""
from __future__ import annotations

import json
import time
import uuid

from .db import Database

DISPOSITIONS = {"false_positive", "not_applicable", "duplicate", "accepted_risk", "open"}


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Store:
    def __init__(self, url: str = "data/avishkar_v2.db"):
        self.d = Database(url)

    # ------------------------------------------------------------ shared counters & login throttle
    # Kept in the database (not process memory) so every API replica sees the same lockouts and counters.
    def incr_metric(self, name):
        self.d.execute("INSERT INTO metric_counter(name,value) VALUES(?,1) "
                       "ON CONFLICT(name) DO UPDATE SET value=metric_counter.value+1", (name,))

    def metrics(self):
        return {r["name"]: r["value"] for r in self.d.query("SELECT name,value FROM metric_counter")}

    def login_failures(self, key, since):
        return self.d.query("SELECT COUNT(*) AS n FROM login_failure WHERE key=? AND ts>?", (key, since))[0]["n"]

    def add_login_failure(self, key):
        self.d.execute("INSERT INTO login_failure(key,ts) VALUES(?,?)", (key, time.time()))
        self.d.execute("DELETE FROM login_failure WHERE ts<?", (time.time() - 86400,))

    def clear_login_failures(self, key):
        self.d.execute("DELETE FROM login_failure WHERE key=?", (key,))

    # ------------------------------------------------------------ audit
    def audit(self, actor, action, otype, oid, outcome="ok", corr=None, detail=None, org=None):
        self.d.execute("INSERT INTO audit_event(organization_id,actor,action,object_type,object_id,ts,outcome,"
                       "correlation_id,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                       (org, actor, action, otype, oid, time.time(), outcome, corr, json.dumps(detail or {})))

    def recent_audit_count(self, org, actor, action, since):
        return self.d.query("SELECT COUNT(*) AS n FROM audit_event WHERE organization_id=? AND actor=? AND action=? AND ts>?",
                            (org, actor, action, since))[0]["n"]

    def audit_log(self, org, limit=100):
        return self.d.query("SELECT * FROM audit_event WHERE organization_id=? ORDER BY id DESC LIMIT ?", (org, limit))

    # ------------------------------------------------------------ orgs, users, keys
    def create_org(self, name):
        r = self.d.query("SELECT * FROM organization WHERE name=?", (name,))
        if r:
            return r[0]
        oid = _id("org")
        self.d.execute("INSERT INTO organization VALUES(?,?,?)", (oid, name, time.time()))
        return {"id": oid, "name": name}

    def org(self, oid):
        r = self.d.query("SELECT * FROM organization WHERE id=?", (oid,))
        return r[0] if r else None

    def org_count(self):
        return self.d.query("SELECT COUNT(*) AS n FROM organization")[0]["n"]

    def create_user(self, org, email, pw_hash, role):
        uid = _id("usr")
        self.d.execute("INSERT INTO app_user VALUES(?,?,?,?,?,?,?)",
                       (uid, org, email.lower(), pw_hash, role, 1, time.time()))
        return {"id": uid, "organizationId": org, "email": email.lower(), "role": role}

    def user_by_email(self, email):
        r = self.d.query("SELECT * FROM app_user WHERE email=? AND active=1", (email.lower(),))
        return r[0] if r else None

    def user(self, uid):
        r = self.d.query("SELECT * FROM app_user WHERE id=? AND active=1", (uid,))
        return r[0] if r else None

    def users(self, org):
        return self.d.query("SELECT id,email,role,active,created_at FROM app_user WHERE organization_id=? ORDER BY email",
                            (org,))

    def deactivate_user(self, org, uid):
        return self.d.execute("UPDATE app_user SET active=0 WHERE id=? AND organization_id=?", (uid, org)) > 0

    def create_api_key(self, org, role, label, key_hash):
        kid = _id("key")
        self.d.execute("INSERT INTO api_key VALUES(?,?,?,?,?,?,?,?)",
                       (kid, org, key_hash, role, label, 1, time.time(), None))
        return kid

    def api_key(self, key_hash):
        r = self.d.query("SELECT * FROM api_key WHERE key_hash=? AND active=1", (key_hash,))
        return r[0] if r else None

    def revoke_api_key(self, org, kid):
        return self.d.execute("UPDATE api_key SET active=0 WHERE id=? AND organization_id=?", (kid, org)) > 0

    def api_keys(self, org):
        return self.d.query("SELECT id,role,label,active,created_at FROM api_key WHERE organization_id=?", (org,))

    # ------------------------------------------------------------ repositories
    def get_or_create_repo(self, org, name):
        r = self.d.query("SELECT * FROM repository WHERE organization_id=? AND name=?", (org, name))
        if r:
            return r[0]
        rid = _id("repo")
        self.d.execute("INSERT INTO repository VALUES(?,?,?,?)", (rid, org, name, time.time()))
        return {"id": rid, "organization_id": org, "name": name}

    def repos(self, org):
        return self.d.query("""SELECT r.id,r.name,
          (SELECT COUNT(*) FROM analysis_run a WHERE a.repository_id=r.id) AS runs,
          (SELECT score FROM analysis_run a WHERE a.repository_id=r.id AND a.status='complete'
             ORDER BY started_at DESC LIMIT 1) AS latest_score
          FROM repository r WHERE r.organization_id=? ORDER BY r.name""", (org,))

    def repo(self, rid, org):
        r = self.d.query("SELECT * FROM repository WHERE id=? AND organization_id=?", (rid, org))
        return r[0] if r else None

    # ------------------------------------------------------------ analysis runs
    def baseline(self, repo_id):
        return {r["fingerprint"]: {"state": r["state"], "first_seen": r["first_seen"]}
                for r in self.d.query("SELECT fingerprint,state,first_seen FROM finding WHERE repository_id=?",
                                      (repo_id,))}

    def create_run(self, repo_id, commit_sha, corr, status="queued"):
        rid, now = _id("run"), time.time()
        stages = json.dumps({"current": "queued", "timeline": [{"stage": "queued", "ts": now}]})
        self.d.execute("INSERT INTO analysis_run(id,repository_id,commit_sha,status,started_at,correlation_id,stages)"
                       " VALUES(?,?,?,?,?,?,?)", (rid, repo_id, commit_sha, status, now, corr, stages))
        return rid

    def set_run_status(self, run_id, status):
        self.d.execute("UPDATE analysis_run SET status=? WHERE id=?", (status, run_id))

    def _timeline(self, run_id):
        r = self.d.query("SELECT stages FROM analysis_run WHERE id=?", (run_id,))
        st = json.loads(r[0]["stages"]) if r and r[0]["stages"] else {}
        return st.get("timeline", [])

    def set_run_stage(self, run_id, stage, status="running"):
        """Record a real pipeline stage transition (queued -> preparing -> scanning -> scoring -> saving -> complete)."""
        tl = self._timeline(run_id) + [{"stage": stage, "ts": time.time()}]
        self.d.execute("UPDATE analysis_run SET status=?, stages=? WHERE id=?",
                       (status, json.dumps({"current": stage, "timeline": tl}), run_id))

    def prune_runs(self, repo_id, keep=40):
        """Bound growth of demo repositories: drop the oldest runs' instances and rows (the finding ledger is kept)."""
        old = self.d.query("SELECT id FROM analysis_run WHERE repository_id=? ORDER BY started_at DESC LIMIT 1000 OFFSET ?",
                           (repo_id, keep))
        for r in old:
            self.d.execute("DELETE FROM finding_instance WHERE analysis_run_id=?", (r["id"],))
            self.d.execute("DELETE FROM analysis_run WHERE id=?", (r["id"],))
        return len(old)

    def recent_job_count(self, org, kind, since):
        return self.d.query("SELECT COUNT(*) AS n FROM job WHERE organization_id=? AND kind=? AND created_at>?",
                            (org, kind, since))[0]["n"]

    def save_run(self, repo_id, run_id, result):
        """Finalize a run row and upsert the finding ledger (one transaction)."""
        now = time.time()
        d = self.d
        with d.transaction():
            timeline = self._timeline(run_id) + [{"stage": "complete" if result["status"] == "complete" else result["status"],
                                                   "ts": now}]
            stages = {**result["stages"], "current": timeline[-1]["stage"], "timeline": timeline}
            d.execute("UPDATE analysis_run SET policy_version=?,status=?,completed_at=?,completeness=?,score=?,"
                      "decision=?,stages=?,notes=? WHERE id=?",
                      (result["decision"]["policyVersion"], result["status"], result["completedAt"],
                       json.dumps(result["completeness"]), json.dumps(result["securityDebt"]),
                       json.dumps(result["decision"]), json.dumps(stages),
                       json.dumps(result["notes"]), run_id))
            for f in result["findings"]:
                r = f.raw
                row = d.query("SELECT id,state FROM finding WHERE repository_id=? AND fingerprint=?",
                              (repo_id, f.fingerprint))
                if row:
                    fid = row[0]["id"]
                    newstate = "open" if row[0]["state"] == "fixed" else row[0]["state"]
                    d.execute("UPDATE finding SET last_seen=?, state=? WHERE id=?", (now, newstate, fid))
                else:
                    fid = _id("fnd")
                    d.execute(
                        "INSERT INTO finding(id,repository_id,fingerprint,detector_id,rule_id,category,severity,"
                        "confidence,exposure,title,remediation,effort,state,first_seen,last_seen)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (fid, repo_id, f.fingerprint, r.detector_id, r.rule_id, r.category, r.severity.value,
                         r.confidence.value, r.exposure.value, r.title, r.remediation, r.effort,
                         "open", now, now))
                d.execute("INSERT INTO finding_instance(finding_id,analysis_run_id,path,line_start,evidence,state)"
                          " VALUES(?,?,?,?,?,?)", (fid, run_id, r.path, r.line, r.evidence, f.state.value))
            if result["status"] == "complete":  # only a complete scan may mark findings fixed
                for fp in result["fixed"]:
                    d.execute("UPDATE finding SET state='fixed', version=version+1 WHERE repository_id=? AND fingerprint=?",
                              (repo_id, fp))

    def run(self, rid):
        rows = self.d.query("SELECT * FROM analysis_run WHERE id=?", (rid,))
        return self._decode_run(rows[0]) if rows else None

    def runs(self, repo_id, limit=100):
        return [self._decode_run(r) for r in
                self.d.query("SELECT * FROM analysis_run WHERE repository_id=? ORDER BY started_at DESC LIMIT ?",
                             (repo_id, limit))]

    @staticmethod
    def _decode_run(r):
        for k in ("completeness", "score", "decision", "stages", "notes"):
            r[k] = json.loads(r[k]) if r[k] else None
        return r

    # ------------------------------------------------------------ findings
    LOC = "(SELECT path||':'||CAST(line_start AS TEXT) FROM finding_instance i WHERE i.finding_id=f.id ORDER BY i.id DESC LIMIT 1)"
    EV = "(SELECT evidence FROM finding_instance i WHERE i.finding_id=f.id ORDER BY i.id DESC LIMIT 1)"
    PATH = "(SELECT path FROM finding_instance i WHERE i.finding_id=f.id ORDER BY i.id DESC LIMIT 1)"
    SORTS = {"id": "f.id", "severity": "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                                         "WHEN 'low' THEN 3 ELSE 4 END",
             "confidence": "CASE f.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END",
             "path": PATH, "rule": "f.rule_id", "first_seen": "f.first_seen", "last_seen": "f.last_seen"}

    @staticmethod
    def _like(term: str) -> str:
        return "%" + term.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def _findings_where(self, repo_id, state, severity, category, confidence, rule_ids, path, q):
        where, args = ["f.repository_id=?"], [repo_id]
        for col, val in (("state", state), ("severity", severity), ("category", category), ("confidence", confidence)):
            if val:
                where.append(f"f.{col}=?")
                args.append(val)
        if rule_ids:
            where.append("f.rule_id IN (" + ",".join("?" * len(rule_ids)) + ")")
            args += list(rule_ids)
        if path:
            where.append(f"LOWER({self.PATH}) LIKE ? ESCAPE '\\'")
            args.append(self._like(path))
        if q:
            like = self._like(q)
            where.append(f"(LOWER(f.title) LIKE ? ESCAPE '\\' OR LOWER(f.rule_id) LIKE ? ESCAPE '\\' OR LOWER(f.category) LIKE ? "
                         f"ESCAPE '\\' OR LOWER({self.PATH}) LIKE ? ESCAPE '\\' OR LOWER({self.EV}) LIKE ? ESCAPE '\\')")
            args += [like] * 5
        return " AND ".join(where), args

    def findings(self, repo_id, state=None, severity=None, cursor=None, limit=50, *, q=None, category=None, path=None,
                 confidence=None, rule_ids=None, sort="id", order="asc", offset=0):
        """Filtered, sorted, paginated findings. sort=id uses a stable cursor; other sorts use offset paging.
        Returns (rows, next_cursor, next_offset, total_matching)."""
        if sort not in self.SORTS:
            sort = "id"
        where, args = self._findings_where(repo_id, state, severity, category, confidence, rule_ids, path, q)
        total = self.d.query(f"SELECT COUNT(*) AS n FROM finding f WHERE {where}", args)[0]["n"]
        sql = f"SELECT f.*, {self.LOC} AS location, {self.EV} AS evidence FROM finding f WHERE {where}"
        if sort == "id" and cursor:
            sql += " AND f.id>?"
            args = args + [cursor]
        direction = "DESC" if str(order).lower() == "desc" else "ASC"
        sql += f" ORDER BY {self.SORTS[sort]} {direction}, f.id ASC LIMIT ?"
        args = args + [limit + 1]
        if sort != "id":
            sql += " OFFSET ?"
            args.append(max(0, int(offset)))
        rows = self.d.query(sql, args)
        more = len(rows) > limit
        nxt = rows[limit - 1]["id"] if (more and sort == "id") else None
        next_offset = (max(0, int(offset)) + limit) if (more and sort != "id") else None
        return rows[:limit], nxt, next_offset, total

    def findings_count(self, repo_id, **filters):
        rows = self.d.query("SELECT state, severity, category, COUNT(*) AS n FROM finding WHERE repository_id=? "
                            "GROUP BY state, severity, category", (repo_id,))
        return rows

    def all_findings(self, repo_id):
        """Every ledger row for a repository (no pagination): small, used for dashboard aggregates."""
        return self.d.query("SELECT * FROM finding WHERE repository_id=?", (repo_id,))

    def latest_run(self, repo_id):
        r = self.d.query("SELECT * FROM analysis_run WHERE repository_id=? ORDER BY started_at DESC LIMIT 1", (repo_id,))
        return self._decode_run(r[0]) if r else None

    def open_counts(self, org):
        out = {}
        for r in self.d.query("SELECT f.repository_id AS rid, f.severity AS sev, COUNT(*) AS n FROM finding f JOIN repository r "
                              "ON r.id=f.repository_id WHERE r.organization_id=? AND f.state='open' GROUP BY f.repository_id, f.severity",
                              (org,)):
            out.setdefault(r["rid"], {})[r["sev"]] = r["n"]
        return out

    def repo_activity(self, repo_id, limit=15):
        ev = []
        for r in self.d.query("SELECT id,status,started_at,commit_sha,decision FROM analysis_run WHERE repository_id=? "
                              "ORDER BY started_at DESC LIMIT ?", (repo_id, limit)):
            dec = json.loads(r["decision"]) if r["decision"] else {}
            ev.append({"ts": r["started_at"], "type": "scan", "runId": r["id"],
                       "text": f"Scan {r['status']}" + (f" ({dec.get('outcome', '').replace('_', ' ')})" if dec else "")
                               + (f" at {r['commit_sha'][:8]}" if r["commit_sha"] else "")})
        for d in self.d.query("SELECT d.created_at AS ts, d.type AS type, d.actor AS actor, f.title AS title, f.id AS fid FROM disposition d "
                              "JOIN finding f ON f.id=d.finding_id WHERE f.repository_id=? ORDER BY d.created_at DESC LIMIT ?",
                              (repo_id, limit)):
            ev.append({"ts": d["ts"], "type": "triage", "findingId": d["fid"],
                       "text": f"{d['actor']} marked \"{d['title']}\" as {d['type'].replace('_', ' ')}"})
        ev.sort(key=lambda e: -e["ts"])
        return ev[:limit]

    def run_findings(self, run_id):
        """Findings observed in one run, joined with their ledger state."""
        return self.d.query(
            "SELECT f.id,f.fingerprint,f.rule_id,f.title,f.severity,f.confidence,f.category,f.remediation,f.state,"
            "i.path,i.line_start,i.evidence FROM finding_instance i JOIN finding f ON f.id=i.finding_id "
            "WHERE i.analysis_run_id=? ORDER BY f.id", (run_id,))

    def finding(self, fid, org):
        r = self.d.query("SELECT f.* FROM finding f JOIN repository r ON r.id=f.repository_id "
                         "WHERE f.id=? AND r.organization_id=?", (fid, org))
        if not r:
            return None
        f = r[0]
        f["instances"] = self.d.query("SELECT * FROM finding_instance WHERE finding_id=? ORDER BY id DESC", (fid,))
        f["dispositions"] = self.d.query("SELECT * FROM disposition WHERE finding_id=? ORDER BY created_at", (fid,))
        f["explanation"] = self.explanation(fid)
        return f

    def disposition(self, fid, org, dtype, rationale, actor, expires_at, expected_version):
        with self.d.transaction():
            f = self.finding(fid, org)
            if not f:
                return "not_found", None
            if f["version"] != expected_version:
                return "conflict", f
            self.d.execute("INSERT INTO disposition VALUES(?,?,?,?,?,?,?)",
                           (_id("dsp"), fid, dtype, rationale, actor, expires_at, time.time()))
            self.d.execute("UPDATE finding SET state=?, version=version+1 WHERE id=?", (dtype, fid))
        return "ok", self.finding(fid, org)

    def expire_exceptions(self, org):
        """Expired accepted-risk reverts to open so normal policy evaluation resumes."""
        now = time.time()
        ids = [r["finding_id"] for r in self.d.query(
            "SELECT d.finding_id FROM disposition d JOIN finding f ON f.id=d.finding_id "
            "JOIN repository r ON r.id=f.repository_id "
            "WHERE r.organization_id=? AND d.type='accepted_risk' AND f.state='accepted_risk' "
            "AND d.expires_at IS NOT NULL AND d.expires_at<? "
            "AND d.created_at=(SELECT MAX(created_at) FROM disposition WHERE finding_id=d.finding_id)", (org, now))]
        for i in ids:
            self.d.execute("UPDATE finding SET state='open', version=version+1 WHERE id=?", (i,))
            self.audit("system", "exception_expired", "finding", i, org=org)
        return ids

    # ------------------------------------------------------------ explanations
    def save_explanation(self, fid, status, content, model, prompt_version):
        self.d.execute("DELETE FROM explanation WHERE finding_id=?", (fid,))
        self.d.execute("INSERT INTO explanation VALUES(?,?,?,?,?,?)",
                       (fid, status, json.dumps(content) if content else None, model, prompt_version, time.time()))

    def explanation(self, fid):
        r = self.d.query("SELECT * FROM explanation WHERE finding_id=?", (fid,))
        if not r:
            return None
        r[0]["content"] = json.loads(r[0]["content"]) if r[0]["content"] else None
        return r[0]

    # ------------------------------------------------------------ durable job queue
    def enqueue(self, org, repo_id, run_id, kind, payload, idem_key=None, max_attempts=3):
        """Returns (job, created). An existing idempotency key returns the original job."""
        with self.d.lock:
            if idem_key:
                ex = self.d.query("SELECT * FROM job WHERE organization_id=? AND idempotency_key=?", (org, idem_key))
                if ex:
                    return ex[0], False
            jid, now = _id("job"), time.time()
            try:
                self.d.execute("INSERT INTO job VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (jid, org, repo_id, run_id, kind, json.dumps(payload), "queued", 0, max_attempts,
                                now, None, None, None, idem_key, now, now))
            except Exception:
                # another replica inserted the same idempotency key between our check and insert
                ex = self.job_by_idem(org, idem_key) if idem_key else None
                if ex:
                    return ex, False
                raise
            return self.job(jid), True

    def job_by_idem(self, org, idem_key):
        r = self.d.query("SELECT * FROM job WHERE organization_id=? AND idempotency_key=?", (org, idem_key))
        return r[0] if r else None

    def job(self, jid):
        r = self.d.query("SELECT * FROM job WHERE id=?", (jid,))
        return r[0] if r else None

    def jobs(self, org, status=None, limit=100):
        sql, args = "SELECT * FROM job WHERE organization_id=?", [org]
        if status:
            sql += " AND status=?"; args.append(status)
        return self.d.query(sql + " ORDER BY created_at DESC LIMIT ?", args + [limit])

    def active_job_count(self, org):
        return self.d.query("SELECT COUNT(*) AS n FROM job WHERE organization_id=? AND status IN ('queued','running')",
                            (org,))[0]["n"]

    def reclaim_expired(self):
        """A worker that died mid-job leaves an expired lease; requeue (or dead-letter) it."""
        now, n = time.time(), 0
        for j in self.d.query("SELECT * FROM job WHERE status='running' AND lease_until<?", (now,)):
            n += self._fail(j, "lease expired (worker lost)", 0)
        return n

    def claim(self, worker_id, lease_seconds=300):
        """Fair claim: prefer the organization with the fewest running jobs, then the oldest job."""
        now = time.time()
        with self.d.lock:
            self.reclaim_expired()
            cands = self.d.query("SELECT * FROM job WHERE status='queued' AND not_before<=? ORDER BY created_at LIMIT 100",
                                 (now,))
            if not cands:
                return None
            running = {r["organization_id"]: r["n"] for r in self.d.query(
                "SELECT organization_id, COUNT(*) AS n FROM job WHERE status='running' GROUP BY organization_id")}
            cands.sort(key=lambda j: (running.get(j["organization_id"], 0), j["created_at"]))
            for j in cands:
                n = self.d.execute("UPDATE job SET status='running', attempts=attempts+1, worker_id=?, lease_until=?,"
                                   " updated_at=? WHERE id=? AND status='queued'",
                                   (worker_id, now + lease_seconds, now, j["id"]))
                if n:
                    return self.job(j["id"])
            return None

    def complete_job(self, jid):
        self.d.execute("UPDATE job SET status='done', lease_until=NULL, updated_at=? WHERE id=?", (time.time(), jid))

    def fail_job(self, jid, error, retry_delay=5.0):
        j = self.job(jid)
        return self._fail(j, error, retry_delay) if j else 0

    def _fail(self, j, error, retry_delay):
        now = time.time()
        if j["attempts"] >= j["max_attempts"]:  # quarantine (dead-letter)
            self.d.execute("UPDATE job SET status='dead', error=?, lease_until=NULL, updated_at=? WHERE id=?",
                           (error[:500], now, j["id"]))
            return 1
        delay = retry_delay * (2 ** (j["attempts"] - 1))
        self.d.execute("UPDATE job SET status='queued', error=?, lease_until=NULL, not_before=?, updated_at=? WHERE id=?",
                       (error[:500], now + delay, now, j["id"]))
        return 1

    def requeue_dead(self, org, jid):
        return self.d.execute("UPDATE job SET status='queued', attempts=0, not_before=?, error=NULL WHERE id=? "
                              "AND organization_id=? AND status='dead'", (time.time(), jid, org)) > 0

    # ------------------------------------------------------------ GitHub integration state
    def record_delivery(self, provider, delivery_id, event, body_hash):
        """True if new; False for a replayed/redelivered delivery id."""
        with self.d.lock:
            if self.d.query("SELECT 1 AS x FROM webhook_delivery WHERE provider=? AND delivery_id=?",
                            (provider, delivery_id)):
                return False
            self.d.execute("INSERT INTO webhook_delivery VALUES(?,?,?,?,?,?)",
                           (provider, delivery_id, event, body_hash, time.time(), "received"))
            return True

    def set_delivery_outcome(self, provider, delivery_id, outcome):
        self.d.execute("UPDATE webhook_delivery SET outcome=? WHERE provider=? AND delivery_id=?",
                       (outcome, provider, delivery_id))

    def link_installation(self, org, installation_id, account):
        ex = self.d.query("SELECT * FROM github_installation WHERE installation_id=?", (str(installation_id),))
        if ex and ex[0]["organization_id"] != org:
            return False  # an installation can belong to only one organization
        if ex:
            self.d.execute("UPDATE github_installation SET active=1, account=? WHERE installation_id=?",
                           (account, str(installation_id)))
        else:
            self.d.execute("INSERT INTO github_installation VALUES(?,?,?,?,?)",
                           (str(installation_id), org, account, 1, time.time()))
        return True

    def installation(self, installation_id):
        r = self.d.query("SELECT * FROM github_installation WHERE installation_id=? AND active=1",
                         (str(installation_id),))
        return r[0] if r else None

    def deactivate_installation(self, installation_id):
        self.d.execute("UPDATE github_installation SET active=0 WHERE installation_id=?", (str(installation_id),))

    def installations(self, org):
        return self.d.query("SELECT * FROM github_installation WHERE organization_id=?", (org,))

    def set_ref_head(self, repo_id, ref, sha):
        self.d.execute("DELETE FROM ref_head WHERE repository_id=? AND ref=?", (repo_id, ref))
        self.d.execute("INSERT INTO ref_head VALUES(?,?,?,?)", (repo_id, ref, sha, time.time()))

    def ref_head(self, repo_id, ref):
        r = self.d.query("SELECT sha FROM ref_head WHERE repository_id=? AND ref=?", (repo_id, ref))
        return r[0]["sha"] if r else None
