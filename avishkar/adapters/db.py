"""Relational access layer supporting SQLite (default) and PostgreSQL.

`DATABASE_URL=postgresql://user:pw@host/db` selects PostgreSQL (requires `pip install "psycopg[binary]"`).
SQL is written once with `?` placeholders and translated per dialect. The PostgreSQL path is
exercised only against a live server (see docs/POSTGRES.md); the unit suite runs on SQLite.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS organization(id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at REAL);
CREATE TABLE IF NOT EXISTS app_user(
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at REAL);
CREATE TABLE IF NOT EXISTS api_key(
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, key_hash TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
  label TEXT, active INTEGER NOT NULL DEFAULT 1, created_at REAL, last_used REAL);
CREATE TABLE IF NOT EXISTS repository(
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL, created_at REAL,
  UNIQUE(organization_id, name));
CREATE TABLE IF NOT EXISTS analysis_run(
  id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, commit_sha TEXT, policy_version TEXT,
  status TEXT, started_at REAL, completed_at REAL, completeness TEXT, score TEXT, decision TEXT,
  stages TEXT, notes TEXT, correlation_id TEXT);
CREATE TABLE IF NOT EXISTS finding(
  id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
  detector_id TEXT, rule_id TEXT, category TEXT, severity TEXT, confidence TEXT, exposure TEXT,
  title TEXT, remediation TEXT, effort TEXT, state TEXT NOT NULL, first_seen REAL, last_seen REAL,
  version INTEGER NOT NULL DEFAULT 1, UNIQUE(repository_id, fingerprint));
CREATE TABLE IF NOT EXISTS finding_instance(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id TEXT, analysis_run_id TEXT, path TEXT, line_start INTEGER, evidence TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS disposition(
  id TEXT PRIMARY KEY, finding_id TEXT, type TEXT, rationale TEXT, actor TEXT,
  expires_at REAL, created_at REAL);
CREATE TABLE IF NOT EXISTS audit_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id TEXT, actor TEXT, action TEXT, object_type TEXT,
  object_id TEXT, ts REAL, outcome TEXT, correlation_id TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS job(
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, repository_id TEXT, run_id TEXT, kind TEXT NOT NULL,
  payload TEXT, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
  not_before REAL, lease_until REAL, worker_id TEXT, error TEXT, idempotency_key TEXT,
  created_at REAL, updated_at REAL, UNIQUE(organization_id, idempotency_key));
CREATE TABLE IF NOT EXISTS webhook_delivery(
  provider TEXT NOT NULL, delivery_id TEXT NOT NULL, event TEXT, body_hash TEXT, received_at REAL,
  outcome TEXT, PRIMARY KEY(provider, delivery_id));
CREATE TABLE IF NOT EXISTS github_installation(
  installation_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, account TEXT, active INTEGER NOT NULL DEFAULT 1,
  created_at REAL);
CREATE TABLE IF NOT EXISTS ref_head(
  repository_id TEXT NOT NULL, ref TEXT NOT NULL, sha TEXT NOT NULL, updated_at REAL,
  PRIMARY KEY(repository_id, ref));
CREATE TABLE IF NOT EXISTS explanation(
  finding_id TEXT PRIMARY KEY, status TEXT, content TEXT, model TEXT, prompt_version TEXT, created_at REAL);
CREATE INDEX IF NOT EXISTS ix_run_repo ON analysis_run(repository_id, started_at);
CREATE INDEX IF NOT EXISTS ix_finding_repo ON finding(repository_id, state);
CREATE INDEX IF NOT EXISTS ix_job_status ON job(status, not_before);
"""


def _pg_schema(sql: str) -> str:
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
    return re.sub(r"\bREAL\b", "DOUBLE PRECISION", sql)


class Database:
    def __init__(self, url: str = "data/avishkar_v2.db"):
        self.lock = threading.RLock()
        self.pg = url.startswith(("postgres://", "postgresql://"))
        if self.pg:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as e:  # pragma: no cover
                raise RuntimeError('PostgreSQL needs: pip install "psycopg[binary]"') from e
            self.conn = psycopg.connect(url, row_factory=dict_row, autocommit=False)
            schema = _pg_schema(SCHEMA)
        else:
            if url != ":memory:":
                Path(url).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(url, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            schema = SCHEMA
        with self.lock:
            for stmt in [s.strip() for s in schema.split(";") if s.strip()]:
                self.conn.cursor().execute(stmt) if self.pg else self.conn.execute(stmt)
            self.conn.commit()

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.pg else sql

    def query(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            try:
                cur = self.conn.cursor() if self.pg else self.conn
                cur = cur.execute(self._sql(sql), tuple(args))
                rows = cur.fetchall()
                return [dict(r) for r in rows]
            except Exception:
                self.conn.rollback()
                raise

    def execute(self, sql: str, args=(), commit: bool = True) -> int:
        with self.lock:
            try:
                cur = self.conn.cursor() if self.pg else self.conn
                cur = cur.execute(self._sql(sql), tuple(args))
                n = cur.rowcount
                if commit:
                    self.conn.commit()
                return n
            except Exception:
                self.conn.rollback()
                raise

    def commit(self):
        with self.lock:
            self.conn.commit()
