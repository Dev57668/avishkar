import io
import os
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["AVISHKAR_ALLOW_INLINE"] = "1"

from avishkar.api.app import create_app  # noqa: E402
from avishkar.api.security import hash_password, new_api_key  # noqa: E402
from avishkar.workers import runner as runner_mod  # noqa: E402
from avishkar.workers.sandbox import Sandbox  # noqa: E402

FIX = Path(__file__).resolve().parents[1] / "fixtures"
PW = "correct horse battery"


def zip_dir(d: Path, extra=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in d.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(d).as_posix())
        for n, c in (extra or {}).items():
            z.writestr(n, c)
    return buf.getvalue()


def _truncate_all(url):
    from avishkar.adapters.db import SCHEMA, Database
    import re
    db = Database(url)  # creates the schema if missing
    names = re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA)
    db.execute("TRUNCATE " + ",".join(names) + " RESTART IDENTITY CASCADE")
    db.conn.close()


class Env:
    """Test harness: app + client + helpers. Worker thread is off; tests drain the queue deterministically."""

    def __init__(self, tmp_path, **kw):
        runner_mod.SPOOL_DIR = tmp_path / "spool"
        self.sandbox = kw.pop("sandbox", None) or Sandbox("inline")
        # CI runs the whole suite on PostgreSQL when AVISHKAR_TEST_DATABASE_URL is set.
        self.db_url = os.environ.get("AVISHKAR_TEST_DATABASE_URL") or str(tmp_path / "t.db")
        if self.db_url.startswith("postgres"):
            _truncate_all(self.db_url)
        self.app = create_app(self.db_url, secret_key="s" * 40, sandbox=self.sandbox, start_worker=False, **kw)
        self.client = TestClient(self.app)
        self.store = self.app.state.store
        self.runner = self.app.state.runner
        self.runner.retry_delay = 0
        self.org = self.store.create_org("acme")
        self.admin = self.add_user(self.org["id"], "admin@acme.test", "admin")
        self.h = self.login("admin@acme.test")

    def add_user(self, org_id, email, role):
        return self.store.create_user(org_id, email, hash_password(PW), role)

    def login(self, email, pw=PW):
        r = self.client.post("/v1/auth/login", json={"email": email, "password": pw})
        assert r.status_code == 200, r.text
        return {"Authorization": "Bearer " + r.json()["token"]}

    def api_key(self, org_id, role="analyst"):
        key, h = new_api_key()
        self.store.create_api_key(org_id, role, "ci", h)
        return {"X-API-Key": key}

    def scan(self, repo, data, headers=None, drain=True, **form):
        r = self.client.post("/v1/analyses", headers=headers or self.h, data={"repository": repo, **form},
                             files={"archive": ("a.zip", data)})
        if drain and r.status_code == 202:
            self.runner.drain()
        return r

    def run(self, queued, headers=None):
        b = queued.json()
        r = self.client.get(f"/v1/repositories/{b['repositoryId']}/analyses/{b['runId']}", headers=headers or self.h)
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)
