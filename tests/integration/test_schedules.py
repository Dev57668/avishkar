"""Scheduled GitHub rescans and change emails, against mocked GitHub and Resend APIs (no network)."""
import json

import httpx

from avishkar.adapters import github as gh
from avishkar.adapters.mailer import Mailer

from .conftest import Env
from .test_email import Outbox
from .test_github import SHA
from .test_github_browse import BrowseGitHub, keypair  # noqa: F401  (keypair is a fixture)

BODY = {"installation": "777", "repo": "acme/app", "branch": "main", "everyHours": 24}
T0 = 1_800_000_000.0


def env(tmp_path, keypair, mail=True, fixture="insecure"):
    priv, pub = keypair
    fake = BrowseGitHub(pub, fixture=fixture)
    client = gh.GitHubClient("123", priv, "https://api.github.test", transport=httpx.MockTransport(fake))
    box = Outbox()
    m = Mailer("re_test", "Second Read <no-reply@example.test>", "https://site.example", transport=httpx.MockTransport(box)) if mail else None
    e = Env(tmp_path, github=client, webhook_secret="whsec_test", mailer=m)
    assert e.client.post("/v1/github/installations", headers=e.h, json={"installation_id": "777", "account": "acme"}).status_code == 201
    e.add_user(e.org["id"], "ops@acme.test", "viewer")
    return e, fake, box


def create(e, **kw):
    return e.client.post("/v1/schedules", headers=e.h, json={**BODY, **kw})


# ------------------------------------------------------------------ API: validation and access
def test_admin_can_create_list_and_delete_a_schedule(tmp_path, keypair):
    e, _, _ = env(tmp_path, keypair)
    r = create(e, notifyEmail="Ops@Acme.test")
    assert r.status_code == 201 and r.json()["everyHours"] == 24 and r.json()["notifyEmail"] == "ops@acme.test"
    lst = e.client.get("/v1/schedules", headers=e.h).json()
    assert [s["repo"] for s in lst["items"]] == ["acme/app"] and lst["max"] == 10 and lst["emailConfigured"] is True
    assert e.client.delete(f"/v1/schedules/{r.json()['id']}", headers=e.h).status_code == 200
    assert e.client.get("/v1/schedules", headers=e.h).json()["items"] == []
    assert e.client.delete(f"/v1/schedules/{r.json()['id']}", headers=e.h).status_code == 404


def test_only_admins_manage_schedules(tmp_path, keypair):
    e, _, _ = env(tmp_path, keypair)
    e.add_user(e.org["id"], "an@acme.test", "analyst")
    for who in ("an@acme.test", "ops@acme.test"):
        h = e.login(who)
        assert e.client.get("/v1/schedules", headers=h).status_code == 403
        assert e.client.post("/v1/schedules", headers=h, json=BODY).status_code == 403


def test_validation_and_honest_errors(tmp_path, keypair):
    e, _, _ = env(tmp_path, keypair)
    assert create(e, everyHours=1).status_code == 422                      # too frequent
    assert create(e, everyHours=100000).status_code == 422
    assert create(e, repo="../etc").status_code == 422
    assert create(e, branch="nope").status_code == 404
    assert create(e, installation="999").status_code == 404                # not linked to this org
    assert create(e, notifyEmail="stranger@elsewhere.test").status_code == 422   # not a user of this org
    assert create(e, **{"extra": 1}).status_code == 422
    for i in range(10):
        assert create(e, repo="acme/app").status_code == 201
    assert create(e).status_code == 422                                    # per-org limit


def test_not_configured_and_email_not_configured(tmp_path, keypair, monkeypatch):
    for k in ("GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_PRIVATE_KEY_PATH"):
        monkeypatch.delenv(k, raising=False)
    assert create(Env(tmp_path / "a")).status_code == 503
    e, _, _ = env(tmp_path / "b", keypair, mail=False)
    r = create(e, notifyEmail="ops@acme.test")
    assert r.status_code == 422 and r.json()["error"]["code"] == "email_not_configured"
    assert create(e).status_code == 201                                    # a schedule without notifications is fine


# ------------------------------------------------------------------ the scheduler
def test_tick_queues_once_per_period_and_the_scan_runs(tmp_path, keypair):
    e, fake, _ = env(tmp_path, keypair)
    sid = create(e).json()["id"]
    assert e.runner.schedule_tick(now=T0) == 1
    assert e.runner.schedule_tick(now=T0 + 60) == 0                        # not due again for 24 h
    e.runner.drain()
    (c,) = fake.checks.values()
    assert c["create"]["head_sha"] == SHA and c["final"]["status"] == "completed"
    s = e.client.get("/v1/schedules", headers=e.h).json()["items"][0]
    assert s["id"] == sid and s["lastStatus"] == "complete" and s["lastIndex"] is not None and s["nextRun"] > T0 + 86000
    assert e.runner.schedule_tick(now=T0 + 86401) == 1                     # next period: the same commit is rescanned on purpose


def test_changes_trigger_one_email_with_counts_not_code(tmp_path, keypair):
    e, fake, box = env(tmp_path, keypair)
    create(e, notifyEmail="ops@acme.test")
    e.runner.schedule_tick(now=T0)
    e.runner.drain()
    assert box.sent == []                                                  # first run only sets the baseline
    fake.fixture = "secure"                                                # the code was fixed between scans
    e.runner.schedule_tick(now=T0 + 90000)
    e.runner.drain()
    assert len(box.sent) == 1
    mail = box.sent[0]
    assert mail["to"] == ["ops@acme.test"] and "acme/app" in mail["subject"]
    text = mail["text"]
    assert "Fixed (" in text and "Security debt index:" in text and "https://site.example/#/repo/" in text
    assert "AKIAQ3EXZ4HT7WN2K5ML" not in text and "not proof of safety" in text


def test_no_email_when_nothing_changed(tmp_path, keypair):
    e, _, box = env(tmp_path, keypair)
    create(e, notifyEmail="ops@acme.test")
    for i in range(3):
        e.runner.schedule_tick(now=T0 + i * 90000)
        e.runner.drain()
    assert box.sent == []


def test_a_mail_outage_does_not_fail_the_scan(tmp_path, keypair):
    e, fake, box = env(tmp_path, keypair)
    box.status = 500
    create(e, notifyEmail="ops@acme.test")
    e.runner.schedule_tick(now=T0)
    e.runner.drain()
    fake.fixture = "secure"
    e.runner.schedule_tick(now=T0 + 90000)
    assert e.runner.drain() >= 1
    s = e.client.get("/v1/schedules", headers=e.h).json()["items"][0]
    assert s["lastStatus"] == "complete"                                    # the scan finished and was recorded
    assert any(a["action"] == "schedule_email_failed" for a in e.client.get("/v1/audit", headers=e.h).json()["items"])


def test_deleted_branch_and_gone_installation_and_full_queue(tmp_path, keypair):
    e, fake, _ = env(tmp_path, keypair)
    sid = create(e).json()["id"]
    # a full organization queue postpones the schedule (next_run is not advanced) instead of dropping or flooding
    import os
    os.environ["AVISHKAR_MAX_ACTIVE_JOBS"] = "0"
    try:
        assert e.runner.schedule_tick(now=T0) == 0
    finally:
        del os.environ["AVISHKAR_MAX_ACTIVE_JOBS"]
    assert e.runner.schedule_tick(now=T0 + 1) == 1
    e.runner.drain()
    # the branch disappears: the period is skipped and the schedule stays
    orig = fake.__class__.__call__

    def no_branches(self, req):
        if req.url.path.endswith("/branches"):
            return httpx.Response(200, json=[])
        return orig(self, req)
    fake.__class__.__call__ = no_branches
    try:
        assert e.runner.schedule_tick(now=T0 + 90000) == 0
    finally:
        fake.__class__.__call__ = orig
    assert any(a["action"] == "schedule_failed" for a in e.client.get("/v1/audit", headers=e.h).json()["items"])
    assert len(e.client.get("/v1/schedules", headers=e.h).json()["items"]) == 1
    # the installation is deactivated (uninstalled): the schedule is switched off
    e.store.deactivate_installation("777")
    e.runner.schedule_tick(now=T0 + 200000)
    assert e.client.get("/v1/schedules", headers=e.h).json()["items"] == [] and sid


def test_schedule_state_is_tenant_scoped(tmp_path, keypair):
    e, _, _ = env(tmp_path, keypair)
    sid = create(e).json()["id"]
    other = e.store.create_org("globex")
    e.add_user(other["id"], "root@globex.test", "admin")
    h = e.login("root@globex.test")
    assert e.client.get("/v1/schedules", headers=h).json()["items"] == []
    assert e.client.delete(f"/v1/schedules/{sid}", headers=h).status_code == 404
