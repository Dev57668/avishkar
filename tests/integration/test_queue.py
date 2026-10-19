from avishkar.workers import runner as runner_mod

from .conftest import FIX, Env, zip_dir


def test_idempotency_key_dedupes(env):
    h = {**env.h, "Idempotency-Key": "k1"}
    a = env.scan("r/a", zip_dir(FIX / "secure"), headers=h, drain=False).json()
    b = env.scan("r/a", zip_dir(FIX / "secure"), headers=h, drain=False).json()
    assert a["jobId"] == b["jobId"] and b["deduplicated"] is True
    assert len(env.store.jobs(env.org["id"])) == 1
    assert len(list(runner_mod.SPOOL_DIR.glob("*.zip"))) == 1  # duplicate upload not spooled


def test_quota_rejects_when_too_many_active(tmp_path):
    e = Env(tmp_path, max_active_jobs=2)
    assert e.scan("r/1", zip_dir(FIX / "secure"), drain=False).status_code == 202
    assert e.scan("r/2", zip_dir(FIX / "secure"), drain=False).status_code == 202
    r = e.scan("r/3", zip_dir(FIX / "secure"), drain=False)
    assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limited"
    assert len(list(runner_mod.SPOOL_DIR.glob("*.zip"))) == 2  # rejected upload cleaned up
    e.runner.drain()
    assert e.scan("r/3", zip_dir(FIX / "secure"), drain=False).status_code == 202


def test_retry_then_dead_letter_yields_incomplete_run(env, monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise OSError("disk exploded")

    monkeypatch.setattr(env.sandbox, "collect", boom)
    q = env.scan("r/x", zip_dir(FIX / "secure"), drain=False).json()
    assert env.runner.drain() == 3 and len(calls) == 3  # max_attempts
    job = env.store.job(q["jobId"])
    assert job["status"] == "dead" and "disk exploded" in job["error"]
    run = env.client.get(f"/v1/repositories/{q['repositoryId']}/analyses/{q['runId']}", headers=env.h).json()
    assert run["status"] == "incomplete" and run["decision"]["outcome"] == "not_evaluated"
    assert not list(runner_mod.SPOOL_DIR.glob("*.zip"))
    assert env.client.post(f"/v1/jobs/{q['jobId']}/requeue", headers=env.h).status_code == 200


def test_transient_failure_retries_and_succeeds(env, monkeypatch):
    real, n = env.sandbox.collect, {"n": 0}

    def flaky(*a, **k):
        n["n"] += 1
        if n["n"] == 1:
            raise OSError("transient")
        return real(*a, **k)

    monkeypatch.setattr(env.sandbox, "collect", flaky)
    q = env.scan("r/y", zip_dir(FIX / "secure"), drain=False).json()
    env.runner.drain()
    job = env.store.job(q["jobId"])
    assert job["status"] == "done" and job["attempts"] == 2
    run = env.client.get(f"/v1/repositories/{q['repositoryId']}/analyses/{q['runId']}", headers=env.h).json()
    assert run["status"] == "complete"


def test_expired_lease_is_reclaimed(env):
    q = env.scan("r/z", zip_dir(FIX / "secure"), drain=False).json()
    j = env.store.claim("dead-worker", lease_seconds=-1)  # worker crashed holding an expired lease
    assert j["status"] == "running"
    assert env.store.reclaim_expired() == 1
    assert env.store.job(q["jobId"])["status"] == "queued"
    env.runner.drain()
    assert env.store.job(q["jobId"])["status"] == "done"


def test_claim_is_exclusive(env):
    env.scan("r/one", zip_dir(FIX / "secure"), drain=False)
    assert env.store.claim("w1") and env.store.claim("w2") is None


def test_fair_claim_prefers_org_with_fewer_running(env):
    other = env.store.create_org("globex")
    env.store.enqueue(env.org["id"], "r", "run1", "archive", {}, None)
    env.store.enqueue(env.org["id"], "r", "run2", "archive", {}, None)
    env.store.enqueue(other["id"], "r2", "run3", "archive", {}, None)
    first, second = env.store.claim("w"), env.store.claim("w")
    assert first["organization_id"] == env.org["id"] and second["organization_id"] == other["id"]


def test_dead_jobs_visible_to_operators_without_payload(env, monkeypatch):
    monkeypatch.setattr(env.sandbox, "collect", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    env.scan("r/q", zip_dir(FIX / "secure"), drain=True)
    dead = env.client.get("/v1/jobs?status=dead", headers=env.h).json()["items"]
    assert len(dead) == 1 and "payload" not in dead[0]
