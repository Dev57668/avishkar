import subprocess
import sys
import time
import types

import pytest

import avishkar.workers.sandbox as sbx_mod
from avishkar.domain.policy import Policy
from avishkar.domain.scoring import ScoreConfig
from avishkar.workers.pipeline import assemble
from avishkar.workers.sandbox import Sandbox, SandboxError, _scrubbed_env

from .conftest import FIX, zip_dir

CFG = ScoreConfig.load()
REQ = CFG.required_detectors


def test_inline_refused_without_explicit_flag(monkeypatch):
    monkeypatch.delenv("AVISHKAR_ALLOW_INLINE", raising=False)
    with pytest.raises(SandboxError):
        Sandbox("inline")


def test_docker_mode_requires_docker_installed(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(SandboxError):
        Sandbox("docker")


def test_process_sandbox_matches_inline_results(tmp_path, monkeypatch):
    monkeypatch.setenv("AVISHKAR_ALLOW_INLINE", "1")
    z = tmp_path / "s.zip"
    z.write_bytes(zip_dir(FIX / "insecure"))
    a = Sandbox("process").collect(REQ, zip_path=z)
    b = Sandbox("inline").collect(REQ, zip_path=z)
    assert a["failed"] == {} and a["raw"] == b["raw"] and a["files"] == b["files"]
    assert assemble(CFG, Policy.load(), a)["securityDebt"]["rawUnits"] == 37.0


def test_child_environment_has_no_credentials(monkeypatch):
    for k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_APP_PRIVATE_KEY", "ANTHROPIC_API_KEY", "AVISHKAR_SECRET_KEY",
              "DATABASE_URL", "GITHUB_WEBHOOK_SECRET"):
        monkeypatch.setenv(k, "topsecret")
    env = _scrubbed_env()
    assert "topsecret" not in str(env) and "DATABASE_URL" not in env


def test_timeout_kills_worker_and_is_incomplete(tmp_path, monkeypatch):
    z = tmp_path / "s.zip"
    z.write_bytes(zip_dir(FIX / "secure"))
    real = subprocess.Popen

    def sleeper(cmd, **kw):  # swap the child for a sleeper to force the timeout path
        return real([sys.executable, "-c", "import time;time.sleep(30)"],
                    **{k: v for k, v in kw.items() if k in ("stdout", "stderr")})

    shim = types.SimpleNamespace(**{k: getattr(subprocess, k) for k in dir(subprocess) if not k.startswith("__")})
    shim.Popen = sleeper  # only the sandbox module sees the sleeper; taskkill via subprocess.run stays real
    monkeypatch.setattr(sbx_mod, "subprocess", shim)
    t0 = time.time()
    res = Sandbox("process", timeout=1).collect(REQ, zip_path=z)
    assert time.time() - t0 < 20
    assert set(res["failed"]) == set(REQ) and "timed out" in str(res["failed"])
    out = assemble(CFG, Policy.load(), res)
    assert out["status"] == "incomplete" and out["decision"]["outcome"] == "not_evaluated"


def test_unreadable_archive_is_incomplete_not_clean(tmp_path):
    z = tmp_path / "bad.zip"
    z.write_bytes(b"this is not a zip")
    res = Sandbox("process").collect(REQ, zip_path=z)
    assert res["failed"]
    assert assemble(CFG, Policy.load(), res)["status"] == "incomplete"


def test_malformed_worker_output_is_rejected_by_assemble():
    bad = {"raw": [{"detector_id": "x", "rule_id": "r", "category": "c", "severity": "catastrophic",
                    "confidence": "high", "title": "t", "path": "p", "line": 1, "evidence": "e"}],
           "completed": list(REQ), "failed": {}, "stages": {}, "files": 1, "notes": []}
    out = assemble(CFG, Policy.load(), bad)
    assert out["status"] == "incomplete" and out["securityDebt"]["rawUnits"] is None


def test_docker_command_hardening(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")
    s = Sandbox("docker", memory_mb=256, cpus=0.5, image="avishkar-worker@sha256:abc")
    cmd = s._docker_cmd(tmp_path / "out", None, tmp_path / "in.zip", ["--required", "secrets"])
    joined = " ".join(cmd)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--pids-limit",
                 "--memory 256m", "--cpus 0.5", "--user 65534:65534"):
        assert flag in joined
    assert ":/in/source.zip:ro" in joined and "privileged" not in joined
    assert s.describe()["isolationBoundary"] is True and Sandbox("process").describe()["isolationBoundary"] is False
