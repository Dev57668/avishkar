"""Real Docker sandbox checks. Skipped unless AVISHKAR_DOCKER_TESTS=1 and `docker` exists (see CI job docker-sandbox).
These are the tests that actually prove the isolation properties the unit tests only describe."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from avishkar.domain.policy import Policy
from avishkar.domain.scoring import ScoreConfig
from avishkar.workers.pipeline import assemble
from avishkar.workers.sandbox import Sandbox

from .conftest import FIX, zip_dir

pytestmark = pytest.mark.skipif(os.environ.get("AVISHKAR_DOCKER_TESTS") != "1" or not shutil.which("docker"),
                                reason="docker sandbox tests are opt-in (AVISHKAR_DOCKER_TESTS=1, docker installed)")
IMAGE = os.environ.get("AVISHKAR_WORKER_IMAGE", "avishkar-worker:latest")
FULL = ScoreConfig.load(Path(__file__).resolve().parents[2] / "config" / "profiles" / "full.json")


def docker_run(*args, entrypoint="python"):
    return subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                           "--security-opt", "no-new-privileges", "--user", "65534:65534", "--tmpfs", "/tmp",
                           "--entrypoint", entrypoint, IMAGE, *args], capture_output=True, text=True, timeout=120)


def test_scan_in_container_matches_inline(tmp_path, monkeypatch):
    monkeypatch.setenv("AVISHKAR_ALLOW_INLINE", "1")
    z = tmp_path / "s.zip"
    z.write_bytes(zip_dir(FIX / "insecure"))
    cfg = ScoreConfig.load()
    a = Sandbox("docker", image=IMAGE).collect(cfg.required_detectors, zip_path=z)
    b = Sandbox("inline").collect(cfg.required_detectors, zip_path=z)
    assert a["failed"] == {} and a["raw"] == b["raw"]


def test_container_has_no_network():
    r = docker_run("-c", "import socket,sys\ntry:\n socket.create_connection(('1.1.1.1',53),3)\n print('REACHED')\nexcept OSError:\n print('BLOCKED')")
    assert "BLOCKED" in r.stdout, r.stdout + r.stderr


def test_container_is_readonly_nonroot_and_capless():
    r = docker_run("-c", "import os\ntry:\n open('/app/x','w')\n print('WROTE')\nexcept OSError:\n print('RO')\nprint(os.getuid())")
    assert "RO" in r.stdout and r.stdout.strip().endswith("65534"), r.stdout + r.stderr
    caps = docker_run("-c", "print(open('/proc/self/status').read())").stdout
    assert "CapEff:\t0000000000000000" in caps


def test_container_has_no_host_secrets(monkeypatch):
    monkeypatch.setenv("AVISHKAR_SECRET_KEY", "topsecret-host-value")
    assert "topsecret-host-value" not in docker_run("-c", "import os;print(dict(os.environ))").stdout


def test_oom_is_incomplete_not_clean(tmp_path):
    z = tmp_path / "s.zip"
    z.write_bytes(zip_dir(FIX / "secure"))
    res = Sandbox("docker", image=IMAGE, memory_mb=6, timeout=60).collect(ScoreConfig.load().required_detectors, zip_path=z)
    out = assemble(ScoreConfig.load(), Policy.load(), res)
    assert out["status"] == "incomplete" and out["decision"]["outcome"] == "not_evaluated"


def test_full_profile_runs_semgrep_and_gitleaks_in_container(tmp_path):
    z = tmp_path / "s.zip"
    z.write_bytes(zip_dir(FIX / "insecure"))
    res = Sandbox("docker", image=IMAGE, timeout=110).collect(FULL.required_detectors, zip_path=z)
    assert res["failed"] == {}, res["failed"]
    out = assemble(FULL, Policy.load(), res)
    assert out["status"] == "complete" and {"semgrep", "gitleaks"} <= set(res["completed"])
    assert any(f.raw.detector_id == "semgrep" for f in out["findings"])  # shell=True in the fixture
    assert any(f.raw.category == "secret" for f in out["findings"])
