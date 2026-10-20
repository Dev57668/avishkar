"""Isolation boundary for untrusted repository content (spec SEC-002, Appendix N).

Modes (env AVISHKAR_SANDBOX):
  docker  - `docker run` with no network, read-only rootfs, all caps dropped, non-root, pids/memory/cpu limits,
            source mounted read-only. REQUIRED for production. Needs Docker and the image from
            infra/Dockerfile.worker (AVISHKAR_WORKER_IMAGE).
  process - child Python process (`-I`), scrubbed environment (no credentials), empty cwd, wall-clock timeout
            with process-tree kill, and on POSIX RLIMIT_AS/CPU/NPROC/FSIZE. NOT a security boundary against a
            hostile repo exploiting the interpreter; suitable for development and trusted code only.
  inline  - same process, no isolation. Tests only; refused unless AVISHKAR_ALLOW_INLINE=1.

Any sandbox failure (crash, timeout, OOM, bad JSON) returns an *incomplete* collection, never a clean one.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .pipeline import collect_findings, failed_collection

PKG_PARENT = Path(__file__).resolve().parents[2]
MAX_OUTPUT_BYTES = 20_000_000


class SandboxError(Exception):
    pass


def _scrubbed_env() -> dict:
    keep = {"SYSTEMROOT", "PATH", "TEMP", "TMP", "LANG", "SEMGREP_PATH", "GITLEAKS_PATH",
            "AVISHKAR_SEMGREP_RULES", "AVISHKAR_TOOL_TIMEOUT"}  # tool locations only; never credentials  # SYSTEMROOT/PATH needed for Python on Windows
    env = {k: v for k, v in os.environ.items() if k.upper() in keep}
    env["PYTHONPATH"] = str(PKG_PARENT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _limits(mem_bytes: int, cpu_s: int):
    def apply():  # POSIX only; runs in the child before exec
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_FSIZE, (200_000_000, 200_000_000))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        os.setsid()
    return apply


def _kill_tree(p: subprocess.Popen):
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
        else:
            import signal
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except Exception:
        p.kill()


class Sandbox:
    def __init__(self, mode: str | None = None, timeout: int = 120, memory_mb: int = 512, cpus: float = 1.0,
                 image: str | None = None):
        self.mode = mode or os.environ.get("AVISHKAR_SANDBOX", "process")
        if self.mode not in ("docker", "process", "inline"):
            raise ValueError(f"unknown sandbox mode {self.mode}")
        if self.mode == "inline" and os.environ.get("AVISHKAR_ALLOW_INLINE") != "1":
            raise SandboxError("inline sandbox is disabled; set AVISHKAR_ALLOW_INLINE=1 (tests only)")
        if self.mode == "docker" and not shutil.which("docker"):
            raise SandboxError("docker sandbox selected but docker is not installed")
        self.timeout, self.memory_mb, self.cpus = timeout, memory_mb, cpus
        self.image = image or os.environ.get("AVISHKAR_WORKER_IMAGE", "avishkar-worker:latest")
        self.detectors = None  # test hook for inline mode

    def describe(self) -> dict:
        return {"mode": self.mode, "timeoutSeconds": self.timeout, "memoryMb": self.memory_mb,
                "network": "none" if self.mode == "docker" else "host (not isolated)",
                "isolationBoundary": self.mode == "docker"}

    # ---------------------------------------------------------------- public
    def collect(self, required, source_dir: Path | None = None, zip_path: Path | None = None) -> dict:
        try:
            if self.mode == "inline":
                return collect_findings(tuple(required), source_dir=source_dir, zip_path=zip_path,
                                        detectors=self.detectors)
            return self._run(required, source_dir, zip_path)
        except SandboxError as e:
            return failed_collection(required, f"sandbox failure: {e}")

    # ---------------------------------------------------------------- impl
    def _run(self, required, source_dir, zip_path) -> dict:
        work = Path(tempfile.mkdtemp(prefix="avishkar-sbx-"))
        source_dir = source_dir.resolve() if source_dir else None
        zip_path = zip_path.resolve() if zip_path else None
        try:
            out = work / "out"
            out.mkdir()
            args = ["--required", ",".join(required)]
            if self.mode == "docker":
                cmd = self._docker_cmd(out, source_dir, zip_path, args)
                popen_kw = {}
            else:
                # -I ignores PYTHONPATH, so the package root is inserted explicitly (it is our own trusted code).
                boot = "import sys;sys.path.insert(0,sys.argv.pop(1));from avishkar.workers.sandbox_child import main;raise SystemExit(main())"
                cmd = [sys.executable, "-I", "-c", boot, str(PKG_PARENT), "--out", str(out / "result.json")]
                cmd += args + (["--zip", str(zip_path)] if zip_path else ["--dir", str(source_dir)])
                popen_kw = {"env": _scrubbed_env(), "cwd": str(work)}
                if os.name != "nt":
                    popen_kw["preexec_fn"] = _limits(self.memory_mb * 1024 * 1024 * 4, self.timeout)
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_kw)
            except OSError as e:
                raise SandboxError(f"cannot start sandbox: {e}")
            try:
                _, err = p.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                _kill_tree(p)
                p.communicate()
                raise SandboxError(f"timed out after {self.timeout}s")
            res = out / "result.json"
            if p.returncode != 0 or not res.exists():
                tail = (err or b"").decode(errors="replace")[-200:].replace("\n", " ")
                raise SandboxError(f"worker exited {p.returncode}: {tail}")
            if res.stat().st_size > MAX_OUTPUT_BYTES:
                raise SandboxError("worker output too large")
            try:
                data = json.loads(res.read_text())
                assert isinstance(data, dict) and {"raw", "completed", "failed", "stages", "files", "notes"} <= set(data)
            except Exception:
                raise SandboxError("worker produced malformed output")
            return data
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _docker_cmd(self, out: Path, source_dir, zip_path, args) -> list[str]:
        cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--pids-limit", "128",
               "--memory", f"{self.memory_mb}m", "--cpus", str(self.cpus), "--user", "65534:65534",
               "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
               "-v", f"{out}:/out:rw"]
        if zip_path:
            cmd += ["-v", f"{zip_path}:/in/source.zip:ro", self.image, "--zip", "/in/source.zip"]
        else:
            cmd += ["-v", f"{source_dir}:/in/src:ro", self.image, "--dir", "/in/src"]
        return cmd + ["--out", "/out/result.json"] + args
