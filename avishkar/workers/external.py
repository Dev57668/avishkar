"""Adapters for external scanners (Semgrep, Gitleaks). They run *inside the sandbox child* only.

Design rules (spec App. N):
* Pinned local rule pack, no network: `--config auto` is never used.
* A missing binary, non-zero crash, timeout or unparsable output raises -> the required detector fails ->
  the run is *incomplete*, never clean.
* Gitleaks is run with --redact so a full secret never leaves the tool; output is redacted again regardless.
* Severity/confidence come from the scanner rule + a static mapping here (versioned in code review), never a model.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text

RULES_PATH = Path(os.environ.get("AVISHKAR_SEMGREP_RULES", Path(__file__).resolve().parents[2] / "infra" / "semgrep-rules.yml"))
TOOL_TIMEOUT = int(os.environ.get("AVISHKAR_TOOL_TIMEOUT", "100"))


class ScannerUnavailable(Exception):
    pass


class ScannerFailed(Exception):
    pass


def _exe(name: str, env_var: str) -> str:
    cand = os.environ.get(env_var) or shutil.which(name)
    if not cand:
        raise ScannerUnavailable(f"{name} is not installed (set {env_var} or add it to PATH)")
    return cand


def _run(cmd: list[str], ok_codes: tuple[int, ...]) -> subprocess.CompletedProcess:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        raise ScannerFailed(f"{Path(cmd[0]).name} timed out after {TOOL_TIMEOUT}s") from e
    except OSError as e:
        raise ScannerUnavailable(f"cannot execute {cmd[0]}: {e}") from e
    if p.returncode not in ok_codes:
        raise ScannerFailed(f"{Path(cmd[0]).name} exited {p.returncode}: {(p.stderr or '')[-200:].strip()}")
    return p


# ------------------------------------------------------------------ Semgrep
SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
CONFIDENCE = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}


def parse_semgrep(out: str, root: Path) -> list[RawFinding]:
    try:
        data = json.loads(out)
        results = data["results"]
    except (ValueError, KeyError, TypeError) as e:
        raise ScannerFailed(f"unparsable semgrep output: {type(e).__name__}") from e
    if not isinstance(results, list):
        raise ScannerFailed("semgrep results is not a list")
    found = []
    for r in results:
        try:
            meta = (r.get("extra") or {}).get("metadata") or {}
            path = Path(r["path"])
            try:
                rel = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = path.as_posix()
            line = int(r["start"]["line"])
            snippet = ""
            try:
                snippet = (root / rel).read_text(errors="replace").splitlines()[line - 1].strip()
            except Exception:
                snippet = str((r.get("extra") or {}).get("lines", ""))[:160]
            rid = "SG:" + str(r["check_id"]).rsplit(".", 1)[-1]
            sev = SEMGREP_SEVERITY.get(str((r.get("extra") or {}).get("severity", "INFO")).upper(), Severity.LOW)
            conf = CONFIDENCE.get(str(meta.get("confidence", "MEDIUM")).upper(), Confidence.MEDIUM)
            found.append(RawFinding("semgrep", rid, str(meta.get("category", "sast")), sev, conf,
                                    str((r.get("extra") or {}).get("message", rid))[:200], rel, line,
                                    redact_text(snippet)[:160], Exposure.UNKNOWN,
                                    "See rule message; fix the flagged construct.", "small"))
        except (KeyError, TypeError, ValueError) as e:
            raise ScannerFailed(f"malformed semgrep result: {type(e).__name__}") from e
    return found


def detect_semgrep(root: Path, files: list[Path]) -> list[RawFinding]:
    exe = _exe("semgrep", "SEMGREP_PATH")
    if not RULES_PATH.exists():
        raise ScannerUnavailable(f"semgrep rule pack missing: {RULES_PATH}")
    p = _run([exe, "--config", str(RULES_PATH), "--json", "--quiet", "--metrics", "off", "--disable-version-check",
              "--timeout", "20", str(root)], ok_codes=(0, 1))
    return parse_semgrep(p.stdout, root)


# ------------------------------------------------------------------ Gitleaks
GENERIC_RULES = re.compile(r"(?i)generic|high-entropy")


def parse_gitleaks(report: str, root: Path) -> list[RawFinding]:
    try:
        items = json.loads(report) if report.strip() else []
    except ValueError as e:
        raise ScannerFailed("unparsable gitleaks report") from e
    if items is None:
        items = []
    if not isinstance(items, list):
        raise ScannerFailed("gitleaks report is not a list")
    found = []
    for it in items:
        try:
            rule = str(it["RuleID"])
            path = Path(str(it["File"]))
            try:
                rel = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = path.as_posix()
            conf = Confidence.MEDIUM if GENERIC_RULES.search(rule) else Confidence.HIGH
            # `Match`/`Secret` are redacted by --redact; redact_text is a second barrier.
            ev = redact_text(f"GL:{rule}:{str(it.get('Match', ''))[:80]}")
            found.append(RawFinding("gitleaks", "GL:" + rule, "secret",
                                    Severity.CRITICAL if conf == Confidence.HIGH else Severity.HIGH, conf,
                                    str(it.get("Description", rule))[:200], rel, int(it.get("StartLine", 0)), ev,
                                    Exposure.UNKNOWN,
                                    "Revoke and rotate the credential, purge it from history, use a secret manager.",
                                    "medium"))
        except (KeyError, TypeError, ValueError) as e:
            raise ScannerFailed(f"malformed gitleaks item: {type(e).__name__}") from e
    return found


def detect_gitleaks(root: Path, files: list[Path]) -> list[RawFinding]:
    exe = _exe("gitleaks", "GITLEAKS_PATH")
    with tempfile.TemporaryDirectory(prefix="avk-gl-") as td:
        rep = Path(td) / "report.json"
        # exit 1 = leaks found (not an error); 0 = clean. Anything else is a failure.
        _run([exe, "detect", "--source", str(root), "--no-git", "--redact", "--report-format", "json",
              "--report-path", str(rep), "--no-banner"], ok_codes=(0, 1))
        if not rep.exists():
            raise ScannerFailed("gitleaks produced no report")
        return parse_gitleaks(rep.read_text(errors="replace"), root)


EXTERNAL_DETECTORS = {"semgrep": detect_semgrep, "gitleaks": detect_gitleaks}
