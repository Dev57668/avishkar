"""Deterministic detectors. Each returns normalized RawFinding objects with redacted evidence.

These are built-in, dependency-free detectors. Semgrep/Gitleaks adapters can implement the
same `Detector` protocol (spec Appendix N) and be added to `config/score-v1.json` required set.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from ..domain.models import Confidence, Exposure, RawFinding, Severity

SUPPORT_MATRIX = {
    "python": {"status": "supported", "ext": [".py"]},
    "javascript/typescript": {"status": "supported", "ext": [".js", ".jsx", ".ts", ".tsx", ".mjs"]},
    "config/iac": {"status": "experimental", "ext": [".env", ".yml", ".yaml", ".json", ".tf", ".ini", ".cfg"]},
    "dependencies": {"status": "supported", "files": ["requirements.txt", "package.json"]},
    "other languages": {"status": "unsupported", "ext": []},
}

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"}
SECRET_EXT = CODE_EXT | {".env", ".yml", ".yaml", ".json", ".tf", ".ini", ".cfg", ".txt", ".sh", ".toml", ".properties"}


def redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * 6 + value[-2:]


# ---------------------------------------------------------------- secrets
SECRET_RULES = [
    ("SEC-AWS-KEY", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS access key id", Confidence.HIGH, 1),
    ("SEC-GH-TOKEN", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), "GitHub token", Confidence.HIGH, 1),
    ("SEC-SLACK", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "Slack token", Confidence.HIGH, 1),
    ("SEC-PRIVKEY", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"), "Private key block", Confidence.HIGH, 1),
    ("SEC-GENERIC", re.compile(
        r"""(?ix)\b(?:api[_-]?key|secret|passwd|password|token|auth)[\w-]*\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{12,})["']"""),
     "Hard-coded credential assignment", Confidence.MEDIUM, 1),
]
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[_-]|xxxx|<.*>|dummy|test)")


def detect_secrets(root: Path, files: list[Path]) -> list[RawFinding]:
    out = []
    for p in files:
        if p.suffix.lower() not in SECRET_EXT and p.name != ".env":
            continue
        rel = p.relative_to(root).as_posix()
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            for rule_id, rx, title, conf, grp in SECRET_RULES:
                m = rx.search(line)
                if not m:
                    continue
                val = m.group(grp)
                c = conf
                if PLACEHOLDER.search(val) or PLACEHOLDER.search(line.split("=")[-1] if "=" in line else ""):
                    c = Confidence.LOW
                out.append(RawFinding(
                    "secrets", rule_id, "secret",
                    Severity.CRITICAL if c == Confidence.HIGH else Severity.HIGH, c,
                    title, rel, n, f"{rule_id}:{redact(val)}",
                    Exposure.UNKNOWN,
                    "Revoke and rotate the credential, remove it from history, load it from a secret manager.",
                    "medium"))
                break
    return out


# ---------------------------------------------------------------- code patterns
# (rule_id, regex, extensions, severity, confidence, title, remediation, category)
PY, JS = {".py"}, {".js", ".jsx", ".ts", ".tsx", ".mjs"}
PATTERN_RULES = [
    ("PY-EVAL", re.compile(r"\b(?:eval|exec)\s*\("), PY, Severity.HIGH, Confidence.MEDIUM,
     "Dynamic code execution (eval/exec)", "Avoid eval/exec; use ast.literal_eval or explicit dispatch.", "injection"),
    ("PY-SHELL", re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\s*\("), PY, Severity.HIGH, Confidence.MEDIUM,
     "Shell command execution", "Pass an argument list with shell=False and validate inputs.", "injection"),
    ("PY-SQLI", re.compile(r"""\.execute\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format))"""), PY, Severity.HIGH, Confidence.MEDIUM,
     "SQL built by string formatting", "Use parameterized queries.", "injection"),
    ("PY-PICKLE", re.compile(r"\bpickle\.loads?\s*\("), PY, Severity.MEDIUM, Confidence.MEDIUM,
     "Unsafe deserialization (pickle)", "Use a safe format such as JSON for untrusted data.", "deserialization"),
    ("PY-YAML", re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)"), PY, Severity.MEDIUM, Confidence.MEDIUM,
     "yaml.load without SafeLoader", "Use yaml.safe_load.", "deserialization"),
    ("PY-WEAKHASH", re.compile(r"hashlib\.(?:md5|sha1)\s*\("), PY, Severity.LOW, Confidence.MEDIUM,
     "Weak hash algorithm", "Use SHA-256+ or a password KDF (argon2/bcrypt).", "crypto"),
    ("PY-NOVERIFY", re.compile(r"verify\s*=\s*False"), PY, Severity.MEDIUM, Confidence.HIGH,
     "TLS certificate verification disabled", "Remove verify=False.", "transport"),
    ("PY-DEBUG", re.compile(r"\bdebug\s*=\s*True\b"), PY, Severity.MEDIUM, Confidence.LOW,
     "Debug mode enabled", "Disable debug in deployed configuration.", "config"),
    ("JS-EVAL", re.compile(r"\beval\s*\(|new\s+Function\s*\("), JS, Severity.HIGH, Confidence.MEDIUM,
     "Dynamic code execution (eval)", "Avoid eval; parse data explicitly.", "injection"),
    ("JS-INNERHTML", re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML"), JS, Severity.MEDIUM, Confidence.MEDIUM,
     "Unsanitized HTML sink (XSS risk)", "Use textContent or sanitize with a vetted library.", "xss"),
    ("JS-CMDI", re.compile(r"child_process[\s\S]{0,80}\bexec\s*\(|\bexec(?:Sync)?\s*\(\s*[`\"'].*\$\{"), JS, Severity.HIGH, Confidence.MEDIUM,
     "Shell command built from input", "Use execFile with an argument array.", "injection"),
    ("JS-TLS", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"), JS, Severity.MEDIUM, Confidence.HIGH,
     "TLS certificate verification disabled", "Do not disable certificate validation.", "transport"),
    ("ANY-CORS", re.compile(r"""(?i)access-control-allow-origin["']?\s*[:,]\s*["']\*|allow_origins\s*=\s*\[\s*["']\*["']"""),
     PY | JS, Severity.MEDIUM, Confidence.MEDIUM, "Wildcard CORS origin", "Restrict allowed origins.", "config"),
]


def detect_patterns(root: Path, files: list[Path]) -> list[RawFinding]:
    out = []
    for p in files:
        ext = p.suffix.lower()
        if ext not in CODE_EXT:
            continue
        rel = p.relative_to(root).as_posix()
        text = p.read_text(errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith(("#", "//", "*")):
                continue
            for rule_id, rx, exts, sev, conf, title, fix, cat in PATTERN_RULES:
                if ext in exts and rx.search(line):
                    out.append(RawFinding("code-patterns", rule_id, cat, sev, conf, title, rel, n,
                                          s[:160], Exposure.UNKNOWN, fix, "small"))
    return out


# ---------------------------------------------------------------- dependencies
# Tiny embedded advisory sample. A production deployment should use a pinned vulnerability feed.
ADVISORIES = {
    ("pypi", "django"): [("<3.2", "DEP-DJANGO-OLD", Severity.HIGH, "Django < 3.2 is end-of-life with known CVEs")],
    ("pypi", "flask"): [("<2.0", "DEP-FLASK-OLD", Severity.MEDIUM, "Flask < 2.0 is outdated")],
    ("pypi", "pyyaml"): [("<5.4", "DEP-PYYAML", Severity.CRITICAL, "PyYAML < 5.4 arbitrary code execution (CVE-2020-14343)")],
    ("pypi", "requests"): [("<2.31", "DEP-REQUESTS", Severity.MEDIUM, "requests < 2.31 leaks Proxy-Authorization (CVE-2023-32681)")],
    ("npm", "lodash"): [("<4.17.21", "DEP-LODASH", Severity.HIGH, "lodash < 4.17.21 prototype pollution/command injection")],
    ("npm", "minimist"): [("<1.2.6", "DEP-MINIMIST", Severity.CRITICAL, "minimist < 1.2.6 prototype pollution (CVE-2021-44906)")],
    ("npm", "express"): [("<4.17.3", "DEP-EXPRESS", Severity.MEDIUM, "express < 4.17.3 qs vulnerability")],
}


def _ver(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s)[:4]) or (0,)


def _lt(version: str, bound: str) -> bool:
    a, b = _ver(version), _ver(bound)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def _check(eco: str, name: str, version: str | None, rel: str, line: int, out: list):
    for bound, rid, sev, title in ADVISORIES.get((eco, name.lower()), []):
        if version and _lt(version, bound.lstrip("<")):
            out.append(RawFinding("dependencies", rid, "dependency", sev, Confidence.HIGH,
                                  f"{title} (found {name} {version})", rel, line,
                                  f"{name}=={version}", Exposure.UNKNOWN,
                                  f"Upgrade {name} to >={bound.lstrip('<')}.", "small"))


def detect_dependencies(root: Path, files: list[Path]) -> list[RawFinding]:
    out = []
    names = {p.name for p in files}
    for p in files:
        rel = p.relative_to(root).as_posix()
        if p.name == "requirements.txt":
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                s = line.split("#")[0].strip()
                m = re.match(r"([A-Za-z0-9_.\-]+)\s*(==|>=|~=|<=|<|>)?\s*([\w.\-]+)?", s)
                if not s or s.startswith("-") or not m:
                    continue
                name, op, ver = m.groups()
                if op != "==":
                    out.append(RawFinding("dependencies", "DEP-UNPINNED", "dependency", Severity.LOW, Confidence.HIGH,
                                          f"Unpinned dependency {name}", rel, n, s, Exposure.UNKNOWN,
                                          "Pin exact versions and use hashes.", "small"))
                _check("pypi", name, ver if op in ("==", ">=", "~=") else None, rel, n, out)
        elif p.name == "package.json":
            try:
                data = json.loads(p.read_text(errors="replace"))
            except json.JSONDecodeError as e:
                raise ValueError(f"malformed {rel}: {e}") from e  # detector failure => incomplete scan
            for section in ("dependencies", "devDependencies"):
                for name, spec in (data.get(section) or {}).items():
                    _check("npm", name, re.sub(r"^[\^~>=<\s]+", "", str(spec)), rel, 1, out)
            if not ({"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} & names):
                out.append(RawFinding("dependencies", "DEP-NOLOCK", "dependency", Severity.LOW, Confidence.MEDIUM,
                                      "package.json without a lockfile", rel, 1, "missing lockfile",
                                      Exposure.UNKNOWN, "Commit a lockfile.", "small"))
    return out


Detector = Callable[[Path, list[Path]], list[RawFinding]]
DETECTORS: dict[str, Detector] = {
    "secrets": detect_secrets,
    "code-patterns": detect_patterns,
    "dependencies": detect_dependencies,
}
