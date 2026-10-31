"""Known-vulnerability lookups for dependencies, in the TRUSTED stage (never inside the scan sandbox).

Source: OSV.dev (https://osv.dev), an open vulnerability database that aggregates GitHub advisories, PyPI, Go, RustSec and
others. Enabled with AVISHKAR_VULN_FEED=osv; without it the small built-in advisory list is used instead.

Honest behaviour:
  * A failed lookup (network error, timeout, bad response) raises VulnLookupError and the caller marks the dependency check
    INCOMPLETE. A dependency scan that could not ask the database is never reported as "no vulnerabilities".
  * A match means "this exact version is listed in an advisory". It does not prove the vulnerable code path is reachable.
  * Only exact versions are queried. A range's lower bound ("^1.2.3") is queried too but reported at lower confidence.
  * Dependency records come from the sandbox (untrusted) and are re-validated here before they are sent anywhere. Only
    ecosystem, package name and version leave the server, never source code or file contents.
"""
from __future__ import annotations

import os
import re
import time

import httpx

from ..domain.models import Confidence, Exposure, RawFinding, Severity

API = "https://api.osv.dev"
ECOSYSTEMS = {"PyPI", "npm", "Maven", "Go", "NuGet", "Packagist", "RubyGems"}
NAME_OK = re.compile(r"^[A-Za-z0-9_.@/:+\-~]{1,214}$")
VER_OK = re.compile(r"^\d[A-Za-z0-9_.+\-~]{0,63}$")
ID_OK = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
BATCH = 100
MAX_DEPS = 1000
MAX_DETAILS = 80
MAX_FINDINGS = 150
DEADLINE_S = 60
SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
       "LOW": Severity.LOW}


class VulnLookupError(Exception):
    pass


def valid_dep(d) -> bool:
    return bool(isinstance(d, dict) and d.get("eco") in ECOSYSTEMS and isinstance(d.get("name"), str) and NAME_OK.match(d["name"])
                and isinstance(d.get("version"), str) and VER_OK.match(d["version"]) and isinstance(d.get("path"), str)
                and isinstance(d.get("line"), int))


def builtin_advisory_ids() -> set[str]:
    from ..workers.detectors import ADVISORIES
    return {row[1] for rows in ADVISORIES.values() for row in rows}


class OsvClient:
    def __init__(self, base: str = API, transport: httpx.BaseTransport | None = None, timeout: float = 15):
        self.base = base.rstrip("/")
        self._http = httpx.Client(transport=transport, timeout=timeout)
        self._details: dict[str, dict] = {}

    def _post(self, path: str, body: dict) -> dict:
        try:
            r = self._http.post(self.base + path, json=body)
            if r.status_code != 200:
                raise VulnLookupError(f"OSV returned HTTP {r.status_code}")
            data = r.json()
        except httpx.HTTPError as e:
            raise VulnLookupError(f"OSV unreachable ({type(e).__name__})") from None
        except ValueError:
            raise VulnLookupError("OSV returned invalid JSON") from None
        if not isinstance(data, dict):
            raise VulnLookupError("OSV returned an unexpected response")
        return data

    def _detail(self, vid: str) -> dict:
        if vid in self._details:
            return self._details[vid]
        try:
            r = self._http.get(f"{self.base}/v1/vulns/{vid}")
            if r.status_code != 200:
                raise VulnLookupError(f"OSV returned HTTP {r.status_code} for {vid}")
            data = r.json()
        except httpx.HTTPError as e:
            raise VulnLookupError(f"OSV unreachable ({type(e).__name__})") from None
        except ValueError:
            raise VulnLookupError("OSV returned invalid JSON") from None
        if not isinstance(data, dict):
            raise VulnLookupError("OSV returned an unexpected response")
        if len(self._details) > 2000:
            self._details.clear()
        self._details[vid] = data
        return data

    def lookup(self, deps: list[dict]) -> list[dict]:
        """RawFinding dicts for every (dependency, advisory) pair. Raises VulnLookupError on any failure."""
        t0 = time.time()
        deps = [d for d in deps if valid_dep(d)][:MAX_DEPS]
        if not deps:
            return []
        hits: list[tuple[dict, str]] = []
        for i in range(0, len(deps), BATCH):
            chunk = deps[i:i + BATCH]
            res = self._post("/v1/querybatch", {"queries": [{"package": {"name": d["name"], "ecosystem": d["eco"]}, "version": d["version"]}
                                                            for d in chunk]}).get("results")
            if not isinstance(res, list) or len(res) != len(chunk):
                raise VulnLookupError("OSV returned a result list that does not match the query")
            for d, r in zip(chunk, res):
                for v in (r or {}).get("vulns", []) if isinstance(r, dict) else []:
                    if isinstance(v, dict) and isinstance(v.get("id"), str) and ID_OK.match(v["id"]):
                        hits.append((d, v["id"]))
            if time.time() - t0 > DEADLINE_S:
                raise VulnLookupError("vulnerability lookup took too long")
        ids = list(dict.fromkeys(vid for _, vid in hits))[:MAX_DETAILS]
        details = {}
        for vid in ids:
            details[vid] = self._detail(vid)
            if time.time() - t0 > DEADLINE_S:
                raise VulnLookupError("vulnerability lookup took too long")
        out = []
        for d, vid in hits:
            if vid not in details:
                continue
            out.append(self._finding(d, vid, details[vid]).to_dict())
            if len(out) >= MAX_FINDINGS:
                break
        return out

    @staticmethod
    def _fixed(detail: dict, name: str) -> str | None:
        for a in detail.get("affected", []) if isinstance(detail.get("affected"), list) else []:
            if not isinstance(a, dict) or (a.get("package") or {}).get("name", "").lower() != name.lower():
                continue
            for rng in a.get("ranges", []) or []:
                for ev in (rng.get("events") or []) if isinstance(rng, dict) else []:
                    if isinstance(ev, dict) and isinstance(ev.get("fixed"), str) and VER_OK.match(ev["fixed"]):
                        return ev["fixed"]
        return None

    def _finding(self, d: dict, vid: str, detail: dict) -> RawFinding:
        spec = (detail.get("database_specific") or {}) if isinstance(detail.get("database_specific"), dict) else {}
        sev = SEV.get(str(spec.get("severity", "")).upper(), Severity.MEDIUM)
        summary = re.sub(r"\s+", " ", str(detail.get("summary") or detail.get("details") or "known vulnerability"))[:90]
        aliases = [a for a in (detail.get("aliases") or []) if isinstance(a, str) and ID_OK.match(a)][:3]
        fixed = self._fixed(detail, d["name"])
        fix = f"Upgrade {d['name']} to {fixed} or later." if fixed else f"Upgrade {d['name']} to a version not listed in {vid}."
        title = f"{d['name']} {d['version']}: {vid} ({summary})"
        evidence = f"{d['name']}=={d['version']} {vid}" + (f" {' '.join(aliases)}" if aliases else "")
        return RawFinding("dependencies", "DEP-VULN", "dependency", sev, Confidence.HIGH if d.get("exact", True) else Confidence.MEDIUM,
                          title, d["path"], d["line"], evidence, Exposure.UNKNOWN, fix, "small")


_default: OsvClient | None = None


def default_source() -> OsvClient | None:
    """The configured source, or None (built-in list only). Read from the environment on every call, so tests can toggle it."""
    global _default
    if os.environ.get("AVISHKAR_VULN_FEED", "").lower() != "osv":
        return None
    if _default is None:
        _default = OsvClient()
    return _default
