"""Dependency manifest parsing (runs in the sandbox, so it treats every file as untrusted and never raises on bad input).

Each parser returns dependency records {"eco", "name", "version", "exact", "path", "line"} using OSV ecosystem names
(PyPI, npm, Maven, Go, NuGet, Packagist, RubyGems). `exact` is False when the version is only the lower bound of a range
(package.json "^1.2.3"), because an advisory match on a lower bound is weaker evidence than on a pinned version.

The lookup against a vulnerability database happens later, in the trusted stage (`avishkar.adapters.vulns`): the sandbox may
have no network at all, and nothing parsed here is trusted until it is validated again there.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

MAX_DEPS = 2000
NAME_OK = re.compile(r"^[A-Za-z0-9_.@/:+\-~]{1,214}$")
VER_OK = re.compile(r"^[A-Za-z0-9_.+\-~]{1,64}$")


def _dep(eco: str, name: str, version: str, exact: bool, path: str, line: int) -> dict | None:
    name, version = name.strip(), version.strip().lstrip("vV=") if eco != "Go" else version.strip()
    if eco == "Go":
        version = version.lstrip("v")
    if not NAME_OK.match(name) or not VER_OK.match(version) or not re.match(r"^\d", version):
        return None
    return {"eco": eco, "name": name, "version": version, "exact": exact, "path": path, "line": line}


def _requirements(text: str, rel: str) -> list[dict]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.\-+]+)\s*(?:;.*)?$", s)
        if m:
            d = _dep("PyPI", m.group(1).lower().replace("_", "-"), m.group(2), True, rel, n)
            if d:
                out.append(d)
    return out


def _package_json(text: str, rel: str) -> list[dict]:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) if isinstance(data, dict) else None
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            m = re.match(r"^\s*([\^~]|>=)?\s*v?(\d+\.\d+\.\d+(?:[-+][\w.\-]+)?)\s*$", str(spec))
            if m:
                d = _dep("npm", str(name), m.group(2), m.group(1) is None, rel, 1)
                if d:
                    out.append(d)
    return out


def _package_lock(text: str, rel: str) -> list[dict]:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    out = []
    pk = data.get("packages") if isinstance(data, dict) else None
    if isinstance(pk, dict):
        for key, info in pk.items():
            if not key.startswith("node_modules/") or not isinstance(info, dict) or info.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[1]
            d = _dep("npm", name, str(info.get("version", "")), True, rel, 1)
            if d:
                out.append(d)
    elif isinstance(data, dict) and isinstance(data.get("dependencies"), dict):  # lockfile v1
        stack = [data["dependencies"]]
        while stack and len(out) < MAX_DEPS:
            for name, info in stack.pop().items():
                if isinstance(info, dict):
                    d = _dep("npm", str(name), str(info.get("version", "")), True, rel, 1)
                    if d:
                        out.append(d)
                    if isinstance(info.get("dependencies"), dict):
                        stack.append(info["dependencies"])
    return out


def _pom(text: str, rel: str) -> list[dict]:
    out = []
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        block = m.group(1)
        g, a, v = (re.search(rf"<{t}>\s*([^<]+?)\s*</{t}>", block) for t in ("groupId", "artifactId", "version"))
        if g and a and v and "${" not in v.group(1) and "${" not in g.group(1):
            line = text.count("\n", 0, m.start()) + 1
            d = _dep("Maven", f"{g.group(1)}:{a.group(1)}", v.group(1), True, rel, line)
            if d:
                out.append(d)
    return out


def _gradle(text: str, rel: str) -> list[dict]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for m in re.finditer(r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*\(?\s*['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]""", line):
            d = _dep("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), True, rel, n)
            if d:
                out.append(d)
    return out


def _go_mod(text: str, rel: str) -> list[dict]:
    out, in_block = [], False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.split("//")[0].strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-/~]+)\s+(v\d[\w.\-+]*)$", s) if (in_block or s.startswith("require ")) else None
        if m:
            d = _dep("Go", m.group(1), m.group(2), True, rel, n)
            if d:
                out.append(d)
    return out


def _csproj(text: str, rel: str) -> list[dict]:
    out = []
    for m in re.finditer(r'<PackageReference\s+[^>]*?Include="([^"]+)"[^>]*?Version="([^"$]+)"', text):
        d = _dep("NuGet", m.group(1), m.group(2), True, rel, text.count("\n", 0, m.start()) + 1)
        if d:
            out.append(d)
    return out


def _composer_lock(text: str, rel: str) -> list[dict]:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    out = []
    for section in ("packages", "packages-dev"):
        for p in (data.get(section) or []) if isinstance(data, dict) else []:
            if isinstance(p, dict) and isinstance(p.get("name"), str):
                d = _dep("Packagist", p["name"], str(p.get("version", "")), True, rel, 1)
                if d:
                    out.append(d)
    return out


def _gemfile_lock(text: str, rel: str) -> list[dict]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \((\d[\w.\-]*)\)$", line)  # four-space indent: resolved gems, not their constraints
        if m:
            d = _dep("RubyGems", m.group(1), m.group(2), True, rel, n)
            if d:
                out.append(d)
    return out


PARSERS = {
    "requirements.txt": _requirements, "package.json": _package_json, "package-lock.json": _package_lock,
    "pom.xml": _pom, "build.gradle": _gradle, "build.gradle.kts": _gradle, "go.mod": _go_mod,
    "composer.lock": _composer_lock, "Gemfile.lock": _gemfile_lock,
}


def parse_manifests(root: Path, files: list[Path]) -> list[dict]:
    out: list[dict] = []
    for p in files:
        parser = PARSERS.get(p.name) or (_csproj if p.suffix.lower() == ".csproj" else None)
        if parser is None:
            continue
        try:
            out.extend(parser(p.read_text(errors="replace"), p.relative_to(root).as_posix()))
        except Exception:  # a parser bug must never fail the whole scan; the file simply contributes nothing
            continue
        if len(out) >= MAX_DEPS:
            break
    seen, uniq = set(), []
    for d in out[:MAX_DEPS]:
        key = (d["eco"], d["name"].lower(), d["version"], d["path"])
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    return uniq
