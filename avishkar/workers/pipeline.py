"""Scan pipeline, split at the trust boundary.

* `collect_findings` touches untrusted repository content (extraction, parsing, detectors). In production
  it runs inside the sandbox (`workers/sandbox.py`) and returns plain JSON.
* `assemble` is trusted: it validates that JSON, dedupes, compares to the baseline, scores and applies policy.

A required detector failure, sandbox failure or exceeded limit yields an *incomplete* run (score not
calculated, decision not_evaluated) -- never a pass (spec §8, §9).
"""
from __future__ import annotations

import io
import shutil
import tempfile
import time
import zipfile
from pathlib import Path

from ..domain import policy as policy_mod
from ..domain.models import Completeness, FindingRecord, RawFinding, State
from ..domain.scoring import ScoreConfig, compute_score
from .detectors import DETECTORS, SUPPORT_MATRIX

MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 50_000_000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


class LimitExceeded(Exception):
    pass


def extract_zip(src: "Path | bytes", dest: Path) -> None:
    """Safely extract an archive (rejects traversal, symlinks, zip bombs). A single top-level
    directory (as in GitHub zipballs) is stripped."""
    total = 0
    zf = zipfile.ZipFile(io.BytesIO(src) if isinstance(src, bytes) else src)
    with zf as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise LimitExceeded("too many files")
        for i in infos:  # reject hostile names before any directory stripping can launder them
            parts = i.filename.replace("\\", "/").split("/")
            if ".." in parts or i.filename.startswith(("/", "\\")) or (len(i.filename) > 1 and i.filename[1] == ":"):
                raise LimitExceeded(f"path traversal in archive: {i.filename}")
        tops = {i.filename.split("/")[0] for i in infos if i.filename.strip("/")}
        strip = (next(iter(tops)) + "/") if len(tops) == 1 and all("/" in i.filename for i in infos) else ""
        root = dest.resolve()
        for i in infos:
            name = i.filename[len(strip):] if strip and i.filename.startswith(strip) else i.filename
            if not name:
                continue
            target = (dest / name).resolve()
            if target != root and root not in target.parents:
                raise LimitExceeded(f"path traversal in archive: {i.filename}")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise LimitExceeded(f"symlink in archive: {i.filename}")
            total += i.file_size
            if total > MAX_TOTAL_BYTES:
                raise LimitExceeded("archive too large when extracted")
            if i.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(i))


def _collect_files(root: Path) -> tuple[list[Path], list[str]]:
    files, notes, total = [], [], 0
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_symlink():
            notes.append(f"skipped symlink {p.relative_to(root).as_posix()}")
            continue
        if not p.is_file():
            continue
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            notes.append(f"skipped oversized file {p.relative_to(root).as_posix()}")
            continue
        total += size
        if len(files) >= MAX_FILES or total > MAX_TOTAL_BYTES:
            raise LimitExceeded("repository exceeds size limits")
        files.append(p)
    return files, notes


def collect_findings(required: tuple[str, ...], source_dir: Path | None = None, zip_path: Path | None = None,
                     detectors: dict | None = None) -> dict:
    """Untrusted-content stage. Returns JSON-serializable detector output; the workspace is always removed."""
    detectors = detectors if detectors is not None else DETECTORS
    raw, completed, failed, stages = [], [], {}, {}
    files, notes = [], []
    workspace = Path(tempfile.mkdtemp(prefix="avishkar-"))
    try:
        root = workspace / "src"
        try:
            if zip_path is not None:
                root.mkdir()
                extract_zip(zip_path, root)
            else:
                shutil.copytree(source_dir, root, symlinks=True, ignore=shutil.ignore_patterns(*SKIP_DIRS))
            files, notes = _collect_files(root)
            stages["checkout"] = "ok"
        except Exception as e:
            for d in required:
                failed[d] = f"checkout failed: {type(e).__name__}: {e}"
            stages["checkout"] = "failed"
        if stages["checkout"] == "ok":
            for name in required:
                fn = detectors.get(name)
                if fn is None:
                    failed[name] = "detector not available"
                    continue
                try:
                    raw.extend(r.to_dict() for r in fn(root, files))
                    completed.append(name)
                    stages[name] = "ok"
                except Exception as e:  # preserve failure in stage state
                    failed[name] = f"{type(e).__name__}: {e}"
                    stages[name] = "failed"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)  # cleanup on success and failure
    return {"raw": raw, "completed": completed, "failed": failed, "stages": stages,
            "files": len(files), "notes": notes}


def failed_collection(required, reason: str, stage: str = "sandbox") -> dict:
    return {"raw": [], "completed": [], "failed": {d: reason for d in required}, "stages": {stage: "failed"},
            "files": 0, "notes": []}


def assemble(cfg: ScoreConfig, pol: policy_mod.Policy, collected: dict, baseline: dict | None = None) -> dict:
    """Trusted stage: validate, dedupe, baseline-compare, score, evaluate policy."""
    baseline = baseline or {}
    failed, completed, stages = dict(collected["failed"]), list(collected["completed"]), dict(collected["stages"])
    raw: list[RawFinding] = []
    try:
        raw = [RawFinding.from_dict(d) for d in collected["raw"]]
    except Exception as e:  # malformed detector output must never be scored as clean
        for d in cfg.required_detectors:
            failed.setdefault(d, f"malformed detector output: {type(e).__name__}")
        completed, raw = [], []
        stages["validation"] = "failed"
    completeness = Completeness("complete" if not failed else "incomplete", tuple(cfg.required_detectors),
                                tuple(completed), failed)
    seen: dict[str, FindingRecord] = {}
    secret_sites: set[tuple] = set()  # two secret detectors flagging one line count once
    now = time.time()
    for r in sorted(raw, key=lambda r: (-r.confidence.rank, r.detector_id, r.rule_id, r.path, r.line)):
        fp = r.fp
        if fp in seen:
            continue
        if r.category == "secret":
            site = (r.path, r.line)
            if site in secret_sites:
                continue
            secret_sites.add(site)
        prior = baseline.get(fp)
        state, is_new, days = State.OPEN, True, 0
        if prior:
            is_new = False
            days = int((now - prior["first_seen"]) / 86400)
            if prior["state"] in (State.ACCEPTED_RISK.value, State.FALSE_POSITIVE.value,
                                  State.NOT_APPLICABLE.value, State.DUPLICATE.value):
                state = State(prior["state"])
        seen[fp] = FindingRecord(fp, r, state, is_new, days)
    findings = list(seen.values())
    fixed = []
    if completeness.state == "complete":
        fixed = [fp for fp, b in baseline.items() if fp not in seen and b["state"] != State.FIXED.value]
    score = compute_score(cfg, findings, completeness)
    decision = policy_mod.evaluate(pol, findings, completeness)
    return {
        "status": "complete" if completeness.state == "complete" else "incomplete",
        "completedAt": time.time(),
        "completeness": {"state": completeness.state, "requiredDetectors": len(completeness.required),
                         "completedDetectors": len(completeness.completed),
                         "missing": completeness.missing, "failures": failed},
        "securityDebt": score, "decision": decision, "stages": stages,
        "findings": findings, "fixed": fixed, "filesScanned": collected["files"], "notes": collected["notes"],
        "supportMatrix": SUPPORT_MATRIX,
    }


def run_scan(source_dir: Path, cfg: ScoreConfig, pol: policy_mod.Policy, baseline: dict | None = None,
             detectors: dict | None = None, sandbox=None) -> dict:
    """Scan a directory (CLI / tests). With `sandbox`, untrusted parsing runs out of process."""
    started = time.time()
    if sandbox is not None:
        collected = sandbox.collect(cfg.required_detectors, source_dir=source_dir)
    else:
        collected = collect_findings(cfg.required_detectors, source_dir=source_dir, detectors=detectors)
    res = assemble(cfg, pol, collected, baseline)
    res["id"] = "run_" + str(int(started * 1000))
    res["startedAt"] = started
    return res
