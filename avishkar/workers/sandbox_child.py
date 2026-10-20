"""Entry point executed *inside* the sandbox. Reads untrusted content, writes detector JSON."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import collect_findings


def _apply_limits(mem_bytes, cpu_seconds):
    """POSIX resource limits, applied by the child to itself (best effort; the Docker mode is the real boundary)."""
    try:
        import resource
    except ImportError:  # Windows
        return
    for kind, val in (("RLIMIT_AS", mem_bytes), ("RLIMIT_CPU", cpu_seconds), ("RLIMIT_FSIZE", 200_000_000)):
        if val:
            try:
                resource.setrlimit(getattr(resource, kind), (val, val))
            except (ValueError, OSError):
                pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--required", required=True)
    ap.add_argument("--zip")
    ap.add_argument("--dir")
    ap.add_argument("--mem-bytes", type=int)
    ap.add_argument("--cpu-seconds", type=int)
    a = ap.parse_args()
    _apply_limits(a.mem_bytes, a.cpu_seconds)
    required = tuple(x for x in a.required.split(",") if x)
    res = collect_findings(required, source_dir=Path(a.dir) if a.dir else None,
                           zip_path=Path(a.zip) if a.zip else None)
    Path(a.out).write_text(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
