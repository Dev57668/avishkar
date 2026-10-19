"""Entry point executed *inside* the sandbox. Reads untrusted content, writes detector JSON."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import collect_findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--required", required=True)
    ap.add_argument("--zip")
    ap.add_argument("--dir")
    a = ap.parse_args()
    required = tuple(x for x in a.required.split(",") if x)
    res = collect_findings(required, source_dir=Path(a.dir) if a.dir else None,
                           zip_path=Path(a.zip) if a.zip else None)
    Path(a.out).write_text(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
