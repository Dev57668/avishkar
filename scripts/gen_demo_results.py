"""Regenerate web/demo_results.json from REAL scans of the bundled samples (the landing page reads this file).
A test fails when the committed file differs from a fresh run, so the page can never show stale or invented numbers.

    python scripts/gen_demo_results.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from avishkar.demo import demo_results  # noqa: E402

out = ROOT / "web" / "demo_results.json"
out.write_text(json.dumps(demo_results(), indent=1) + "\n", encoding="utf8", newline="\n")
print("wrote", out)
