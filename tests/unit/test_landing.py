"""The landing page shows recorded scan results; keep every number sourced from web/demo_results.json."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_landing_page_carries_no_hard_coded_scan_numbers():
    """Index, finding counts and the Fig 3 rows must come from web/demo_results.json, not typed into the HTML or JS."""
    html = (ROOT / "web" / "index.html").read_text(encoding="utf8")
    js = (ROOT / "web" / "landing.js").read_text(encoding="utf8")
    data = json.loads((ROOT / "web" / "demo_results.json").read_text(encoding="utf8"))
    idx = str(data["samples"]["vulnerable-python"]["before"]["normalizedIndex"])
    assert "79.6" not in html + js and "76.2" not in html + js
    assert idx not in html  # real values are injected from the JSON at load time
    assert "demo_results.json" in js
