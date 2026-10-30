"""The landing page's hero shows a verbatim slice of a bundled sample; keep it from drifting from the real file."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_hero_source_is_verbatim_slice_of_the_sample():
    js = (ROOT / "web" / "landing.js").read_text(encoding="utf8")
    m = re.search(r"const FIRST_LINE = (\d+);\nconst SRC = `(.*?)`\.split", js, re.S)
    assert m, "hero SRC block not found"
    first, shown = int(m.group(1)), m.group(2).split("\n")
    real = (ROOT / "sample_projects" / "vulnerable-python" / "app.py").read_text(encoding="utf8").split("\n")
    assert real[first - 1:first - 1 + len(shown)] == shown


def test_landing_page_carries_no_hard_coded_scan_numbers():
    """Index, finding counts and the Fig 3 rows must come from web/demo_results.json, not typed into the HTML or JS."""
    html = (ROOT / "web" / "index.html").read_text(encoding="utf8")
    js = (ROOT / "web" / "landing.js").read_text(encoding="utf8")
    data = json.loads((ROOT / "web" / "demo_results.json").read_text(encoding="utf8"))
    idx = str(data["samples"]["vulnerable-python"]["before"]["normalizedIndex"])
    assert "79.6" not in html + js and "76.2" not in html + js
    assert idx not in html  # real values are injected from the JSON at load time
    assert "demo_results.json" in js
