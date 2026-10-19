"""Policy evaluation on explicit finding predicates, never on the aggregate index alone."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import Completeness, Confidence, FindingRecord, Severity, State
from .scoring import CONFIG_DIR


@dataclass(frozen=True)
class Policy:
    version: str
    mode: str  # report_only | warn | enforce
    predicates: tuple[dict, ...]

    @classmethod
    def load(cls, path: Path | None = None) -> "Policy":
        d = json.loads((path or CONFIG_DIR / "policy.json").read_text())
        return cls(d["version"], d["mode"], tuple(d["predicates"]))


def _matches(p: dict, f: FindingRecord) -> bool:
    r = f.raw
    if f.state != State.OPEN:
        return False
    if "category" in p and r.category != p["category"]:
        return False
    if r.severity.rank < Severity(p["min_severity"]).rank:
        return False
    if r.confidence.rank < Confidence(p["min_confidence"]).rank:
        return False
    if p.get("new_only") and not f.is_new:
        return False
    return True


def evaluate(policy: Policy, findings: list[FindingRecord], completeness: Completeness) -> dict:
    """Structured decision with matched predicates. Incomplete => not_evaluated, never pass."""
    if completeness.state != "complete":
        return {"outcome": "not_evaluated", "reasons": ["required_scanner_failed"],
                "matched": [], "mode": policy.mode, "policyVersion": policy.version}
    matched = []
    for p in policy.predicates:
        hits = [f.fingerprint for f in findings if _matches(p, f)]
        if hits:
            matched.append({"id": p["id"], "action": p["action"], "findings": hits})
    outcome = "pass"
    if any(m["action"] == "warn" for m in matched):
        outcome = "warn"
    if any(m["action"] == "block" for m in matched):
        # report-only mode records what would have blocked but does not enforce
        outcome = "block" if policy.mode == "enforce" else "would_block"
    return {"outcome": outcome, "reasons": [m["id"] for m in matched], "matched": matched,
            "mode": policy.mode, "policyVersion": policy.version}
