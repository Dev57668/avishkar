"""Deterministic scoring (spec §8, Appendix A). No I/O."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

from .models import EXCLUDED_STATES, Completeness, FindingRecord, State

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@dataclass(frozen=True)
class ScoreConfig:
    version: str
    impact: dict
    exposure: dict
    confidence: dict
    aging_enabled: bool
    aging_max_days: int
    aging_max_extra: float
    k: float
    required_detectors: tuple[str, ...]
    # Per-rule confidence tier overrides (from measured precision). Empty in the shipped score-v1.
    rule_confidence: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "ScoreConfig":
        """`AVISHKAR_SCORE_CONFIG` selects a profile (e.g. config/profiles/full.json) when no path is given."""
        import os
        env = os.environ.get("AVISHKAR_SCORE_CONFIG")
        d = json.loads((path or (Path(env) if env else CONFIG_DIR / "score-v1.json")).read_text())
        if d["normalization_k"] <= 0:
            raise ValueError("K must be positive")
        return cls(d["version"], d["impact"], d["exposure"], d["confidence"],
                   d["aging"]["enabled"], d["aging"]["max_days"], d["aging"]["max_extra"],
                   float(d["normalization_k"]), tuple(d["required_detectors"]), dict(d.get("rule_confidence", {})))


def aging_multiplier(cfg: ScoreConfig, days_open: int) -> float:
    if not cfg.aging_enabled:
        return 1.0
    return 1.0 + cfg.aging_max_extra * min(max(days_open, 0) / cfg.aging_max_days, 1.0)


def debt_units(cfg: ScoreConfig, f: FindingRecord) -> dict:
    """D_i = I x E x C x A. Remediation effort is deliberately NOT multiplied in."""
    r = f.raw
    i = cfg.impact[r.severity.value]
    e = cfg.exposure[r.exposure.value]
    c = cfg.confidence[r.confidence.value]
    a = aging_multiplier(cfg, f.days_open)
    return {"I": i, "E": e, "C": c, "A": a, "D": round(i * e * c * a, 6),
            "exposure_unknown": r.exposure.value == "unknown"}


def compute_score(cfg: ScoreConfig, findings: list[FindingRecord], completeness: Completeness) -> dict:
    """Returns a ScoreSnapshot-shaped dict. Incomplete scans yield null, never zero."""
    base = {"scoreVersion": cfg.version, "k": cfg.k, "agingEnabled": cfg.aging_enabled,
            "calibrated": False}
    if completeness.state != "complete":
        return {**base, "status": "not_calculated", "rawUnits": None, "normalizedIndex": None,
                "grossUnits": None, "components": [], "missing": completeness.missing}
    components, raw, gross = [], 0.0, 0.0
    for f in findings:
        parts = debt_units(cfg, f)
        counted = f.state not in EXCLUDED_STATES
        if counted:
            gross += parts["D"]
        # accepted risk remains in gross debt (spec); eligibility for blocking is a policy matter
        if f.state == State.OPEN:
            raw += parts["D"]
        components.append({"fingerprint": f.fingerprint, "state": f.state.value,
                           "counted": counted, **parts})
    raw = round(raw, 6)
    gross = round(gross, 6)
    # Normalized index is driven by gross debt so accepted risk cannot be used to game it.
    index = round(100 * (1 - math.exp(-gross / cfg.k)), 1)
    return {**base, "status": "calculated", "rawUnits": raw, "grossUnits": gross,
            "normalizedIndex": index, "components": components, "missing": []}
