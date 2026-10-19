import math

import pytest

from avishkar.domain.models import (Completeness, Confidence, Exposure, FindingRecord, RawFinding,
                                    Severity, State)
from avishkar.domain.policy import Policy, evaluate
from avishkar.domain.scoring import ScoreConfig, compute_score, debt_units

CFG = ScoreConfig.load()
COMPLETE = Completeness("complete", CFG.required_detectors, CFG.required_detectors)


def rec(sev, conf=Confidence.HIGH, exp=Exposure.UNKNOWN, state=State.OPEN, new=True, cat="x", n="a"):
    r = RawFinding("d", "R-" + n, cat, sev, conf, "t", "f.py", 1, "ev" + n, exp)
    return FindingRecord(r.fp, r, state, new)


@pytest.mark.parametrize("sev,i", [(Severity.CRITICAL, 5), (Severity.HIGH, 4), (Severity.MEDIUM, 3),
                                   (Severity.LOW, 2), (Severity.INFORMATIONAL, 1)])
def test_impact_vectors(sev, i):
    assert debt_units(CFG, rec(sev))["D"] == i


@pytest.mark.parametrize("exp,e", [(Exposure.CONFIRMED_EXTERNAL, 1.5), (Exposure.PREREQUISITES, 1.25),
                                   (Exposure.INTERNAL, 1.0), (Exposure.UNREACHABLE, 0.75), (Exposure.UNKNOWN, 1.0)])
def test_exposure_vectors(exp, e):
    assert debt_units(CFG, rec(Severity.HIGH, exp=exp))["D"] == 4 * e


def test_unknown_exposure_flagged_not_zero():
    p = debt_units(CFG, rec(Severity.HIGH))
    assert p["exposure_unknown"] and p["D"] > 0


def test_confidence_multiplier():
    assert debt_units(CFG, rec(Severity.CRITICAL, Confidence.LOW))["D"] == 2.5


def test_zero_findings_complete_is_zero():
    s = compute_score(CFG, [], COMPLETE)
    assert s["status"] == "calculated" and s["rawUnits"] == 0 and s["normalizedIndex"] == 0


def test_incomplete_is_null_not_zero():
    inc = Completeness("incomplete", CFG.required_detectors, ("secrets",), {"dependencies": "boom"})
    s = compute_score(CFG, [rec(Severity.HIGH)], inc)
    assert s["status"] == "not_calculated" and s["rawUnits"] is None and s["normalizedIndex"] is None
    assert set(s["missing"]) == {"code-patterns", "dependencies"}


def test_normalization_formula():
    s = compute_score(CFG, [rec(Severity.CRITICAL)], COMPLETE)
    assert s["normalizedIndex"] == round(100 * (1 - math.exp(-5 / CFG.k)), 1)


def test_fixed_false_positive_duplicate_na_excluded():
    fs = [rec(Severity.HIGH, state=st, n=st.value) for st in
          (State.FIXED, State.FALSE_POSITIVE, State.DUPLICATE, State.NOT_APPLICABLE)]
    assert compute_score(CFG, fs, COMPLETE)["grossUnits"] == 0


def test_accepted_risk_stays_in_gross_debt():
    s = compute_score(CFG, [rec(Severity.HIGH, state=State.ACCEPTED_RISK)], COMPLETE)
    assert s["grossUnits"] == 4 and s["rawUnits"] == 0 and s["normalizedIndex"] > 0


def test_deterministic_and_order_independent():
    fs = [rec(Severity.HIGH, n="1"), rec(Severity.LOW, n="2"), rec(Severity.CRITICAL, n="3")]
    a = compute_score(CFG, fs, COMPLETE)
    b = compute_score(CFG, list(reversed(fs)), COMPLETE)
    assert a["rawUnits"] == b["rawUnits"] and a["normalizedIndex"] == b["normalizedIndex"]


def test_aging_disabled_by_default_and_monotonic_when_enabled():
    old = rec(Severity.HIGH); old.days_open = 365
    assert debt_units(CFG, old)["A"] == 1.0
    on = ScoreConfig(**{**CFG.__dict__, "aging_enabled": True})
    vals = []
    for d in (0, 45, 90, 400):
        r = rec(Severity.HIGH); r.days_open = d
        vals.append(debt_units(on, r)["A"])
    assert vals == sorted(vals) and vals[-1] == 1.5


def test_effort_does_not_affect_risk():
    a = rec(Severity.HIGH); b = rec(Severity.HIGH)
    object.__setattr__(b.raw, "effort", "large")
    assert debt_units(CFG, a)["D"] == debt_units(CFG, b)["D"]


POL = Policy.load()


def test_policy_blocks_critical_secret_regardless_of_low_index():
    f = rec(Severity.CRITICAL, cat="secret")
    d = evaluate(POL, [f], COMPLETE)
    assert d["outcome"] == "would_block"  # report_only mode
    enforce = Policy(POL.version, "enforce", POL.predicates)
    assert evaluate(enforce, [f], COMPLETE)["outcome"] == "block"


def test_policy_low_confidence_cannot_block():
    d = evaluate(Policy(POL.version, "enforce", POL.predicates),
                 [rec(Severity.CRITICAL, Confidence.LOW, cat="secret")], COMPLETE)
    assert d["outcome"] == "pass"


def test_policy_incomplete_never_passes():
    inc = Completeness("incomplete", CFG.required_detectors, (), {"x": "y"})
    assert evaluate(POL, [], inc)["outcome"] == "not_evaluated"


def test_policy_new_high_warns_but_existing_does_not():
    assert evaluate(POL, [rec(Severity.HIGH)], COMPLETE)["outcome"] == "warn"
    assert evaluate(POL, [rec(Severity.HIGH, new=False)], COMPLETE)["outcome"] == "pass"
