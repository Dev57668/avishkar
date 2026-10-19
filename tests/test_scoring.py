import pytest
import sys
from pathlib import Path

# Ensure backend is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# pyrefly: ignore [missing-import]
from normalization.models import (
    NormalizedFinding,
    SeverityLevel,
    ExposureCategory,
    ConfidenceLevel,
    RemediationCategory,
    FindingStatus
)
from scoring.rubric import (
    get_impact_weight,
    get_exposure_multiplier,
    get_confidence_multiplier,
    get_age_multiplier,
    get_effort_units,
    get_risk_band,
    DEFAULT_K_CONSTANT
)
from scoring.engine import ScoringEngine


def make_finding(
    fid: str = "f1",
    severity: SeverityLevel = SeverityLevel.HIGH,
    exposure: ExposureCategory = ExposureCategory.INTERNAL,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    remediation: RemediationCategory = RemediationCategory.MEDIUM,
    status: FindingStatus = FindingStatus.OPEN,
    days_open: int = 0
) -> NormalizedFinding:
    """Helper to build a test NormalizedFinding"""
    return NormalizedFinding(
        id=fid,
        canonical_fingerprint=f"fp_{fid}",
        title="Test finding",
        category="Test Category",
        file="src/app.py",
        line=10,
        rule_id="test-rule",
        severity=severity,
        exposure=exposure,
        confidence=confidence,
        remediation_effort=remediation,
        status=status,
        days_open=days_open
    )


class TestScoringRubricGoldenVectors:
    """Verify exact formula D_i = I_i * E_i * C_i * A_i against golden vectors"""

    def test_golden_vector_critical_external_high_confidence(self):
        """Critical (5.0) * Confirmed External (1.50) * High (1.00) * Age (1.00) = 7.50"""
        engine = ScoringEngine()
        finding = make_finding(
            severity=SeverityLevel.CRITICAL,
            exposure=ExposureCategory.CONFIRMED_EXTERNAL,
            confidence=ConfidenceLevel.HIGH
        )
        d_i = engine.calculate_finding_debt(finding)
        assert d_i == 7.50

    def test_golden_vector_high_prerequisites_high_confidence(self):
        """High (4.0) * Prerequisites (1.25) * High (1.00) * Age (1.00) = 5.00"""
        engine = ScoringEngine()
        finding = make_finding(
            severity=SeverityLevel.HIGH,
            exposure=ExposureCategory.PREREQUISITES_REQUIRED,
            confidence=ConfidenceLevel.HIGH
        )
        d_i = engine.calculate_finding_debt(finding)
        assert d_i == 5.00

    def test_golden_vector_medium_internal_medium_confidence(self):
        """Medium (3.0) * Internal (1.00) * Medium (0.75) * Age (1.00) = 2.25"""
        engine = ScoringEngine()
        finding = make_finding(
            severity=SeverityLevel.MEDIUM,
            exposure=ExposureCategory.INTERNAL,
            confidence=ConfidenceLevel.MEDIUM
        )
        d_i = engine.calculate_finding_debt(finding)
        assert d_i == 2.25

    def test_golden_vector_low_unreachable_low_confidence(self):
        """Low (2.0) * Demonstrably Unreachable (0.75) * Low (0.50) * Age (1.00) = 0.75"""
        engine = ScoringEngine()
        finding = make_finding(
            severity=SeverityLevel.LOW,
            exposure=ExposureCategory.DEMONSTRABLY_UNREACHABLE,
            confidence=ConfidenceLevel.LOW
        )
        d_i = engine.calculate_finding_debt(finding)
        assert d_i == 0.75

    def test_golden_vector_informational_minimum(self):
        """Informational (1.0) * Unreachable (0.75) * Low (0.50) * Age (1.00) = 0.375"""
        engine = ScoringEngine()
        finding = make_finding(
            severity=SeverityLevel.INFORMATIONAL,
            exposure=ExposureCategory.DEMONSTRABLY_UNREACHABLE,
            confidence=ConfidenceLevel.LOW
        )
        d_i = engine.calculate_finding_debt(finding)
        assert d_i == 0.375


class TestUnknownInputsAndSafetyDefaults:
    """Verify requirement that unknown inputs receive safe neutral handling and never zero out risk"""

    def test_unknown_exposure_defaults_to_neutral_one(self):
        """Unknown exposure defaults to 1.00 (internal baseline), NEVER 0.00"""
        engine = ScoringEngine()
        finding = make_finding(
            severity=SeverityLevel.HIGH,
            exposure=ExposureCategory.UNKNOWN,
            confidence=ConfidenceLevel.HIGH
        )
        assert finding.unknown_exposure is True
        d_i = engine.calculate_finding_debt(finding)
        # 4.0 * 1.00 * 1.00 * 1.00 = 4.00 (not zero!)
        assert d_i == 4.00

    def test_invalid_k_constant_raises_value_error(self):
        """Calibration constant K <= 0 must be rejected"""
        with pytest.raises(ValueError):
            ScoringEngine(k_constant=0)
        with pytest.raises(ValueError):
            ScoringEngine(k_constant=-10.0)


class TestRemediationEffortDecoupling:
    """Verify requirement that remediation effort does NOT alter the security risk score"""

    def test_remediation_effort_does_not_affect_risk_debt(self):
        """Two findings with identical severity/exposure/confidence but different remediation effort have identical debt"""
        engine = ScoringEngine()
        f_cheap = make_finding(fid="1", severity=SeverityLevel.CRITICAL, remediation=RemediationCategory.LOW)
        f_expensive = make_finding(fid="2", severity=SeverityLevel.CRITICAL, remediation=RemediationCategory.HIGH)

        d_cheap = engine.calculate_finding_debt(f_cheap)
        d_expensive = engine.calculate_finding_debt(f_expensive)

        assert d_cheap == d_expensive
        assert d_cheap == 5.00  # 5.0 (Critical) * 1.0 (Internal) * 1.0 (High confidence) * 1.0 (Age)

    def test_remediation_summary_is_tracked_separately(self):
        """Project debt calculation summarizes effort units without affecting risk score"""
        engine = ScoringEngine()
        findings = [
            make_finding(fid="1", remediation=RemediationCategory.LOW),     # 1 unit
            make_finding(fid="2", remediation=RemediationCategory.MEDIUM),  # 2 units
            make_finding(fid="3", remediation=RemediationCategory.HIGH),    # 4 units
        ]
        raw_debt, score, band, rem_summary, _ = engine.calculate_project_debt(findings)

        assert rem_summary.totalEffortUnits == 7.0
        assert rem_summary.effortDistribution == {"low": 1, "medium": 1, "high": 1}
        # Score calculation is pure exponential of raw_debt, independent of effort
        assert score > 0.0


class TestLifecycleEligibility:
    """Verify that fixed and false positive findings do not contribute to active debt"""

    def test_fixed_and_false_positive_excluded_from_debt(self):
        """Fixed and false_positive findings do not add to raw debt; accepted_risk remains in debt"""
        engine = ScoringEngine()
        f_open = make_finding(fid="open", status=FindingStatus.OPEN)
        f_fixed = make_finding(fid="fixed", status=FindingStatus.FIXED)
        f_fp = make_finding(fid="fp", status=FindingStatus.FALSE_POSITIVE)
        f_accepted = make_finding(fid="accepted", status=FindingStatus.ACCEPTED_RISK)

        raw_debt, score, band, _, eligible = engine.calculate_project_debt([f_open, f_fixed, f_fp, f_accepted])

        assert len(eligible) == 2  # open + accepted_risk
        assert f_fixed not in eligible
        assert f_fp not in eligible


class TestIncompleteAnalysisSemantics:
    """Verify requirement 5: If a required detector fails/is unavailable, analysis is incomplete and score is not calculated"""

    def test_required_detector_failure_yields_incomplete_status(self):
        """When a required scanner fails, score MUST be not_calculated and null, never zero"""
        engine = ScoringEngine()
        findings = [make_finding(fid="1")]

        required = ["semgrep", "gitleaks", "custom_python"]
        successful = {"semgrep", "custom_python"}  # gitleaks failed / missing

        result = engine.evaluate_analysis(
            required_detectors=required,
            successful_detectors=successful,
            findings=findings
        )

        assert result.status == "incomplete"
        assert result.completeness.state == "incomplete"
        assert result.completeness.missing == ["gitleaks"]
        assert result.completeness.completedDetectors == 2
        assert result.completeness.requiredDetectors == 3

        # Must NOT calculate debt
        assert result.securityDebt.status == "not_calculated"
        assert result.securityDebt.rawUnits is None
        assert result.securityDebt.normalizedIndex is None
        assert result.securityDebt.riskBand is None

        # Policy decision is not_evaluated
        assert result.decision.outcome == "not_evaluated"
        assert any("gitleaks" in r for r in result.decision.reasons)

    def test_successful_zero_findings_scan_yields_clean_zero_debt(self):
        """When ALL required scanners succeed and find zero issues, debt is 0.0 and status complete"""
        engine = ScoringEngine()
        required = ["semgrep", "custom_python"]
        successful = {"semgrep", "custom_python"}

        result = engine.evaluate_analysis(
            required_detectors=required,
            successful_detectors=successful,
            findings=[]
        )

        assert result.status == "complete"
        assert result.completeness.state == "complete"
        assert result.completeness.missing == []
        assert result.securityDebt.status == "calculated"
        assert result.securityDebt.rawUnits == 0.0
        assert result.securityDebt.normalizedIndex == 0.0
        assert result.securityDebt.riskBand == "NONE"
        assert result.decision.outcome == "pass"
