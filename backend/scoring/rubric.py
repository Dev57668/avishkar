"""
Deterministic scoring rubric for score-v1
All factor values are provisional prioritization weights, not breach probabilities or compliance grades.
"""

from normalization.models import (
    SeverityLevel,
    ExposureCategory,
    ConfidenceLevel,
    RemediationCategory
)

SCORE_VERSION = "score-v1"
DEFAULT_K_CONSTANT = 25.0


def get_impact_weight(severity: SeverityLevel) -> float:
    """
    Map severity to impact weight I (range: 1.0 to 5.0)
    Provisional weights from Specification v1.1 Appendix A
    """
    weights = {
        SeverityLevel.CRITICAL: 5.0,
        SeverityLevel.HIGH: 4.0,
        SeverityLevel.MEDIUM: 3.0,
        SeverityLevel.LOW: 2.0,
        SeverityLevel.INFORMATIONAL: 1.0
    }
    return weights.get(severity, 3.0)  # Unknown falls back to neutral Medium


def get_exposure_multiplier(exposure: ExposureCategory) -> float:
    """
    Map exposure category to multiplier E (range: 0.75 to 1.50)
    Unknown exposure defaults to 1.00 (neutral internal baseline) with uncertainty flag.
    Missing evidence MUST NEVER be assigned 0.0 or asserted as unreachable.
    """
    multipliers = {
        ExposureCategory.CONFIRMED_EXTERNAL: 1.50,
        ExposureCategory.PREREQUISITES_REQUIRED: 1.25,
        ExposureCategory.INTERNAL: 1.00,
        ExposureCategory.DEMONSTRABLY_UNREACHABLE: 0.75,
        ExposureCategory.UNKNOWN: 1.00
    }
    return multipliers.get(exposure, 1.00)


def get_confidence_multiplier(confidence: ConfidenceLevel) -> float:
    """
    Map detector evidence confidence to multiplier C (range: 0.50 to 1.00)
    """
    multipliers = {
        ConfidenceLevel.HIGH: 1.00,
        ConfidenceLevel.MEDIUM: 0.75,
        ConfidenceLevel.LOW: 0.50
    }
    return multipliers.get(confidence, 0.75)


def get_age_multiplier(days_open: int = 0, enable_aging: bool = False) -> float:
    """
    Map days open to age multiplier A (range: 1.00 to 1.50)
    Formula: A = 1 + 0.5 * min(days_open / 90, 1.0)
    Per Specification v1.1 Appendix A: until pilot review, default is frozen at A = 1.00
    so age does not introduce unvalidated distortion.
    """
    if not enable_aging or days_open <= 0:
        return 1.00
    ratio = min(days_open / 90.0, 1.0)
    return round(1.0 + 0.5 * ratio, 4)


def get_effort_units(remediation: RemediationCategory) -> float:
    """
    Map remediation category to effort units (decoupled from security risk debt).
    Small = 1.0, Medium = 2.0, Large = 4.0
    """
    units = {
        RemediationCategory.LOW: 1.0,
        RemediationCategory.MEDIUM: 2.0,
        RemediationCategory.HIGH: 4.0
    }
    return units.get(remediation, 2.0)


def get_risk_band(score: float) -> str:
    """
    Categorize normalized score into provisional prioritization bands.
    These are prioritization markers, NOT probabilities of compromise.
    """
    if score <= 0.0:
        return "NONE"
    elif score <= 20.0:
        return "LOW"
    elif score <= 40.0:
        return "MODERATE"
    elif score <= 60.0:
        return "ELEVATED"
    elif score <= 80.0:
        return "HIGH"
    else:
        return "CRITICAL"
