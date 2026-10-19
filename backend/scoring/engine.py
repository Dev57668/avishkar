"""
Deterministic Security Debt Engine for Avishkar
Implements D_i = I_i * E_i * C_i * A_i, project score normalization,
decoupled remediation burden, and strict incomplete-analysis semantics.
"""

import math
from typing import List, Dict, Optional, Set
from pydantic import BaseModel, Field, ConfigDict

from normalization.models import (
    NormalizedFinding,
    SeverityLevel,
    FindingStatus
)
from scoring.rubric import (
    SCORE_VERSION,
    DEFAULT_K_CONSTANT,
    get_impact_weight,
    get_exposure_multiplier,
    get_confidence_multiplier,
    get_age_multiplier,
    get_effort_units,
    get_risk_band
)


class CompletenessState(BaseModel):
    state: str  # "complete" | "incomplete"
    requiredDetectors: int
    completedDetectors: int
    missing: List[str] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)


class SecurityDebtResult(BaseModel):
    status: str  # "calculated" | "not_calculated"
    rawUnits: Optional[float] = None
    normalizedIndex: Optional[float] = None
    riskBand: Optional[str] = None
    scoreVersion: str = SCORE_VERSION
    calibrationConstant: float = DEFAULT_K_CONSTANT
    model_config = ConfigDict(from_attributes=True)


class RemediationSummary(BaseModel):
    totalEffortUnits: float
    effortDistribution: Dict[str, int] = Field(default_factory=dict)
    model_config = ConfigDict(from_attributes=True)


class DecisionResult(BaseModel):
    outcome: str  # "pass" | "warn" | "block" | "not_evaluated"
    reasons: List[str] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)


class AnalysisEvaluationResult(BaseModel):
    status: str  # "complete" | "incomplete"
    completeness: CompletenessState
    securityDebt: SecurityDebtResult
    remediation: Optional[RemediationSummary] = None
    decision: DecisionResult
    eligibleFindingsCount: int = 0
    totalUniqueFindings: int = 0
    findings: List[NormalizedFinding] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)


class ScoringEngine:
    """Pure, deterministic scoring engine with versioned formula execution"""

    def __init__(self, k_constant: float = DEFAULT_K_CONSTANT, enable_aging: bool = False):
        if k_constant <= 0:
            raise ValueError(f"Calibration constant K must be strictly positive, got {k_constant}")
        self.k_constant = k_constant
        self.enable_aging = enable_aging

    def calculate_finding_debt(self, finding: NormalizedFinding) -> float:
        """
        Calculate provisional debt units for a single finding:
        D_i = I_i * E_i * C_i * A_i
        Remediation effort is tracked separately and NEVER multiplied into D_i.
        """
        impact = get_impact_weight(finding.severity)
        exposure = get_exposure_multiplier(finding.exposure)
        confidence = get_confidence_multiplier(finding.confidence)
        age = get_age_multiplier(finding.days_open, self.enable_aging)

        raw_debt = impact * exposure * confidence * age
        finding_debt = round(raw_debt, 4)
        finding.debt_units = finding_debt
        return finding_debt

    def calculate_project_debt(
        self,
        findings: List[NormalizedFinding]
    ) -> (float, float, str, RemediationSummary, List[NormalizedFinding]):
        """
        Calculate raw debt sum and normalized score index for unique eligible findings.
        Returns (raw_debt, normalized_score, risk_band, remediation_summary, eligible_findings).
        """
        total_raw_debt = 0.0
        eligible_findings = []
        total_effort_units = 0.0
        effort_distribution = {"low": 0, "medium": 0, "high": 0}

        for finding in findings:
            effort_cat = finding.remediation_effort.value
            effort_units = get_effort_units(finding.remediation_effort)
            total_effort_units += effort_units
            effort_distribution[effort_cat] = effort_distribution.get(effort_cat, 0) + 1

            if finding.is_eligible_for_debt:
                d_i = self.calculate_finding_debt(finding)
                total_raw_debt += d_i
                eligible_findings.append(finding)
            else:
                finding.debt_units = 0.0

        total_raw_debt = round(total_raw_debt, 4)

        if total_raw_debt == 0.0:
            normalized_score = 0.0
        else:
            # Score = round(100 * (1 - exp(-D / K)), 1)
            exponential_term = math.exp(-total_raw_debt / self.k_constant)
            normalized_score = round(100.0 * (1.0 - exponential_term), 1)

        risk_band = get_risk_band(normalized_score)
        remediation_summary = RemediationSummary(
            totalEffortUnits=round(total_effort_units, 2),
            effortDistribution=effort_distribution
        )

        return total_raw_debt, normalized_score, risk_band, remediation_summary, eligible_findings

    def evaluate_analysis(
        self,
        required_detectors: List[str],
        successful_detectors: Set[str],
        findings: List[NormalizedFinding]
    ) -> AnalysisEvaluationResult:
        """
        Evaluate full analysis state.
        STRICT REQUIREMENT: If ANY required detector failed or is missing,
        mark run incomplete. A failed scanner NEVER produces a clean score.
        """
        req_set = set(required_detectors)
        missing_detectors = sorted(list(req_set - set(successful_detectors)))

        if missing_detectors:
            # Incomplete scan state
            completeness = CompletenessState(
                state="incomplete",
                requiredDetectors=len(req_set),
                completedDetectors=len(req_set) - len(missing_detectors),
                missing=missing_detectors
            )
            security_debt = SecurityDebtResult(
                status="not_calculated",
                rawUnits=None,
                normalizedIndex=None,
                riskBand=None,
                scoreVersion=SCORE_VERSION,
                calibrationConstant=self.k_constant
            )
            decision = DecisionResult(
                outcome="not_evaluated",
                reasons=[f"required_scanner_missing_or_failed: {d}" for d in missing_detectors]
            )
            return AnalysisEvaluationResult(
                status="incomplete",
                completeness=completeness,
                securityDebt=security_debt,
                remediation=None,
                decision=decision,
                eligibleFindingsCount=0,
                totalUniqueFindings=len(findings),
                findings=findings
            )

        # All required detectors succeeded
        raw_debt, score, band, remediation, eligible = self.calculate_project_debt(findings)

        completeness = CompletenessState(
            state="complete",
            requiredDetectors=len(req_set),
            completedDetectors=len(req_set),
            missing=[]
        )
        security_debt = SecurityDebtResult(
            status="calculated",
            rawUnits=raw_debt,
            normalizedIndex=score,
            riskBand=band,
            scoreVersion=SCORE_VERSION,
            calibrationConstant=self.k_constant
        )

        # Policy decision evaluation
        reasons = []
        critical_count = sum(1 for f in eligible if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in eligible if f.severity == SeverityLevel.HIGH)

        if critical_count > 0:
            outcome = "block"
            reasons.append(f"{critical_count} critical finding(s) detected")
        elif high_count > 0 or score > 40.0:
            outcome = "warn"
            if high_count > 0:
                reasons.append(f"{high_count} high severity finding(s) detected")
            if score > 40.0:
                reasons.append(f"Security debt score {score} exceeds elevated threshold")
        else:
            outcome = "pass"
            reasons.append("No blocking or elevated debt conditions found")

        decision = DecisionResult(outcome=outcome, reasons=reasons)

        return AnalysisEvaluationResult(
            status="complete",
            completeness=completeness,
            securityDebt=security_debt,
            remediation=remediation,
            decision=decision,
            eligibleFindingsCount=len(eligible),
            totalUniqueFindings=len(findings),
            findings=findings
        )
