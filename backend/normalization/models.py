"""
Normalized finding data models with provenance and governance attributes
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ExposureCategory(str, Enum):
    CONFIRMED_EXTERNAL = "confirmed_external"
    PREREQUISITES_REQUIRED = "prerequisites_required"
    INTERNAL = "internal"
    DEMONSTRABLY_UNREACHABLE = "demonstrably_unreachable"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationCategory(str, Enum):
    LOW = "low"       # ~1 effort unit (e.g. quick config or 1-liner fix)
    MEDIUM = "medium" # ~2 effort units (e.g. parameterize query or update auth check)
    HIGH = "high"     # ~4 effort units (e.g. crypto migration or architectural change)


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class FindingInstance(BaseModel):
    """Specific detector occurrence of a finding in an analysis run"""
    detector_id: str
    detector_version: Optional[str] = None
    rule_id: str
    file: str
    line: Optional[int] = None
    raw_severity: str
    raw_message: str
    snippet: Optional[str] = None
    evidence_hash: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(from_attributes=True)


class NormalizedFinding(BaseModel):
    """Canonical finding unified across detectors with evidence and scoring factors"""
    id: str
    canonical_fingerprint: str
    title: str
    category: str
    file: str
    line: Optional[int] = None
    rule_id: str
    
    # Normalized scoring factors (provisional score-v1 rubric)
    severity: SeverityLevel
    confidence: ConfidenceLevel
    exposure: ExposureCategory = ExposureCategory.UNKNOWN
    unknown_exposure: bool = True
    unknown_severity: bool = False
    
    # Decoupled remediation effort (never multiplied into risk debt)
    remediation_effort: RemediationCategory = RemediationCategory.MEDIUM
    
    # Governance & lifecycle
    status: FindingStatus = FindingStatus.OPEN
    days_open: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Calculated finding debt unit (provisional: I * E * C * A)
    debt_units: Optional[float] = None
    
    # Occurrence provenance
    instances: List[FindingInstance] = Field(default_factory=list)
    primary_snippet: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

    @property
    def is_eligible_for_debt(self) -> bool:
        """Fixed and verified false positives do not contribute to active debt"""
        return self.status in {FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.ACCEPTED_RISK}
