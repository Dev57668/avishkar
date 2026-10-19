"""
Pydantic models for API requests and responses
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime


class ProjectBase(BaseModel):
    name: str
    repo_url: Optional[str] = None
    default_branch: str = "main"


class ProjectCreate(ProjectBase):
    pass


class Project(ProjectBase):
    id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ScanBase(BaseModel):
    project_id: str
    commit_sha: Optional[str] = None


class ScanCreate(ScanBase):
    pass


class Scan(ScanBase):
    id: str
    score: Optional[int] = None
    risk_band: Optional[str] = None
    status: str = "pending"
    created_at: datetime
    completed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class Finding(BaseModel):
    id: str
    scan_id: str
    file: str
    line: Optional[int] = None
    rule_id: Optional[str] = None
    category: str
    severity: str
    confidence: float = 1.0
    exploitability: int = 5
    exposure: int = 3
    remediation_effort: int = 3
    status: str = "open"
    snippet: Optional[str] = None
    created_at: datetime
    canonical_fingerprint: Optional[str] = None
    detector_id: Optional[str] = None
    debt_units: Optional[float] = None
    model_config = ConfigDict(from_attributes=True)


class AIAnalysis(BaseModel):
    id: str
    finding_id: str
    is_likely_real: bool
    confidence: float
    explanation: str
    impact: str
    recommended_fix: str
    secure_code: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"


class UploadResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanResult(BaseModel):
    scan_id: str
    score: int
    risk_band: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class FindingWithAI(Finding):
    ai_analysis: Optional[AIAnalysis] = None
