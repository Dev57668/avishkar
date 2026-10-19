"""Canonical domain value objects. Pure, framework-free."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}[self.value]


class Exposure(str, Enum):
    CONFIRMED_EXTERNAL = "confirmed_external"
    PREREQUISITES = "prerequisites"
    INTERNAL = "internal"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class State(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"


# States excluded from current eligible debt (spec §8). Accepted risk stays in gross debt.
EXCLUDED_STATES = {State.FIXED, State.FALSE_POSITIVE, State.NOT_APPLICABLE, State.DUPLICATE}

FINGERPRINT_VERSION = "fp-1"


def fingerprint(rule_id: str, path: str, evidence_hash: str) -> str:
    """Stable canonical id independent of line numbers and of any single run."""
    raw = f"{FINGERPRINT_VERSION}|{rule_id}|{path}|{evidence_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def evidence_hash(text: str) -> str:
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class RawFinding:
    """Normalized detector output."""
    detector_id: str
    rule_id: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    path: str
    line: int
    evidence: str  # already redacted; never contains a full secret
    exposure: Exposure = Exposure.UNKNOWN
    remediation: str = ""
    effort: str = "small"

    @property
    def fp(self) -> str:
        return fingerprint(self.rule_id, self.path, evidence_hash(self.evidence))

    def to_dict(self) -> dict:
        return {"detector_id": self.detector_id, "rule_id": self.rule_id, "category": self.category,
                "severity": self.severity.value, "confidence": self.confidence.value, "title": self.title,
                "path": self.path, "line": self.line, "evidence": self.evidence, "exposure": self.exposure.value,
                "remediation": self.remediation, "effort": self.effort}

    @classmethod
    def from_dict(cls, d: dict) -> "RawFinding":
        """Validates sandbox output: unknown enum values raise, so malformed evidence cannot be scored."""
        return cls(str(d["detector_id"]), str(d["rule_id"]), str(d["category"]), Severity(d["severity"]),
                   Confidence(d["confidence"]), str(d["title"])[:300], str(d["path"])[:500], int(d["line"]),
                   str(d["evidence"])[:300], Exposure(d.get("exposure", "unknown")),
                   str(d.get("remediation", ""))[:500], str(d.get("effort", "small"))[:20])


@dataclass
class FindingRecord:
    """A finding as seen in one run, plus its ledger state."""
    fingerprint: str
    raw: RawFinding
    state: State = State.OPEN
    is_new: bool = True
    days_open: int = 0
    canonical_of: str | None = None  # for duplicates


@dataclass(frozen=True)
class Completeness:
    state: str  # complete | incomplete
    required: tuple[str, ...]
    completed: tuple[str, ...]
    failed: dict = field(default_factory=dict)

    @property
    def missing(self) -> list[str]:
        return [d for d in self.required if d not in self.completed]
