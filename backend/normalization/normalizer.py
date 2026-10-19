"""
Finding normalizer: transforms scanner RawFinding objects into canonical NormalizedFinding objects with deduplication
"""

import hashlib
import logging
from typing import List, Dict, Optional

from scanners.base import RawFinding
from normalization.models import (
    NormalizedFinding,
    FindingInstance,
    SeverityLevel,
    ConfidenceLevel,
    ExposureCategory,
    RemediationCategory,
    FindingStatus
)
from normalization.fingerprint import compute_canonical_fingerprint, normalize_path

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    SeverityLevel.INFORMATIONAL: 1,
    SeverityLevel.LOW: 2,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.HIGH: 4,
    SeverityLevel.CRITICAL: 5
}

CONFIDENCE_ORDER = {
    ConfidenceLevel.LOW: 1,
    ConfidenceLevel.MEDIUM: 2,
    ConfidenceLevel.HIGH: 3
}


class FindingNormalizer:
    """Normalizes raw scanner findings and deduplicates them into canonical issues"""

    @classmethod
    def normalize_severity(cls, raw_severity: str) -> (SeverityLevel, bool):
        """Map raw severity string to normalized enum. Returns (SeverityLevel, is_unknown)"""
        clean = (raw_severity or "").strip().lower()
        if clean in ("critical", "blocker"):
            return SeverityLevel.CRITICAL, False
        elif clean in ("high", "error"):
            return SeverityLevel.HIGH, False
        elif clean in ("medium", "warning", "warn"):
            return SeverityLevel.MEDIUM, False
        elif clean in ("low", "minor"):
            return SeverityLevel.LOW, False
        elif clean in ("info", "informational"):
            return SeverityLevel.INFORMATIONAL, False
        else:
            logger.warning(f"Unknown severity '{raw_severity}', defaulting to medium")
            return SeverityLevel.MEDIUM, True

    @classmethod
    def normalize_confidence(cls, raw_conf: Optional[any]) -> ConfidenceLevel:
        """Map confidence value (string or float) to enum"""
        if isinstance(raw_conf, (int, float)):
            if raw_conf >= 0.9:
                return ConfidenceLevel.HIGH
            elif raw_conf >= 0.6:
                return ConfidenceLevel.MEDIUM
            else:
                return ConfidenceLevel.LOW
        
        clean = str(raw_conf or "").strip().lower()
        if clean in ("high", "certain"):
            return ConfidenceLevel.HIGH
        elif clean in ("medium", "tentative"):
            return ConfidenceLevel.MEDIUM
        elif clean in ("low", "heuristic"):
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.MEDIUM

    @classmethod
    def estimate_remediation_effort(cls, category: str, severity: SeverityLevel) -> RemediationCategory:
        """Decoupled remediation effort estimate based on issue type"""
        cat_lower = (category or "").lower()
        if "secret" in cat_lower or "credential" in cat_lower:
            # Secrets require rotation, git purge, or environment variable refactoring
            return RemediationCategory.MEDIUM
        elif "crypto" in cat_lower:
            # Cryptographic algorithm upgrade can require schema/data migration
            return RemediationCategory.HIGH
        elif "injection" in cat_lower:
            # Parameterized queries or safe APIs
            return RemediationCategory.MEDIUM
        elif "misconfiguration" in cat_lower or "debug" in cat_lower or "verify" in cat_lower:
            # 1-line config or flag change
            return RemediationCategory.LOW
        return RemediationCategory.MEDIUM

    @classmethod
    def normalize_raw_finding(cls, raw: RawFinding) -> (NormalizedFinding, FindingInstance):
        """Convert a single RawFinding to a canonical finding and its detector instance"""
        posix_path = normalize_path(raw.file)
        fingerprint = compute_canonical_fingerprint(
            rule_id=raw.rule_id,
            file_path=posix_path,
            line=raw.line,
            snippet=raw.snippet
        )

        detector_id = raw.metadata.get("scanner", "unknown_detector")
        detector_version = raw.metadata.get("scanner_version")

        # Evidence hash of the match
        evidence_content = f"{raw.snippet or ''}:{raw.line or 0}:{raw.message or ''}"
        evidence_hash = hashlib.sha256(evidence_content.encode("utf-8")).hexdigest()

        severity, unknown_sev = cls.normalize_severity(raw.severity)
        confidence = cls.normalize_confidence(raw.metadata.get("confidence"))
        remediation_effort = cls.estimate_remediation_effort(raw.category, severity)

        instance = FindingInstance(
            detector_id=detector_id,
            detector_version=detector_version,
            rule_id=raw.rule_id,
            file=posix_path,
            line=raw.line,
            raw_severity=raw.severity,
            raw_message=raw.message,
            snippet=raw.snippet,
            evidence_hash=evidence_hash,
            metadata=raw.metadata
        )

        finding = NormalizedFinding(
            id=f"find_{fingerprint[:16]}",
            canonical_fingerprint=fingerprint,
            title=raw.message or f"Issue {raw.rule_id}",
            category=raw.category or "Unknown",
            file=posix_path,
            line=raw.line,
            rule_id=raw.rule_id,
            severity=severity,
            confidence=confidence,
            exposure=ExposureCategory.UNKNOWN,
            unknown_exposure=True,
            unknown_severity=unknown_sev,
            remediation_effort=remediation_effort,
            status=FindingStatus.OPEN,
            primary_snippet=raw.snippet,
            instances=[instance]
        )

        return finding, instance

    @classmethod
    def normalize_and_deduplicate(cls, raw_findings: List[RawFinding]) -> List[NormalizedFinding]:
        """
        Normalize a list of raw findings and deduplicate by canonical fingerprint.
        Duplicate instances are consolidated under the canonical finding.
        """
        dedup_map: Dict[str, NormalizedFinding] = {}

        for raw in raw_findings:
            canonical, instance = cls.normalize_raw_finding(raw)
            fp = canonical.canonical_fingerprint

            if fp in dedup_map:
                existing = dedup_map[fp]
                # Attach instance
                existing.instances.append(instance)

                # Consolidate severity to highest observed
                if SEVERITY_ORDER[canonical.severity] > SEVERITY_ORDER[existing.severity]:
                    existing.severity = canonical.severity
                    existing.unknown_severity = canonical.unknown_severity

                # Consolidate confidence to highest observed
                if CONFIDENCE_ORDER[canonical.confidence] > CONFIDENCE_ORDER[existing.confidence]:
                    existing.confidence = canonical.confidence

                # Use snippet if existing is empty
                if not existing.primary_snippet and canonical.primary_snippet:
                    existing.primary_snippet = canonical.primary_snippet
            else:
                dedup_map[fp] = canonical

        return list(dedup_map.values())
