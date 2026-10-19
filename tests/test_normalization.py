import pytest
import sys
from pathlib import Path

# Ensure backend is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


# pyrefly: ignore [missing-import]
from scanners.base import RawFinding
# pyrefly: ignore [missing-import]
from normalization.fingerprint import (
    compute_canonical_fingerprint
)
from normalization.models import (
    NormalizedFinding,
    FindingInstance,
    SeverityLevel,
    ExposureCategory,
    ConfidenceLevel,
    RemediationCategory,
    FindingStatus
)
from normalization.normalizer import FindingNormalizer


class TestFingerprinting:
    """Test deterministic canonical fingerprint calculation"""

    def test_reproducible_fingerprint(self):
        """Identical inputs produce identical fingerprint"""
        fp1 = compute_canonical_fingerprint("sql-injection", "src/db.py", 42, "SELECT * FROM users")
        fp2 = compute_canonical_fingerprint("sql-injection", "src/db.py", 42, "SELECT * FROM users")
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256

    def test_path_normalization_cross_platform(self):
        """Windows backslashes and case differences normalize to identical fingerprints"""
        fp_unix = compute_canonical_fingerprint("sql-inj", "src/db/users.py", 10, "query")
        fp_win = compute_canonical_fingerprint("sql-inj", "SRC\\DB\\USERS.PY", 10, "query")
        assert fp_unix == fp_win

    def test_whitespace_collapse_in_snippet(self):
        """Whitespace variations collapse to the same fingerprint"""
        fp1 = compute_canonical_fingerprint("rule-1", "app.py", 5, "os.system(  cmd  )")
        fp2 = compute_canonical_fingerprint("rule-1", "app.py", 5, "os.system( cmd )")
        assert fp1 == fp2

    def test_different_rules_or_files_yield_different_fingerprints(self):
        """Distinct rules or paths produce distinct fingerprints"""
        fp1 = compute_canonical_fingerprint("rule-a", "app.py", 5, "code")
        fp2 = compute_canonical_fingerprint("rule-b", "app.py", 5, "code")
        fp3 = compute_canonical_fingerprint("rule-a", "other.py", 5, "code")
        assert fp1 != fp2
        assert fp1 != fp3


class TestFindingNormalizer:
    """Test finding normalization and mapping"""

    def test_severity_normalization(self):
        """Verify mapping of known and unknown severities"""
        assert FindingNormalizer.normalize_severity("critical")[0] == SeverityLevel.CRITICAL
        assert FindingNormalizer.normalize_severity("ERROR")[0] == SeverityLevel.HIGH
        assert FindingNormalizer.normalize_severity("warning")[0] == SeverityLevel.MEDIUM
        assert FindingNormalizer.normalize_severity("minor")[0] == SeverityLevel.LOW
        assert FindingNormalizer.normalize_severity("info")[0] == SeverityLevel.INFORMATIONAL

        # Unknown severity defaults to MEDIUM with unknown_severity=True
        sev, unknown = FindingNormalizer.normalize_severity("unmapped_severity_value")
        assert sev == SeverityLevel.MEDIUM
        assert unknown is True

    def test_confidence_normalization(self):
        """Verify numeric and string confidence mapping"""
        assert FindingNormalizer.normalize_confidence(0.95) == ConfidenceLevel.HIGH
        assert FindingNormalizer.normalize_confidence(0.70) == ConfidenceLevel.MEDIUM
        assert FindingNormalizer.normalize_confidence(0.40) == ConfidenceLevel.LOW
        assert FindingNormalizer.normalize_confidence("certain") == ConfidenceLevel.HIGH
        assert FindingNormalizer.normalize_confidence("heuristic") == ConfidenceLevel.LOW
        assert FindingNormalizer.normalize_confidence(None) == ConfidenceLevel.MEDIUM

    def test_remediation_effort_decoupled(self):
        """Verify decoupled remediation effort estimation"""
        assert FindingNormalizer.estimate_remediation_effort("Hardcoded Secrets", SeverityLevel.CRITICAL) == RemediationCategory.MEDIUM
        assert FindingNormalizer.estimate_remediation_effort("Weak Cryptography", SeverityLevel.HIGH) == RemediationCategory.HIGH
        assert FindingNormalizer.estimate_remediation_effort("Security Misconfiguration", SeverityLevel.MEDIUM) == RemediationCategory.LOW


class TestFindingDeduplication:
    """Test cross-scanner deduplication logic"""

    def test_deduplicates_overlapping_scanner_findings(self):
        """
        When Semgrep and CustomAST both flag the same issue on the same line,
        they must consolidate into one canonical finding with two detector instances.
        """
        raw_semgrep = RawFinding(
            file="app.py",
            line=46,
            rule_id="command-injection",
            message="Semgrep detected command injection",
            severity="critical",
            category="Command Injection",
            snippet="os.system(f'ping {host}')",
            metadata={"scanner": "semgrep", "confidence": "HIGH"}
        )
        raw_custom = RawFinding(
            file="app.py",
            line=46,
            rule_id="command-injection",
            message="Custom AST detected command injection",
            severity="high",
            category="Command Injection",
            snippet="os.system(f'ping {host}')",
            metadata={"scanner": "custom-ast", "confidence": "MEDIUM"}
        )

        canonical_findings = FindingNormalizer.normalize_and_deduplicate([raw_semgrep, raw_custom])

        assert len(canonical_findings) == 1
        canonical = canonical_findings[0]
        # Consolidates to highest severity and confidence
        assert canonical.severity == SeverityLevel.CRITICAL
        assert canonical.confidence == ConfidenceLevel.HIGH
        assert len(canonical.instances) == 2
        detectors = {inst.detector_id for inst in canonical.instances}
        assert detectors == {"semgrep", "custom-ast"}

    def test_distinct_findings_are_preserved(self):
        """Distinct findings on different files or rules remain separate"""
        raw1 = RawFinding(
            file="app.py", line=10, rule_id="sql-injection", message="SQLi",
            severity="critical", category="Injection", snippet="SELECT *", metadata={"scanner": "s1"}
        )
        raw2 = RawFinding(
            file="auth.py", line=20, rule_id="hardcoded-key", message="Key",
            severity="critical", category="Secrets", snippet="API_KEY=123", metadata={"scanner": "s2"}
        )

        canonical_findings = FindingNormalizer.normalize_and_deduplicate([raw1, raw2])
        assert len(canonical_findings) == 2
