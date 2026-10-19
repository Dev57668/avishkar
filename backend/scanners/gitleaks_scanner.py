"""
Gitleaks secret scanner integration
"""

import json
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List

from scanners.base import (
    BaseScanner,
    RawFinding,
    ScannerError,
    ScannerUnavailableError,
    ScannerExecutionError,
    ScannerTimeoutError
)
from config import settings

logger = logging.getLogger(__name__)


class GitleaksScanner(BaseScanner):
    """Gitleaks secret detection scanner"""

    def __init__(self):
        super().__init__("Gitleaks")

    def is_available(self) -> bool:
        """Check if Gitleaks is installed"""
        try:
            exe = settings.GITLEAKS_PATH
            if not shutil.which(exe) and not Path(exe).is_file():
                return False
            result = subprocess.run(
                [exe, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Gitleaks not available: {e}")
            return False

    def scan(self, workspace_path: Path) -> List[RawFinding]:
        """
        Run Gitleaks scan

        Args:
            workspace_path: Path to code workspace

        Returns:
            List of RawFinding objects

        Raises:
            ScannerUnavailableError: If Gitleaks is not available
            ScannerExecutionError: If Gitleaks execution fails
            ScannerTimeoutError: If Gitleaks scan times out
        """
        if not self.is_available():
            raise ScannerUnavailableError(f"Gitleaks is not installed or available at '{settings.GITLEAKS_PATH}'")

        findings = []

        try:
            logger.info(f"Running Gitleaks scan on {workspace_path}")

            # Create temp report file
            report_path = workspace_path / "gitleaks_report.json"

            # Run Gitleaks
            cmd = [
                settings.GITLEAKS_PATH,
                "detect",
                "--source", str(workspace_path),
                "--report-format", "json",
                "--report-path", str(report_path),
                "--no-git"  # Scan files, not git history
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.MAX_SCAN_TIME_SECONDS
            )

            # Gitleaks returns exit code 1 when secrets are found
            if result.returncode not in [0, 1]:
                logger.error(f"Gitleaks error: {result.stderr}")
                raise ScannerExecutionError(f"Gitleaks failed with exit code {result.returncode}: {result.stderr.strip()}")

            # Parse report if it exists
            if report_path.exists():
                with open(report_path, 'r') as f:
                    results = json.load(f)

                logger.info(f"Gitleaks found {len(results)} secrets")

                # Convert to RawFinding
                for item in results:
                    # Redact secret value
                    secret = item.get("Secret", "")
                    redacted_secret = self._redact_secret(secret)

                    finding = RawFinding(
                        file=self._relative_path(item.get("File", ""), workspace_path),
                        line=item.get("StartLine", 0),
                        rule_id=item.get("RuleID", "secret-detected"),
                        message=f"Potential secret detected: {item.get('Description', 'Unknown')}",
                        severity="critical",  # Secrets are always critical
                        category="Hardcoded Secrets",
                        snippet=self._create_redacted_snippet(item.get("Match", ""), secret),
                        metadata={
                            "scanner": "gitleaks",
                            "rule": item.get("RuleID", ""),
                            "redacted_value": redacted_secret,
                            "entropy": item.get("Entropy", 0)
                        }
                    )
                    findings.append(finding)

                # Clean up report
                report_path.unlink()

        except subprocess.TimeoutExpired:
            logger.error(f"Gitleaks scan timed out after {settings.MAX_SCAN_TIME_SECONDS}s")
            raise ScannerTimeoutError(f"Gitleaks scan timed out after {settings.MAX_SCAN_TIME_SECONDS}s")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gitleaks output: {e}")
            raise ScannerExecutionError(f"Failed to parse Gitleaks output: {e}")
        except ScannerError:
            raise
        except Exception as e:
            logger.error(f"Gitleaks scan error: {e}")
            raise ScannerExecutionError(f"Gitleaks scan error: {e}")

        return findings

    @staticmethod
    def _redact_secret(secret: str) -> str:
        """Redact secret value, keeping only first 4 characters"""
        if len(secret) <= 4:
            return "***"
        return f"{secret[:4]}***"

    @staticmethod
    def _create_redacted_snippet(match: str, secret: str) -> str:
        """Create code snippet with redacted secret"""
        if not match or not secret:
            return ""

        redacted = GitleaksScanner._redact_secret(secret)
        return match.replace(secret, redacted)

    @staticmethod
    def _relative_path(file_path: str, workspace_path: Path) -> str:
        """Convert absolute path to relative path from workspace"""
        try:
            return str(Path(file_path).relative_to(workspace_path))
        except ValueError:
            return file_path
