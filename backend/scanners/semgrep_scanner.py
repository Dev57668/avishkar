"""
Semgrep scanner integration
"""

import json
import os
import shutil
import subprocess
import sys
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


class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner"""

    def __init__(self):
        super().__init__("Semgrep")

    @staticmethod
    def _get_executable() -> str:
        """Resolve Semgrep executable path"""
        if settings.SEMGREP_PATH and settings.SEMGREP_PATH != "semgrep":
            return settings.SEMGREP_PATH
        which_path = shutil.which("semgrep")
        if which_path:
            return which_path
        # Check standard user Scripts directory on Windows
        user_script = Path(os.path.expandvars(r"%APPDATA%\Python\Python314\Scripts\semgrep.exe"))
        if user_script.exists():
            return str(user_script)
        python_script = Path(sys.executable).parent / "Scripts" / "semgrep.exe"
        if python_script.exists():
            return str(python_script)
        return "semgrep"

    def _get_env(self) -> dict:
        """Get environment with executable directory added to PATH"""
        env = os.environ.copy()
        exe = self._get_executable()
        exe_dir = str(Path(exe).parent)
        if exe_dir and exe_dir not in env.get("PATH", ""):
            env["PATH"] = exe_dir + os.pathsep + env.get("PATH", "")
        return env

    def is_available(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            exe = self._get_executable()
            result = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                env=self._get_env()
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Semgrep not available: {e}")
            return False

    def scan(self, workspace_path: Path) -> List[RawFinding]:
        """
        Run Semgrep scan

        Args:
            workspace_path: Path to code workspace

        Returns:
            List of RawFinding objects

        Raises:
            ScannerUnavailableError: If Semgrep is not available
            ScannerExecutionError: If Semgrep execution fails
            ScannerTimeoutError: If Semgrep scan times out
        """
        if not self.is_available():
            raise ScannerUnavailableError("Semgrep is not installed or available on this system")

        findings = []
        exe = self._get_executable()

        try:
            logger.info(f"Running Semgrep scan on {workspace_path}")

            # Run Semgrep with auto config (OWASP Top 10 rules)
            cmd = [
                exe,
                "--config=auto",
                "--json",
                "--quiet",
                str(workspace_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.MAX_SCAN_TIME_SECONDS,
                env=self._get_env()
            )

            if result.returncode not in [0, 1]:
                # Return code 1 means findings were found (not an error)
                logger.error(f"Semgrep error: {result.stderr}")
                raise ScannerExecutionError(f"Semgrep failed with exit code {result.returncode}: {result.stderr.strip()}")

            # Parse JSON output
            output = json.loads(result.stdout)
            results = output.get("results", [])

            logger.info(f"Semgrep found {len(results)} issues")

            # Convert to RawFinding
            for item in results:
                # Extract snippet
                snippet_lines = item.get("extra", {}).get("lines", "")

                finding = RawFinding(
                    file=self._relative_path(item.get("path", ""), workspace_path),
                    line=item.get("start", {}).get("line", 0),
                    rule_id=item.get("check_id", ""),
                    message=item.get("extra", {}).get("message", ""),
                    severity=self._map_severity(item.get("extra", {}).get("severity", "INFO")),
                    category=self._extract_category(item.get("check_id", "")),
                    snippet=snippet_lines,
                    metadata={
                        "scanner": "semgrep",
                        "confidence": item.get("extra", {}).get("metadata", {}).get("confidence", "MEDIUM")
                    }
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out after {settings.MAX_SCAN_TIME_SECONDS}s")
            raise ScannerTimeoutError(f"Semgrep scan timed out after {settings.MAX_SCAN_TIME_SECONDS}s")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            raise ScannerExecutionError(f"Failed to parse Semgrep output: {e}")
        except ScannerError:
            raise
        except Exception as e:
            logger.error(f"Semgrep scan error: {e}")
            raise ScannerExecutionError(f"Semgrep scan error: {e}")

        return findings

    @staticmethod
    def _map_severity(semgrep_severity: str) -> str:
        """Map Semgrep severity to normalized severity"""
        severity_map = {
            "ERROR": "critical",
            "WARNING": "high",
            "INFO": "medium"
        }
        return severity_map.get(semgrep_severity.upper(), "low")

    @staticmethod
    def _extract_category(rule_id: str) -> str:
        """Extract security category from Semgrep rule ID"""
        rule_id_lower = rule_id.lower()

        if "sql" in rule_id_lower or "injection" in rule_id_lower:
            return "Injection"
        elif "xss" in rule_id_lower or "cross-site" in rule_id_lower:
            return "XSS"
        elif "crypto" in rule_id_lower or "hash" in rule_id_lower:
            return "Weak Cryptography"
        elif "command" in rule_id_lower or "shell" in rule_id_lower:
            return "Command Injection"
        elif "path" in rule_id_lower or "traversal" in rule_id_lower:
            return "Path Traversal"
        elif "auth" in rule_id_lower:
            return "Authentication"
        elif "deserialize" in rule_id_lower or "pickle" in rule_id_lower:
            return "Deserialization"
        else:
            return "Security Misconfiguration"

    @staticmethod
    def _relative_path(file_path: str, workspace_path: Path) -> str:
        """Convert absolute path to relative path from workspace"""
        try:
            return str(Path(file_path).relative_to(workspace_path))
        except ValueError:
            return file_path
