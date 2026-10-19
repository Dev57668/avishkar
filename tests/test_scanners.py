import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure backend is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from scanners.base import (
    BaseScanner,
    RawFinding,
    ScannerError,
    ScannerUnavailableError,
    ScannerExecutionError,
    ScannerTimeoutError
)
from scanners.semgrep_scanner import SemgrepScanner
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.custom_scanner import CustomScanner


class TestScannerFailureHandling:
    """Verify requirement 7: A failed or unavailable scanner can never produce a successful clean result"""

    def test_gitleaks_unavailable_raises_error(self, tmp_path):
        """When Gitleaks is not available, scan() MUST raise ScannerUnavailableError, never return []"""
        scanner = GitleaksScanner()
        with patch.object(scanner, 'is_available', return_value=False):
            with pytest.raises(ScannerUnavailableError) as exc_info:
                scanner.scan(tmp_path)
            assert "not installed or available" in str(exc_info.value)

    def test_gitleaks_execution_failure_raises_error(self, tmp_path):
        """When Gitleaks returns non-zero exit code (other than 0, 1), scan() MUST raise ScannerExecutionError"""
        scanner = GitleaksScanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stderr = "Fatal error in scanner execution"
        with patch.object(scanner, 'is_available', return_value=True), \
             patch('subprocess.run', return_value=mock_proc):
            with pytest.raises(ScannerExecutionError) as exc_info:
                scanner.scan(tmp_path)
            assert "failed with exit code 2" in str(exc_info.value)

    def test_gitleaks_timeout_raises_timeout_error(self, tmp_path):
        """When Gitleaks times out, scan() MUST raise ScannerTimeoutError"""
        import subprocess
        scanner = GitleaksScanner()
        with patch.object(scanner, 'is_available', return_value=True), \
             patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd="gitleaks", timeout=10)):
            with pytest.raises(ScannerTimeoutError):
                scanner.scan(tmp_path)

    def test_semgrep_unavailable_raises_error(self, tmp_path):
        """When Semgrep is not available, scan() MUST raise ScannerUnavailableError, never return []"""
        scanner = SemgrepScanner()
        with patch.object(scanner, 'is_available', return_value=False):
            with pytest.raises(ScannerUnavailableError) as exc_info:
                scanner.scan(tmp_path)
            assert "not installed or available" in str(exc_info.value)

    def test_semgrep_execution_failure_raises_error(self, tmp_path):
        """When Semgrep returns an unexpected exit code, scan() MUST raise ScannerExecutionError"""
        scanner = SemgrepScanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stderr = "Semgrep syntax rule error"
        with patch.object(scanner, 'is_available', return_value=True), \
             patch('subprocess.run', return_value=mock_proc):
            with pytest.raises(ScannerExecutionError) as exc_info:
                scanner.scan(tmp_path)
            assert "failed with exit code 2" in str(exc_info.value)

    def test_semgrep_timeout_raises_timeout_error(self, tmp_path):
        """When Semgrep times out, scan() MUST raise ScannerTimeoutError"""
        import subprocess
        scanner = SemgrepScanner()
        with patch.object(scanner, 'is_available', return_value=True), \
             patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=10)):
            with pytest.raises(ScannerTimeoutError):
                scanner.scan(tmp_path)

    def test_custom_scanner_invalid_workspace_raises_error(self):
        """Custom scanner on non-existent workspace must raise ScannerExecutionError"""
        scanner = CustomScanner()
        non_existent = Path("non_existent_directory_for_testing_12345")
        with pytest.raises(ScannerExecutionError):
            scanner.scan(non_existent)


class TestCustomScannerDetection:
    """Verify CustomScanner AST and regex detection and Python 3.14 compatibility"""

    def test_custom_scanner_detects_command_injection(self, tmp_path):
        """Verify AST visitor detects os.system with formatted strings (Python 3.14 compatible)"""
        code = (
            "import os\n"
            "user_input = '127.0.0.1'\n"
            "os.system(f'ping {user_input}')\n"
        )
        file_path = tmp_path / "cmd_inj.py"
        file_path.write_text(code, encoding="utf-8")

        scanner = CustomScanner()
        findings = scanner.scan(tmp_path)

        cmd_findings = [f for f in findings if f.rule_id == "command-injection"]
        assert len(cmd_findings) == 1
        assert cmd_findings[0].severity == "critical"
        assert cmd_findings[0].category == "Command Injection"
        assert cmd_findings[0].line == 3

    def test_custom_scanner_on_vulnerable_python_sample(self):
        """Verify CustomScanner detects all known issues in sample_projects/vulnerable-python"""
        sample_dir = Path(__file__).parent.parent / "sample_projects" / "vulnerable-python"
        if not sample_dir.exists():
            pytest.skip("sample_projects/vulnerable-python not found")

        scanner = CustomScanner()
        findings = scanner.scan(sample_dir)

        rule_ids = {f.rule_id for f in findings}
        assert "command-injection" in rule_ids
        assert "python-eval-usage" in rule_ids
        assert "python-pickle-loads" in rule_ids
        assert "python-md5-password" in rule_ids
        assert "python-sha1-password" in rule_ids
        assert "python-verify-false" in rule_ids
        assert "python-debug-true" in rule_ids
        assert len(findings) >= 8
