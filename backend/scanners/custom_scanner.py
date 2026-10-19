"""
Custom Python security scanner using AST analysis
"""

import ast
import re
import logging
from pathlib import Path
from typing import List
import json

from scanners.base import (
    BaseScanner,
    RawFinding,
    ScannerError,
    ScannerExecutionError
)
from config import settings

logger = logging.getLogger(__name__)


class CustomScanner(BaseScanner):
    """Custom Python security pattern scanner"""

    def __init__(self, rules_path: Path = None):
        super().__init__("CustomPython")
        self.rules_path = rules_path or Path("rules/security_rules.json")
        self.rules = self._load_rules()

    def is_available(self) -> bool:
        """Always available (built-in scanner)"""
        return True

    def scan(self, workspace_path: Path) -> List[RawFinding]:
        """
        Scan Python files for security issues

        Args:
            workspace_path: Path to code workspace

        Returns:
            List of RawFinding objects

        Raises:
            ScannerExecutionError: If scan fails critically
        """
        if not workspace_path.exists():
            raise ScannerExecutionError(f"Workspace does not exist: {workspace_path}")

        findings = []

        try:
            logger.info(f"Running custom Python scan on {workspace_path}")

            # Find all Python files
            python_files = list(workspace_path.rglob("*.py"))
            logger.info(f"Found {len(python_files)} Python files")

            for py_file in python_files:
                try:
                    # AST-based analysis
                    findings.extend(self._scan_file_ast(py_file, workspace_path))

                    # Regex-based pattern matching
                    findings.extend(self._scan_file_patterns(py_file, workspace_path))

                except Exception as e:
                    logger.warning(f"Error scanning {py_file}: {e}")

            logger.info(f"Custom scanner found {len(findings)} issues")

        except ScannerError:
            raise
        except Exception as e:
            logger.error(f"Custom scan error: {e}")
            raise ScannerExecutionError(f"Custom scan error: {e}")

        return findings

    def _scan_file_ast(self, file_path: Path, workspace: Path) -> List[RawFinding]:
        """Scan file using AST parsing"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()

            tree = ast.parse(source, filename=str(file_path))
            visitor = SecurityVisitor(file_path, workspace, source_code=source)
            visitor.visit(tree)
            findings.extend(visitor.findings)

        except SyntaxError as e:
            logger.debug(f"Syntax error in {file_path}: {e}")
        except Exception as e:
            logger.warning(f"AST analysis error for {file_path}: {e}")

        return findings

    def _scan_file_patterns(self, file_path: Path, workspace: Path) -> List[RawFinding]:
        """Scan file using regex patterns"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, start=1):
                # Check each rule pattern
                for rule in self.rules:
                    pattern = rule.get("pattern", "")
                    if re.search(pattern, line, re.IGNORECASE):
                        rel_path = str(file_path.relative_to(workspace))

                        finding = RawFinding(
                            file=rel_path,
                            line=line_num,
                            rule_id=rule.get("id", "CUSTOM"),
                            message=rule.get("message", "Security issue detected"),
                            severity=rule.get("severity", "medium"),
                            category=rule.get("category", "Security Misconfiguration"),
                            snippet=line.strip(),
                            metadata={"scanner": "custom", "pattern": pattern}
                        )
                        findings.append(finding)

        except Exception as e:
            logger.warning(f"Pattern analysis error for {file_path}: {e}")

        return findings

    def _load_rules(self) -> List[dict]:
        """Load custom security rules"""
        default_rules = [
            {
                "id": "python-eval-usage",
                "pattern": r"\beval\s*\(",
                "message": "Use of eval() can execute arbitrary code",
                "severity": "critical",
                "category": "Code Injection"
            },
            {
                "id": "python-exec-usage",
                "pattern": r"\bexec\s*\(",
                "message": "Use of exec() can execute arbitrary code",
                "severity": "critical",
                "category": "Code Injection"
            },
            {
                "id": "python-md5-password",
                "pattern": r"hashlib\.md5\(",
                "message": "MD5 is cryptographically broken, use bcrypt or Argon2",
                "severity": "high",
                "category": "Weak Cryptography"
            },
            {
                "id": "python-sha1-password",
                "pattern": r"hashlib\.sha1\(",
                "message": "SHA1 is weak for password hashing, use bcrypt or Argon2",
                "severity": "high",
                "category": "Weak Cryptography"
            },
            {
                "id": "python-pickle-loads",
                "pattern": r"pickle\.loads?\(",
                "message": "Pickle deserialization can execute arbitrary code",
                "severity": "critical",
                "category": "Insecure Deserialization"
            },
            {
                "id": "python-verify-false",
                "pattern": r"verify\s*=\s*False",
                "message": "SSL/TLS verification disabled",
                "severity": "high",
                "category": "Security Misconfiguration"
            },
            {
                "id": "python-debug-true",
                "pattern": r"debug\s*=\s*True",
                "message": "Debug mode enabled in production",
                "severity": "medium",
                "category": "Security Misconfiguration"
            }
        ]

        # Try to load from file if it exists
        if self.rules_path.exists():
            try:
                with open(self.rules_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not load rules from {self.rules_path}: {e}")

        return default_rules


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor to detect security issues"""

    def __init__(self, file_path: Path, workspace: Path, source_code: str = ""):
        self.file_path = file_path
        self.workspace = workspace
        self.findings = []
        self.source_code = source_code

    @staticmethod
    def _is_str_like(node):
        """Check if AST node represents string or formatted string in any Python version"""
        if hasattr(ast, 'Str') and isinstance(node, ast.Str):
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue)):
            return True
        return False

    def visit_Call(self, node):
        """Check function calls for dangerous patterns"""
        func_name = self._get_func_name(node.func)

        # Check for os.system / subprocess.call with string argument
        if func_name in ['os.system', 'subprocess.call', 'subprocess.run']:
            if node.args and self._is_str_like(node.args[0]):
                snippet = ""
                if self.source_code:
                    snippet = ast.get_source_segment(self.source_code, node) or ""
                self.findings.append(RawFinding(
                    file=str(self.file_path.relative_to(self.workspace)),
                    line=node.lineno,
                    rule_id="command-injection",
                    message=f"Potential command injection via {func_name}",
                    severity="critical",
                    category="Command Injection",
                    snippet=snippet,
                    metadata={"scanner": "custom-ast", "function": func_name}
                ))

        self.generic_visit(node)

    @staticmethod
    def _get_func_name(node):
        """Get function name from call node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = SecurityVisitor._get_func_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return ""
