"""
Base scanner interface
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass


class ScannerError(Exception):
    """Base exception for scanner errors"""
    pass


class ScannerUnavailableError(ScannerError):
    """Raised when a scanner is not installed or unavailable"""
    pass


class ScannerExecutionError(ScannerError):
    """Raised when a scanner fails during execution"""
    pass


class ScannerTimeoutError(ScannerExecutionError):
    """Raised when a scanner times out during execution"""
    pass


@dataclass
class RawFinding:
    """Raw finding from a scanner before normalization"""
    file: str
    line: int
    rule_id: str
    message: str
    severity: str
    category: str = "Unknown"
    snippet: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseScanner(ABC):
    """Base class for security scanners"""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def scan(self, workspace_path: Path) -> List[RawFinding]:
        """
        Scan a workspace and return raw findings

        Args:
            workspace_path: Path to code workspace

        Returns:
            List of RawFinding objects
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if scanner is available/installed

        Returns:
            True if scanner can be used
        """
        pass

    def get_name(self) -> str:
        """Get scanner name"""
        return self.name
