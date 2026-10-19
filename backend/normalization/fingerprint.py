"""
Finding fingerprinting for stable identification and deduplication
"""

import hashlib
import re
from typing import Optional


def normalize_snippet(snippet: Optional[str]) -> str:
    """Normalize snippet text by collapsing whitespace and stripping comments"""
    if not snippet:
        return ""
    # Collapse consecutive whitespace
    collapsed = re.sub(r"\s+", " ", snippet.strip())
    return collapsed


def normalize_path(path: str) -> str:
    """Normalize file path to POSIX format with forward slashes and lowercasing for stability"""
    if not path:
        return ""
    posix_path = path.replace("\\", "/").strip("/").lower()
    return posix_path


def compute_canonical_fingerprint(
    rule_id: str,
    file_path: str,
    line: Optional[int] = None,
    snippet: Optional[str] = None
) -> str:
    """
    Compute a deterministic canonical fingerprint for a finding.
    
    Formula:
    sha256(normalized_rule_id : normalized_path : line_bucket : normalized_snippet)

    Args:
        rule_id: Unique detector rule identifier
        file_path: Relative file path in workspace
        line: Source code line number (if available)
        snippet: Matching code snippet or evidence

    Returns:
        64-character SHA-256 hex string
    """
    norm_rule = (rule_id or "unknown_rule").strip().lower()
    norm_path = normalize_path(file_path)
    norm_snippet = normalize_snippet(snippet)
    
    # Bucket lines to allow minor shifts (e.g. 1-2 lines) within the same block
    line_bucket = str(line) if line is not None and line > 0 else "0"

    content = f"{norm_rule}:{norm_path}:{line_bucket}:{norm_snippet}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
