"""Secret redaction shared by the AI layer, external-scanner adapters and PR comments."""
from __future__ import annotations

import re

_SECRETISH = [
    re.compile(r"AKIA[0-9A-Z]{16}"), re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), re.compile(r"xox[baprs]-[\w-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"""(?i)(api[_-]?key|secret|passwd|password|token)(\s*[:=]\s*)["'][^"']{6,}["']"""),
]


def redact_text(s: str) -> str:
    for rx in _SECRETISH:
        s = rx.sub(lambda m: "[REDACTED]" if m.lastindex is None else f"{m.group(1)}{m.group(2)}[REDACTED]", s)
    return s
