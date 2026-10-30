"""Secret redaction shared by the AI layer, the assistant, external-scanner adapters, reports and PR comments.

Defence in depth, not a guarantee: it removes well-known credential shapes (cloud keys, tokens, private keys, JWTs,
bearer/basic credentials, passwords in URLs) and values assigned to credential-looking names (quoted or not) from text
that is about to leave a trust boundary. Scanners already redact their own evidence; this is the second barrier.
Ordinary code is left alone: an unquoted value is only redacted when it looks like a secret (digits, symbols or mixed
case), so `password = request.form` or `token = get_token()` keep their meaning.
"""
from __future__ import annotations

import re

R = "[REDACTED]"
_WHOLE = [  # the entire match is a secret
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[\w-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:sk|pk|rk)[_-](?:live|test|ant|proj)?[_-]?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"),  # JWT
]
_BEARER = re.compile(r"(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._\-+/=]{12,}")
_URL_CRED = re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^@\s/]{3,}(@)")
_NAME = r"[\w.\-]*(?:api[_-]?key|apikey|secret|passwd|password|passphrase|token|auth|credential)[\w\-]*"
_QUOTED = re.compile(rf"""(?i)\b({_NAME})(\s*[:=]\s*)(?:"[^"\n]{{3,}}"|'[^'\n]{{3,}}')""")
_UNQUOTED = re.compile(rf"""(?i)\b({_NAME})(\s*[:=]\s*)([^\s"',;()\[\]{{}}]{{6,}})(?![(\w])""")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z_.]*$")


def _looks_secret(v: str) -> bool:
    if _IDENT.match(v):  # a bare identifier / attribute chain is code, not a value
        return False
    return bool(re.search(r"\d", v) or re.search(r"[!@#$%^&*+/=~]", v) or (v != v.lower() and v != v.upper()))


def redact_text(s: str) -> str:
    for rx in _WHOLE:
        s = rx.sub(R, s)
    s = _BEARER.sub(lambda m: f"{m.group(1)}{m.group(2)}{R}", s)
    s = _URL_CRED.sub(lambda m: f"{m.group(1)}{R}{m.group(2)}", s)
    s = _QUOTED.sub(lambda m: f"{m.group(1)}{m.group(2)}{R}", s)
    s = _UNQUOTED.sub(lambda m: f"{m.group(1)}{m.group(2)}{R}" if _looks_secret(m.group(3)) else m.group(0), s)
    return s
