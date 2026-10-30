"""Shared name/value heuristics for credential and security-context detection (Python AST and JS token scanners)."""
from __future__ import annotations

import re

PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|change[_-]?me|your[_-]|xxxx|<.*>|dummy|test|sample|todo|\*{3,})")

# a variable / key name that suggests a credential
CRED_NAME = re.compile(r"(?i)(pass(word|wd|phrase)?|secret|token|api[_-]?key|apikey|private[_-]?key|auth[_-]?key|"
                       r"access[_-]?key|credential|encryption[_-]?key|signing[_-]?key|client[_-]?secret)")
# ...unless the name says it is *about* a credential rather than being one
CRED_NAME_EXCLUDE = re.compile(r"(?i)(_?(field|header|env|path|file|url|uri|name|label|prompt|regex|pattern|type|hint|"
                               r"help|prefix|suffix|expires?|ttl|length|size|min|max|count|policy|rule|message|text|"
                               r"input|param|placeholder|class|style|endpoint|dir|folder|location)s?$|^(is|has|use|get|set|"
                               r"validate|check|require)[_A-Z])")
# a function/variable name that suggests a value which must be unpredictable
SECURITY_CONTEXT = re.compile(r"(?i)(token|secret|passw|api[_-]?key|nonce|session|otp|salt|csrf|reset[_-]?code|"
                              r"verification|invite|auth[_-]?key)")


def looks_like_secret_value(v: str) -> bool:
    """A string literal worth reporting as a hard-coded credential: long enough, not prose/URL/path. Placeholders still
    qualify (callers report them at low confidence via is_placeholder) so test/demo values stay visible but quiet."""
    if len(v) < 8 or len(v) > 400:
        return False
    if v.count(" ") >= 3:  # sentence
        return False
    if re.match(r"(?i)^(https?|ftp|file)://", v) or v.startswith(("/", "./", "../", "~")):
        return False
    if re.fullmatch(r"[A-Za-z_]+", v) and v.lower() in {"password", "username", "secret", "token", "apikey", "api_key"}:
        return False
    return True


def is_placeholder(v: str) -> bool:
    return bool(PLACEHOLDER.search(v))
