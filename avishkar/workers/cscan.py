"""C/C++ security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer drops // and /* */ comments and understands string and character literals, so text inside comments or
constants can never trigger a rule. Findings come from call shapes (`strcpy(dst, src)`, `sprintf(buf, "%s", input)`,
`system(cmd)`) and type patterns (`gets(buf)`, `scanf("%s", buf)`). No data-flow tracking; rules fire on the call
site or variable shape alone and are labelled heuristic accordingly.

Honest limits: this is NOT a C/C++ parser. No types, no pointer analysis, no cross-file data flow, no knowledge of
compiler mitigations. Expect misses and false positives; each rule's assurance is declared in `avishkar.knowledge`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

C_RULES = (
    "C-BUFOV", "C-FMTSTR", "C-CMDI", "C-INTOV", "C-UAFALL",
    "C-WEAKHASH", "C-RANDOM", "C-SECRET-ASSIGN", "C-PATH",
)
SEVERITY = {
    "C-BUFOV":         (Severity.HIGH,     M),
    "C-FMTSTR":        (Severity.HIGH,     M),
    "C-CMDI":          (Severity.HIGH,     M),
    "C-INTOV":         (Severity.MEDIUM,   M),
    "C-UAFALL":        (Severity.MEDIUM,   L),
    "C-WEAKHASH":      (Severity.LOW,      M),
    "C-RANDOM":        (Severity.MEDIUM,   L),
    "C-SECRET-ASSIGN": (Severity.HIGH,     M),
    "C-PATH":          (Severity.MEDIUM,   L),
}
MAX_TOKENS = 400_000

# Unsafe functions by category
BUFOV_FUNCS    = {"strcpy", "strcat", "gets", "scanf", "vscanf", "sscanf", "fscanf", "sprintf", "vsprintf",
                  "strncpy", "strncat", "strtok", "memcpy", "memmove", "getwd", "realpath"}
SAFE_VARIANTS  = {"strncpy", "strncat", "snprintf", "vsnprintf", "strcpy_s", "strcat_s", "sprintf_s",
                  "strtok_s", "memcpy_s", "memmove_s"}  # still flag gets/scanf regardless
ALWAYS_UNSAFE  = {"gets", "strcpy", "strcat", "sprintf", "vsprintf"}
FMTSTR_FUNCS   = {"printf", "fprintf", "sprintf", "snprintf", "syslog", "dprintf", "vprintf",
                  "vfprintf", "vsprintf", "vsnprintf", "error"}
CMDI_FUNCS     = {"system", "popen", "execlp", "execvp", "execle", "execve", "execl", "execv",
                  "ShellExecute", "ShellExecuteA", "ShellExecuteW", "WinExec", "CreateProcess",
                  "CreateProcessA", "CreateProcessW"}
INTOV_FUNCS    = {"malloc", "calloc", "realloc", "new"}  # size arg from arithmetic
HASH_WEAK      = {"MD5_Init", "MD5_Update", "MD5_Final", "SHA1_Init", "SHA1_Update", "SHA1_Final",
                  "MD5", "SHA1", "EVP_md5", "EVP_sha1", "CC_MD5", "CC_SHA1"}
HASH_STRONG    = {"SHA256", "SHA512", "SHA3_256", "EVP_sha256", "EVP_sha512", "CC_SHA256"}
RAND_INSECURE  = {"rand", "random", "srand", "srandom", "drand48", "lrand48", "mrand48"}
RAND_SECURE    = {"RAND_bytes", "RAND_priv_bytes", "BCryptGenRandom", "getrandom", "arc4random"}
FILE_FUNCS     = {"fopen", "open", "creat", "unlink", "remove", "rename", "freopen", "access"}
CONST_NAME     = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
PUNCT2         = {"::", "->", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "<<", ">>",
                  "++", "--", "/*", "*/", "//"}


@dataclass
class Tok:
    kind: str    # id | num | str | char | punct
    text: str    # for str/char: content; for id: name
    line: int


def tokenize(src: str) -> list[Tok]:
    out: list[Tok] = []
    i, n, line = 0, len(src), 1
    while i < n and len(out) < MAX_TOKENS:
        c = src[i]
        if c == "\n":
            line += 1; i += 1
        elif c in " \t\r\f":
            i += 1
        elif src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j); i = j
        elif c == '"':
            j, buf = i + 1, []
            while j < n and src[j] != '"' and src[j] != "\n":
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2]); j += 2
                else:
                    buf.append(src[j]); j += 1
            out.append(Tok("str", "".join(buf), line))
            i = j + 1
        elif c == "'":
            j = i + 1
            if j < n and src[j] == "\\" and j + 1 < n:
                ch = src[j:j + 3]; j += 3
            elif j < n:
                ch = src[j]; j += 1
            else:
                ch = ""
            out.append(Tok("char", ch, line))
            if j < n and src[j] == "'":
                j += 1
            i = j
        elif c == "#":
            # preprocessor directive — skip line (but count line)
            while i < n and src[i] != "\n":
                i += 1
        elif c.isalpha() or c == "_":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok("id", src[i:j], line)); i = j
        elif c.isdigit() or (c in "+-" and i + 1 < n and src[i + 1].isdigit() and (not out or out[-1].kind == "punct")):
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            out.append(Tok("num", src[i:j], line)); i = j
        else:
            two = src[i:i + 2]
            if two in PUNCT2 and two not in ("/*", "*/", "//"):
                out.append(Tok("punct", two, line)); i += 2
            else:
                out.append(Tok("punct", c, line)); i += 1
    return out


class _Analyzer:
    def __init__(self, toks: list[Tok], lines: list[str]):
        self.T, self.n, self.lines = toks, len(toks), lines
        self.hits: list[tuple[str, int, Confidence | None, str | None]] = []

    def peek(self, i: int, k: int = 1) -> Tok | None:
        j = i + k
        return self.T[j] if j < self.n else None

    def _snip(self, i: int) -> str:
        t = self.T[i]
        return self.lines[t.line - 1].strip()[:120] if t.line <= len(self.lines) else ""

    def _hit(self, rule: str, i: int, conf: Confidence | None = None, ev: str | None = None) -> None:
        self.hits.append((rule, self.T[i].line, conf, ev))

    def _fmt_arg_is_nonliteral(self, open_p: int, skip_args: int = 0) -> bool:
        """Return True if the format argument (at position skip_args) is not a string literal."""
        j = open_p + 1  # first token inside the call
        # skip skip_args arguments (each delimited by a comma at depth 0)
        skipped = 0
        depth = 0
        while skipped < skip_args and j < self.n:
            tok2 = self.T[j]
            if tok2.text in ("(", "[", "{"): depth += 1
            elif tok2.text in (")", "]", "}"):
                depth -= 1
                if depth < 0:
                    return False
            elif tok2.text == "," and depth == 0:
                skipped += 1
            j += 1
        if j >= self.n:
            return False
        return self.T[j].kind not in ("str", "num")  # non-literal format

    def run(self) -> None:
        i = 0
        while i < self.n:
            t = self.T[i]

            if t.kind != "id":
                i += 1; continue

            # unsafe buffer functions
            if t.text in ALWAYS_UNSAFE:
                np = self.peek(i)
                if np and np.text == "(":
                    self._hit("C-BUFOV", i)

            # gets / scanf always unsafe (no safe variant)
            if t.text in ("gets", "scanf", "vscanf"):
                np = self.peek(i)
                if np and np.text == "(":
                    self._hit("C-BUFOV", i, H)

            # format-string: printf/fprintf/syslog with non-literal format arg
            # skip_args: how many leading args come before the format string
            _FMT_SKIP = {"printf": 0, "vprintf": 0, "error": 2,
                         "fprintf": 1, "dprintf": 1, "vfprintf": 1,
                         "sprintf": 1, "vsprintf": 1, "syslog": 1,
                         "snprintf": 2, "vsnprintf": 2}
            if t.text in FMTSTR_FUNCS:
                np = self.peek(i)
                if np and np.text == "(":
                    skip = _FMT_SKIP.get(t.text, 0)
                    if self._fmt_arg_is_nonliteral(i + 1, skip_args=skip):
                        self._hit("C-FMTSTR", i)

            # command injection: system/popen with non-literal string or variable
            if t.text in CMDI_FUNCS:
                np = self.peek(i)
                if np and np.text == "(":
                    arg_idx = i + 2
                    if arg_idx < self.n and self.T[arg_idx].kind not in ("str", "num"):
                        self._hit("C-CMDI", i)

            # weak hash
            if t.text in HASH_WEAK and t.text not in HASH_STRONG:
                self._hit("C-WEAKHASH", i)

            # insecure random in security context
            if t.text in RAND_INSECURE and t.text not in RAND_SECURE:
                from .shapes import SECURITY_CONTEXT
                ctx = self.lines[t.line - 1] if t.line <= len(self.lines) else ""
                if SECURITY_CONTEXT.search(ctx):
                    self._hit("C-RANDOM", i)

            # integer overflow: malloc/calloc/realloc with an arithmetic expression
            if t.text in INTOV_FUNCS:
                np = self.peek(i)
                if np and np.text == "(":
                    # look for * or + inside the argument
                    j = i + 2
                    depth = 1
                    while j < self.n and depth:
                        tok2 = self.T[j]
                        if tok2.text == "(": depth += 1
                        elif tok2.text == ")": depth -= 1
                        elif depth == 1 and tok2.text in ("*", "+", "-", "<<"):
                            self._hit("C-INTOV", i, L)
                            break
                        j += 1

            # credential assignment: const char *secret = "hardcoded";
            if t.text in ("char", "const"):
                # look for: (const) char* name = "literal"
                j = i + 1
                if j < self.n and self.T[j].text == "const":
                    j += 1
                if j < self.n and self.T[j].text == "char":
                    j += 1
                # skip * qualifiers
                while j < self.n and self.T[j].text in ("*", "const", "restrict", "volatile"):
                    j += 1
                if j < self.n and self.T[j].kind == "id":
                    name = self.T[j].text
                    if j + 2 < self.n and self.T[j + 1].text == "=" and self.T[j + 2].kind == "str":
                        val = self.T[j + 2].text
                        lo = name.lower()
                        if (CRED_NAME.search(lo) and not CRED_NAME_EXCLUDE.search(lo)
                                and not is_placeholder(val) and looks_like_secret_value(val)):
                            ev = f"{name} = {redact_text(repr(val))}"
                            self._hit("C-SECRET-ASSIGN", j, None, ev)

            i += 1


def scan_c(src: str, filename: str) -> list[RawFinding]:
    if not src.strip():
        return []
    toks = tokenize(src)
    lines = src.splitlines()
    a = _Analyzer(toks, lines)
    try:
        a.run()
    except Exception:  # noqa: BLE001
        return []
    out = []
    seen: set[tuple[str, int]] = set()
    for rule, ln, conf, ev in a.hits:
        if (rule, ln) in seen:
            continue
        seen.add((rule, ln))
        sev, base_conf = SEVERITY.get(rule, (Severity.MEDIUM, M))
        c = conf if conf is not None else base_conf
        k = knowledge.RULES.get(rule, {})
        line_text = lines[ln - 1].strip()[:200] if ln <= len(lines) else ""
        evidence = ev or redact_text(line_text)
        out.append(RawFinding(
            detector_id="cscan", rule_id=rule, path=filename, line=ln,
            severity=sev, confidence=c, exposure=Exposure.UNKNOWN,
            category=k.get("category", "injection"),
            title=k.get("name", rule),
            evidence=evidence,
            remediation=k.get("remediation", ""),
        ))
    return out
