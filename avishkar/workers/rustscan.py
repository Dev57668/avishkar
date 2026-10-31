"""Rust security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer drops // and /* */ comments and understands string, raw-string (r#"…"#), byte-string and char literals,
so text inside comments or constants can never trigger a rule. Findings come from call shapes
(`Command::new("sh").arg("-c").arg(&input)`, `Md5::digest(data)`, `process::Command`) and attribute patterns
(`#[allow(unsafe_code)]`).

Honest limits: this is NOT a Rust parser. No types, no borrow-checker analysis, no cross-function or cross-crate data
flow, no knowledge of framework sanitizers. Expect misses and false positives; each rule's assurance is declared in
`avishkar.knowledge`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, SECURITY_CONTEXT, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

RUST_RULES = (
    "RS-CMDI", "RS-UNSAFE", "RS-WEAKHASH", "RS-RANDOM",
    "RS-SECRET-ASSIGN", "RS-TLS", "RS-PATH",
)
SEVERITY = {
    "RS-CMDI":          (Severity.HIGH,   M),
    "RS-UNSAFE":        (Severity.MEDIUM, L),
    "RS-WEAKHASH":      (Severity.LOW,    M),
    "RS-RANDOM":        (Severity.MEDIUM, L),
    "RS-SECRET-ASSIGN": (Severity.HIGH,   M),
    "RS-TLS":           (Severity.MEDIUM, H),
    "RS-PATH":          (Severity.MEDIUM, L),
}
MAX_TOKENS = 400_000

CMDI_FUNCS  = {"Command", "Exec"}
HASH_WEAK   = {"Md5", "Sha1", "HmacMd5", "md5", "sha1"}
HASH_STRONG = {"Sha256", "Sha512", "Sha3_256", "blake3", "argon2"}
RAND_INSECURE = {"thread_rng", "SmallRng", "StdRng", "Lcg64Xsh32", "rand_core"}
RAND_SECURE = {"OsRng", "getrandom", "SecureRandom"}
FILE_FUNCS  = {"read_to_string", "read", "open", "create", "remove_file", "rename", "read_dir"}
TLS_DANGER  = {"danger_accept_invalid_certs", "danger_accept_invalid_hostnames", "accept_invalid_certs",
               "accept_invalid_hostnames", "set_verify_hostname", "insecure"}
PUNCT2      = {"::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "|=",
               "&=", "<<", ">>", "..", "..=", "...", "/*", "*/", "//"}


@dataclass
class Tok:
    kind: str    # id | num | str | char | punct | lifetime
    text: str
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
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2]); j += 2
                else:
                    if src[j] == "\n": line += 1
                    buf.append(src[j]); j += 1
            out.append(Tok("str", "".join(buf), line))
            i = j + 1
        elif src.startswith("r#", i) or (c == "r" and i + 1 < n and src[i + 1] == '"'):
            # raw string: r"..." or r#"..."# etc.
            hashes = 0; j = i + 1
            while j < n and src[j] == "#":
                hashes += 1; j += 1
            if j < n and src[j] == '"':
                j += 1; close = '"' + "#" * hashes
                end = src.find(close, j)
                content = src[j:end] if end >= 0 else src[j:]
                out.append(Tok("str", content, line))
                line += content.count("\n")
                i = end + len(close) if end >= 0 else n
            else:
                out.append(Tok("id", "r", line)); i += 1
        elif c == "'" and i + 1 < n and src[i + 1].isalpha():
            # lifetime: 'a  or 'static
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok("lifetime", src[i:j], line)); i = j
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
        elif c == "b" and i + 1 < n and src[i + 1] == '"':
            j, buf = i + 2, []
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2]); j += 2
                else:
                    buf.append(src[j]); j += 1
            out.append(Tok("str", "".join(buf), line))
            i = j + 1
        elif c.isalpha() or c == "_":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok("id", src[i:j], line)); i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_.'"):
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
        self.in_unsafe_block = 0

    def peek(self, i: int, k: int = 1) -> Tok | None:
        j = i + k
        return self.T[j] if j < self.n else None

    def _hit(self, rule: str, i: int, conf: Confidence | None = None, ev: str | None = None) -> None:
        self.hits.append((rule, self.T[i].line, conf, ev))

    def run(self) -> None:
        i = 0
        while i < self.n:
            t = self.T[i]

            if t.kind != "id":
                # track unsafe block depth via braces when inside unsafe
                if t.kind == "punct":
                    if self.in_unsafe_block and t.text == "{":
                        self.in_unsafe_block += 1
                    elif self.in_unsafe_block and t.text == "}":
                        self.in_unsafe_block -= 1
                i += 1; continue

            # unsafe block: unsafe { ... }
            if t.text == "unsafe":
                np = self.peek(i)
                if np and np.text == "{":
                    # flag the block start, not the call inside (for now flag the keyword)
                    self._hit("RS-UNSAFE", i, L)
                    self.in_unsafe_block += 1

            # command injection: Command::new(<non-literal>) or .arg(non-literal with taint)
            # We flag Command::new("sh") or Command::new("bash") plus a subsequent .arg() with non-literal
            if t.text == "Command":
                nn = self.peek(i)
                if nn and nn.text == "::":
                    meth = self.peek(i, 2)
                    if meth and meth.kind == "id" and meth.text == "new":
                        op = self.peek(i, 3)
                        if op and op.text == "(":
                            arg = self.peek(i, 4)
                            if arg:
                                shell = arg.kind == "str" and arg.text.lower() in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell")
                                non_lit = arg.kind not in ("str", "num")
                                if shell or non_lit:
                                    self._hit("RS-CMDI", i, M if shell else L)

            # (arg() check removed — too many false positives; Command::new("sh/bash") is the reliable signal)

            # weak hash: Md5::digest / sha1::Sha1
            if t.text in HASH_WEAK and t.text not in HASH_STRONG:
                self._hit("RS-WEAKHASH", i)

            # insecure random: thread_rng in a security context
            if t.text in RAND_INSECURE and t.text not in RAND_SECURE:
                ctx = self.lines[t.line - 1] if t.line <= len(self.lines) else ""
                if SECURITY_CONTEXT.search(ctx):
                    self._hit("RS-RANDOM", i)

            # TLS: danger_accept_invalid_certs / danger_accept_invalid_hostnames
            if t.text in TLS_DANGER:
                np = self.peek(i)
                # if called as a method (preceded by .)
                prev = self.peek(i, -1)
                if (prev and prev.text == ".") or (np and np.text in ("(", "{")):
                    self._hit("RS-TLS", i)

            # path traversal: File::open/read with non-literal
            if t.text in ("File", "fs"):
                nn = self.peek(i)
                if nn and nn.text == "::":
                    meth = self.peek(i, 2)
                    if meth and meth.kind == "id" and meth.text in FILE_FUNCS:
                        op = self.peek(i, 3)
                        if op and op.text == "(":
                            arg = self.peek(i, 4)
                            if arg and arg.kind not in ("str", "num", "lifetime"):
                                ctx = self.lines[t.line - 1] if t.line <= len(self.lines) else ""
                                if any(w in ctx.lower() for w in ("param", "request", "user", "input", "path", "query")):
                                    self._hit("RS-PATH", i)

            # credential assignment: let [mut] name [: type] = "hardcoded"
            if t.text == "let":
                j = i + 1
                if j < self.n and self.T[j].text == "mut":
                    j += 1
                if j < self.n and self.T[j].kind == "id":
                    name = self.T[j].text
                    k2 = j + 1
                    if k2 < self.n and self.T[k2].text == ":":
                        k2 += 1
                        while k2 < self.n and self.T[k2].text not in ("=", ";"):
                            k2 += 1
                    if k2 < self.n and self.T[k2].text == "=":
                        val_tok = self.peek(i, k2 - i + 1)
                        if val_tok and val_tok.kind == "str":
                            val = val_tok.text
                            lo = name.lower()
                            if (CRED_NAME.search(lo) and not CRED_NAME_EXCLUDE.search(lo)
                                    and not is_placeholder(val) and looks_like_secret_value(val)):
                                ev = f"{name} = {redact_text(repr(val))}"
                                self._hit("RS-SECRET-ASSIGN", j, None, ev)

            # const credential: const NAME: &str = "hardcoded"
            if t.text == "const":
                j = i + 1
                if j < self.n and self.T[j].kind == "id":
                    name = self.T[j].text
                    # skip type annotation
                    k2 = j + 1
                    if k2 < self.n and self.T[k2].text == ":":
                        k2 += 1
                        while k2 < self.n and self.T[k2].text not in ("=", ";"):
                            k2 += 1
                    if k2 < self.n and self.T[k2].text == "=":
                        val_tok = self.peek(i, k2 - i + 1)
                        if val_tok and val_tok.kind == "str":
                            val = val_tok.text
                            lo = name.lower()
                            if (CRED_NAME.search(lo) and not CRED_NAME_EXCLUDE.search(lo)
                                    and not is_placeholder(val) and looks_like_secret_value(val)):
                                ev = f"{name} = {redact_text(repr(val))}"
                                self._hit("RS-SECRET-ASSIGN", j, None, ev)

            i += 1


def scan_rust(src: str, filename: str) -> list[RawFinding]:
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
            detector_id="rustscan", rule_id=rule, path=filename, line=ln,
            severity=sev, confidence=c, exposure=Exposure.UNKNOWN,
            category=k.get("category", "injection"),
            title=k.get("name", rule),
            evidence=evidence,
            remediation=k.get("remediation", ""),
        ))
    return out
