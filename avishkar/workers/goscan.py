"""Go security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer drops comments and understands interpreted strings, raw (backtick) strings and rune literals, so text
inside comments or strings can never trigger a rule. Findings come from call and assignment shapes
(`exec.Command("sh", "-c", "ls "+dir)`, `db.Query(fmt.Sprintf(...))`, `tls.Config{InsecureSkipVerify: true}`). Only simple
same-file flows are followed: a value read from an HTTP request, or an SQL text built by formatting, that is later passed
to a sink.

Honest limits: this is NOT a Go parser. No types, no interfaces, no cross-function or cross-package data flow, and no
knowledge of framework sanitizers. Expect misses (a query built in another package) and some false positives; each rule's
assurance (structural vs heuristic) is declared in `avishkar.knowledge`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, SECURITY_CONTEXT, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
GO_RULES = ("GO-SQLI", "GO-CMDI", "GO-WEAKHASH", "GO-WEAKCIPHER", "GO-RANDOM", "GO-SECRET-ASSIGN", "GO-TLS", "GO-PATH",
            "GO-XSS-REFLECT")
SEVERITY = {"GO-SQLI": (Severity.HIGH, M), "GO-CMDI": (Severity.HIGH, M), "GO-WEAKHASH": (Severity.LOW, M),
            "GO-WEAKCIPHER": (Severity.MEDIUM, M), "GO-RANDOM": (Severity.MEDIUM, L), "GO-SECRET-ASSIGN": (Severity.HIGH, M),
            "GO-TLS": (Severity.MEDIUM, H), "GO-PATH": (Severity.MEDIUM, L), "GO-XSS-REFLECT": (Severity.MEDIUM, L)}
MAX_TOKENS = 400_000

SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter|where|from|values|union)\b")
SQL_SINKS = {"Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext", "Prepare", "PrepareContext",
             "Raw", "NamedExec", "NamedQuery", "Select", "Get"}
SINK_RESULT = {"Command", "CommandContext", "ReadFile", "Open", "OpenFile", "Query", "QueryRow", "Exec", "Output", "ReadAll"}
CONTEXT_FIRST = {"QueryContext", "QueryRowContext", "ExecContext", "PrepareContext"}  # the SQL text is the 2nd argument
ALWAYS_SOURCES = {"FormValue", "PostFormValue", "Param", "QueryParam", "PathValue", "Vars", "GetHeader", "PostForm"}
FILE_SINKS = {"Open", "OpenFile", "ReadFile", "ReadDir", "Create", "Remove", "RemoveAll", "WriteFile", "ServeFile", "Stat"}
ESCAPERS = {"EscapeString", "HTMLEscapeString", "HTMLEscaper", "QueryEscape", "Clean", "Base"}
SHELL_PROGS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "/bin/sh", "/bin/bash"}
SHELL_FLAGS = {"-c", "/c", "-command"}
CONST_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
PUNCT2 = {":=", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "<-", "..", "->"}


@dataclass
class Tok:
    kind: str       # id | num | str | rune | punct
    text: str       # for str/rune the unquoted content
    line: int


def tokenize(src: str) -> list[Tok]:
    out: list[Tok] = []
    i, n, line = 0, len(src), 1
    while i < n and len(out) < MAX_TOKENS:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r\f":
            i += 1
        elif src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
        elif c == "`":
            j = src.find("`", i + 1)
            j = n if j < 0 else j
            out.append(Tok("str", src[i + 1:j], line))
            line += src.count("\n", i, j)
            i = min(n, j + 1)
        elif c == '"' or c == "'":
            j, buf = i + 1, []
            while j < n and src[j] != c and src[j] != "\n":
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                else:
                    buf.append(src[j])
                    j += 1
            out.append(Tok("str" if c == '"' else "rune", "".join(buf), line))
            i = j + 1 if j < n and src[j] == c else j
        elif c.isalpha() or c == "_":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok("id", src[i:j], line))
            i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            out.append(Tok("num", src[i:j], line))
            i = j
        else:
            two = src[i:i + 2]
            if two in PUNCT2:
                out.append(Tok("punct", two, line))
                i += 2
            else:
                out.append(Tok("punct", c, line))
                i += 1
    return out


class _Analyzer:
    def __init__(self, toks: list[Tok], lines: list[str], text: str):
        self.T, self.n, self.lines, self.text = toks, len(toks), lines, text
        self.hits: list[tuple[str, int, Confidence | None, str | None]] = []
        self.pair: dict[int, int] = {}
        stack: list[int] = []
        for i, t in enumerate(toks):
            if t.kind == "punct" and t.text in "([{":
                stack.append(i)
            elif t.kind == "punct" and t.text in ")]}" and stack:
                self.pair[stack.pop()] = i
        self.open_of = {b: a for a, b in self.pair.items()}
        self.func_at = self._funcs()
        self.tainted: dict[tuple[str, str], list[tuple[int, bool]]] = {}
        self.built: dict[tuple[str, str], list[tuple[int, bool]]] = {}
        self.weak_rand = bool(re.search(r'"math/rand"', text)) and not re.search(r'"crypto/rand"', text)
        # a web handler reads HTTP request data somewhere in the file; only then is a concatenated path suspicious
        self.web = any(self._is_source(i) for i in range(self.n))

    # ------------------------------------------------------------------ helpers
    def txt(self, i: int) -> str:
        return self.T[i].text if 0 <= i < self.n else ""

    def is_p(self, i: int, s: str) -> bool:
        return 0 <= i < self.n and self.T[i].kind == "punct" and self.T[i].text == s

    def hit(self, rule: str, line: int, conf: Confidence | None = None, evidence: str | None = None):
        self.hits.append((rule, line, conf, evidence))

    def _funcs(self) -> list[str]:
        """For every token index, the name of the nearest enclosing `func name(...)` ('' when none or anonymous)."""
        T, names = self.T, [""] * self.n
        stack: list[str] = []
        for i, t in enumerate(T):
            names[i] = next((s for s in reversed(stack) if s), "")
            if t.kind == "punct" and t.text == "{":
                name, k = "", i - 1
                for _ in range(40):  # back over the signature: `func (r *T) Name(args) (ret, error) {`
                    if k < 0 or T[k].text in (";", "}", "{"):
                        break
                    if T[k].kind == "id" and T[k].text == "func":
                        j = k + 1
                        if self.is_p(j, "("):  # receiver
                            j = self.pair.get(j, j) + 1
                        if j < self.n and T[j].kind == "id":
                            name = T[j].text
                        break
                    k -= 1
                stack.append(name)
            elif t.kind == "punct" and t.text == "}" and stack:
                stack.pop()
        return names

    def _is_source(self, i: int) -> bool:
        t = self.T[i]
        if t.kind != "id":
            return False
        if t.text in ALWAYS_SOURCES:
            return True
        if t.text == "Query" and self.is_p(i - 1, ".") and self.txt(i - 2) in ("URL", "c", "ctx"):
            return True
        return t.text == "Path" and self.is_p(i - 1, ".") and self.txt(i - 2) == "URL"

    def args(self, open_i: int) -> list[tuple[int, int]]:
        close = self.pair.get(open_i)
        if close is None:
            return []
        out, depth, start = [], 0, open_i + 1
        for k in range(open_i + 1, close):
            t = self.T[k]
            if t.kind == "punct" and t.text in "([{":
                depth += 1
            elif t.kind == "punct" and t.text in ")]}":
                depth -= 1
            elif t.kind == "punct" and t.text == "," and depth == 0:
                out.append((start, k))
                start = k + 1
        if close > open_i + 1:
            out.append((start, close))
        return out

    def literal_only(self, lo: int, hi: int) -> bool:
        return hi > lo and all(t.kind in ("str", "rune", "num") or t.text in ("+", "(", ")") for t in self.T[lo:hi])

    def has_concat(self, lo: int, hi: int) -> bool:
        seg = self.T[lo:hi]
        if self.const_only(lo, hi):
            return False
        if any(t.kind == "punct" and t.text == "+" for t in seg) and not self.literal_only(lo, hi):
            return True
        return any(t.text in ("Sprintf", "Sprint") and k > 1 and seg[k - 2].text == "fmt" for k, t in enumerate(seg))

    def mentions_source(self, lo: int, hi: int) -> bool:
        return any(self._is_source(k) or (self.T[k].kind == "id" and self._scoped(self.tainted, k, self.T[k].text)) for k in range(lo, hi))

    def const_only(self, lo: int, hi: int) -> bool:
        """True when the expression is made of literals and constant-style names (ALL_CAPS, or qualified like Tables.USER_TB).
        `"DELETE FROM " + USER_TB_NAME + " WHERE id = ?"` is a fixed text, not data-dependent SQL."""
        seg = self.T[lo:hi]
        ok = False
        for k, t in enumerate(seg):
            if t.kind in ("str", "chr", "num") and not getattr(t, "interp", False):
                continue
            if t.kind == "punct" and t.text in ("+", ".", "(", ")"):
                continue
            if t.kind == "id" and (CONST_NAME.match(t.text) or (k + 1 < len(seg) and seg[k + 1].text == ".")):
                ok = ok or bool(CONST_NAME.match(t.text))
                continue
            return False
        return ok or self.literal_only(lo, hi)

    def _scoped(self, hist: dict, idx: int, name: str) -> bool:
        """State of `name` at token `idx`: decided by its latest assignment before idx in the same scope (or a parameter marker)."""
        for key in ((self.func_at[idx], name), ("*", name)):
            events = [flag for (j, flag) in hist.get(key, ()) if j < idx]
            if events:
                return events[-1]
        return False

    def _rec(self, hist: dict, idx: int, name: str, flag: bool) -> None:
        hist.setdefault((self.func_at[idx], name), []).append((idx, flag))


    def receiver(self, i: int) -> list[str]:
        out, k = [], i - 1
        while k >= 1 and self.is_p(k, "."):
            k -= 1
            if self.is_p(k, ")"):
                o = self.open_of.get(k)
                if o is None:
                    break
                k = o - 1
            if k >= 0 and self.T[k].kind == "id":
                out.append(self.T[k].text)
                k -= 1
            else:
                break
        return list(reversed(out))

    # ------------------------------------------------------------------ analysis
    def run(self):
        self._assignments()
        T, n = self.T, self.n
        for i in range(n):
            t = T[i]
            if t.kind != "id":
                continue
            if i + 1 < n and self.is_p(i + 1, "(") and self.is_p(i - 1, "."):
                self._call(i)
            elif t.text == "InsecureSkipVerify" and self.is_p(i + 1, ":") and self.txt(i + 2) == "true":
                self.hit("GO-TLS", t.line, H)
            elif t.text == "InsecureSkipVerify" and self.is_p(i + 1, "=") and self.txt(i + 2) == "true":
                self.hit("GO-TLS", t.line, H)
        self._secrets()
        return self.hits

    def _assignments(self):
        """`a, b := expr` / `a = expr`: names fed by request sources, and SQL texts built by formatting/concatenation."""
        T = self.T
        for i in range(1, self.n - 1):
            op = T[i].text if T[i].kind == "punct" else ""
            if op not in (":=", "=") or (op == "=" and (self.is_p(i + 1, "=") or self.is_p(i - 1, "!"))):
                continue
            names, k = [], i - 1
            while k >= 0 and (T[k].kind == "id" or self.is_p(k, ",")):
                if T[k].kind == "id":
                    names.append(T[k].text)
                k -= 1
            if not names:
                continue
            end = i + 1
            while end < self.n and end - i < 80 and not self.is_p(end, ";") and not self._stmt_end(end, i):
                end += 1
            lits = " ".join(t.text for t in T[i + 1:end] if t.kind == "str")
            # a value read back from a command, file or database is output of a sink, not request data
            sink_result = any(T[k].text in SINK_RESULT and self.is_p(k + 1, "(") for k in range(i + 1, end))
            src = self.mentions_source(i + 1, end) and not sink_result
            for nm in names:
                if nm == "_":
                    continue
                self._rec(self.tainted, i, nm, src)
                self._rec(self.built, i, nm, self.has_concat(i + 1, end) and bool(SQL_WORDS.search(lits)))

    def _stmt_end(self, k: int, start: int) -> bool:
        """A new statement begins on a later line when the previous line did not end with an operator or an open bracket."""
        T = self.T
        if T[k].line == T[start].line:
            return False
        prev = T[k - 1]
        return not (prev.kind == "punct" and prev.text in ("+", ",", "(", "{", "[", "&&", "||", "."))

    def _call(self, i: int):
        T, name, line = self.T, self.T[i].text, self.T[i].line
        a, recv = self.args(i + 1), self.receiver(i)
        last = recv[-1] if recv else ""
        if name in SQL_SINKS and last not in ("fmt", "strings", "exec"):
            idx = 1 if name in CONTEXT_FIRST else 0
            if idx < len(a):
                lo, hi = a[idx]
                lits = " ".join(t.text for t in T[lo:hi] if t.kind == "str")
                if self.has_concat(lo, hi) and (SQL_WORDS.search(lits) or self.mentions_source(lo, hi)):
                    self.hit("GO-SQLI", line, M)
                elif hi - lo == 1 and T[lo].kind == "id" and self._scoped(self.built, lo, T[lo].text):
                    self.hit("GO-SQLI", line, L)
        elif last == "exec" and name in ("Command", "CommandContext"):
            args = a[1:] if name == "CommandContext" else a
            if args:
                texts = [("".join(T[x].text for x in range(lo, hi) if T[x].kind == "str").lower(), self.literal_only(lo, hi))
                         for lo, hi in args]
                shell = texts[0][1] and texts[0][0] in SHELL_PROGS and any(t in SHELL_FLAGS for t, _ in texts[1:])
                if shell and any(not lit for _, lit in texts):
                    self.hit("GO-CMDI", line, M)
                elif not texts[0][1] and not self._plain_ident_ok(args[0]):
                    self.hit("GO-CMDI", line, M if self.mentions_source(*args[0]) else L)
        elif last in ("md5", "sha1") and name in ("New", "Sum"):
            self.hit("GO-WEAKHASH", line, M)
        elif last in ("des", "rc4") and name in ("NewCipher", "NewTripleDESCipher"):
            self.hit("GO-WEAKCIPHER", line, M)
        elif last == "rand" and self.weak_rand and name in ("Int", "Intn", "Int63", "Int31", "Uint32", "Uint64", "Read", "Seed", "Float64") \
                and SECURITY_CONTEXT.search(self.func_at[i] + " " + self._stmt_names(i)):
            self.hit("GO-RANDOM", line, L)
        elif a and name in FILE_SINKS and last in ("os", "ioutil", "http", "filepath") and self._path_tainted(a[-1] if name == "ServeFile" else a[0]):
            self.hit("GO-PATH", line, M if self.mentions_source(*(a[-1] if name == "ServeFile" else a[0])) else L)
        elif a and name == "Join" and last == "filepath" and any(self.mentions_source(lo, hi) for lo, hi in a) and not self._normalised_after(i):
            self.hit("GO-PATH", line, L)
        elif name in ("Fprintf", "Fprint", "Fprintln") and last == "fmt" and len(a) >= 2:
            lo, hi = a[0]
            if any(T[x].text in ("w", "rw", "res", "writer") for x in range(lo, hi)) and any(
                    self.mentions_source(l2, h2) and not any(T[x].text in ESCAPERS for x in range(l2, h2)) for l2, h2 in a[1:]):
                self.hit("GO-XSS-REFLECT", line, L)
        elif name in ("Write", "WriteString") and last in ("w", "rw", "res", "writer") and a:
            lo, hi = a[0]
            if self.mentions_source(lo, hi) and not any(T[x].text in ESCAPERS for x in range(lo, hi)):
                self.hit("GO-XSS-REFLECT", line, L)
        elif name == "WriteString" and last == "io" and len(a) >= 2:
            if self.mentions_source(*a[1]) and not any(T[x].text in ESCAPERS for x in range(*a[1])):
                self.hit("GO-XSS-REFLECT", line, L)

    def _plain_ident_ok(self, rng) -> bool:
        """exec.Command(name) where `name` is a bare identifier we cannot see through: only flag it when it is request data."""
        lo, hi = rng
        return hi - lo == 1 and self.T[lo].kind == "id" and not self.mentions_source(lo, hi)

    def _normalised_after(self, i: int) -> bool:
        return any(self.T[x].text in ("Clean", "Base", "EvalSymlinks", "Rel", "HasPrefix") for x in range(max(0, i - 6), min(self.n, i + 8)))

    def _stmt_names(self, i: int) -> str:
        k = i
        while k > 0 and self.txt(k) not in (";", "{", "}") and self.T[k].line >= self.T[i].line - 1:
            k -= 1
        return " ".join(t.text for t in self.T[k:i] if t.kind == "id")

    def _path_tainted(self, rng) -> bool:
        lo, hi = rng
        if any(self.T[x].text in ESCAPERS or self.T[x].text in ("EvalSymlinks", "Rel") for x in range(lo, hi)):
            return False
        return self.mentions_source(lo, hi) or (self.web and self.has_concat(lo, hi))

    def _secrets(self):
        """`name := "literal"`, `const name = "literal"`, `Name: "literal",` (struct fields and map keys)."""
        T = self.T
        for i in range(1, self.n - 1):
            op = T[i].text if T[i].kind == "punct" else ""
            if op in (":=", "=", ":") and T[i - 1].kind == "id" and T[i + 1].kind == "str":
                nxt = T[i + 2] if i + 2 < self.n else None  # None: the literal ends the file
                if nxt is not None and not (nxt.line > T[i + 1].line or nxt.text in (",", ";", ")", "}")):
                    continue  # part of a larger expression
                name = T[i - 1].text
                if op == "=" and (self.is_p(i + 1, "=") or self.is_p(i - 2, "!")):
                    continue
                if CRED_NAME.search(name) and not CRED_NAME_EXCLUDE.search(name):
                    val = T[i + 1].text
                    if looks_like_secret_value(val):
                        red = val[:2] + "*" * 6 if len(val) <= 8 else val[:4] + "*" * 6 + val[-2:]
                        self.hit("GO-SECRET-ASSIGN", T[i - 1].line, L if is_placeholder(val) else None, f"{name} = {red}")


def scan_go(text: str, rel: str) -> list[RawFinding]:
    toks = tokenize(text)
    lines = text.splitlines()
    an = _Analyzer(toks, lines, text)
    hits = an.run()
    out, seen = [], set()
    for rule, ln, conf, ev in sorted(hits, key=lambda h: (h[1], h[0])):
        if (rule, ln) in seen:
            continue
        seen.add((rule, ln))
        sev, dconf = SEVERITY[rule]
        k = knowledge.RULES[rule]
        evidence = ev if ev is not None else redact_text(lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else "")
        out.append(RawFinding("code-patterns", rule, k["category"], sev, conf or dconf, k["name"], rel, ln, evidence,
                              Exposure.UNKNOWN, k["remediation"], "small"))
    return out
