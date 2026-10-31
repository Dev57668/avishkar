"""JavaScript / TypeScript security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer removes comments and understands strings, template literals (with nested `${}`), regex literals and
operators, so text inside comments or strings can never trigger a rule. Findings are then derived from call and
assignment shapes: `const cp = require('child_process'); cp.exec(`ping ${host}`)` is recognised through the import alias,
and `model.eval()` is not mistaken for the global `eval`.

Honest limits: this is not a full parser and does no type or data-flow analysis. It follows only simple same-file flows
(a string built into a variable that is later passed to a sink). Each rule's assurance (structural vs heuristic) is
declared in `avishkar.knowledge`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, SECURITY_CONTEXT, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
JS_RULES = ("JS-EVAL", "JS-CMDI", "JS-INNERHTML", "JS-XSS-REFLECT", "JS-TLS", "JS-SQLI", "JS-WEAKHASH", "JS-RANDOM",
            "JS-SECRET-ASSIGN", "JS-PATH")
SEVERITY = {"JS-EVAL": (Severity.HIGH, M), "JS-CMDI": (Severity.HIGH, M), "JS-INNERHTML": (Severity.MEDIUM, M),
            "JS-XSS-REFLECT": (Severity.MEDIUM, L), "JS-TLS": (Severity.MEDIUM, H), "JS-SQLI": (Severity.HIGH, M),
            "JS-WEAKHASH": (Severity.LOW, M), "JS-RANDOM": (Severity.MEDIUM, L), "JS-SECRET-ASSIGN": (Severity.HIGH, M),
            "JS-PATH": (Severity.MEDIUM, L)}
MAX_TOKENS = 400_000

KEYWORDS_BEFORE_REGEX = {"return", "typeof", "case", "do", "else", "in", "of", "void", "delete", "throw", "new",
                         "instanceof", "yield", "await"}
CTRL = {"if", "for", "while", "switch", "catch", "with", "function", "return", "typeof"}
SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter|where|from|values)\b")
SQL_SINKS = {"query", "run", "get", "all", "exec", "execute", "raw", "each", "$queryRawUnsafe", "$executeRawUnsafe",
             "queryRawUnsafe"}
VM_EVAL = {"vm.runInNewContext", "vm.runInThisContext", "vm.runInContext", "vm.compileFunction"}
FS_SINKS = {"readFile", "readFileSync", "createReadStream", "writeFile", "writeFileSync", "appendFile",
            "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync"}
NORMALISERS = {"resolve", "normalize", "basename", "realpath", "relative", "isAbsolute", "sanitize", "sanitizeFilename",
               "secureJoin"}
GLOBALS = {"window", "globalThis", "global", "self"}
INTERP = re.compile(r"\$\{([^{}]*)\}")
ESCAPERS = re.compile(r"^\s*(?:[\w$.]*\.)?(?:escape\w*|sanitize\w*|encode\w*|xss|purify)\s*\(", re.I)


def all_interpolations_escaped(raw: str) -> bool:
    """True when every ${...} in a template literal is wrapped in an escaping call (escapeHtml(x), DOMPurify.sanitize(x)...).
    A name-based check: it cannot prove the escaper is correct, only that the author used one."""
    exprs = INTERP.findall(raw)
    return bool(exprs) and all(ESCAPERS.match(e) for e in exprs)
MULTI = ("===", "!==", ">>>", "...", "**=", "<<=", ">>=", "&&=", "||=", "??=", "=>", "?.", "**", "&&", "||", "??", "==", "!=",
         "<=", ">=", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>")


@dataclass(slots=True)
class Tok:
    kind: str       # id | num | str | tpl | punct | regex
    text: str
    line: int
    interp: bool = False


def _scan_template(src: str, i: int) -> tuple[int, str, bool, int]:
    """src[i] == '`'. Returns (index after closing backtick, raw content, has_interpolation, newlines inside)."""
    n, j, nl, interp = len(src), i + 1, 0, False
    start = j
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            nl += 1
        if c == "`":
            return j + 1, src[start:j], interp, nl
        if c == "$" and j + 1 < n and src[j + 1] == "{":
            interp = True
            depth, j = 1, j + 2
            while j < n and depth:
                d = src[j]
                if d == "{":
                    depth += 1
                elif d == "}":
                    depth -= 1
                elif d in "'\"":
                    q, j = d, j + 1
                    while j < n and src[j] != q and src[j] != "\n":
                        j += 2 if src[j] == "\\" else 1
                elif d == "`":
                    j, _, _, k = _scan_template(src, j)
                    nl += k
                    continue
                elif d == "\n":
                    nl += 1
                j += 1
            continue
        j += 1
    return n, src[start:], interp, nl  # unterminated: be lenient


def tokenize(src: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n, line = 0, len(src), 1
    if src.startswith("#!"):
        i = src.find("\n") if "\n" in src else n
    while i < n and len(toks) < MAX_TOKENS:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r\f\v﻿":
            i += 1
        elif c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
        elif c.isalpha() or c in "_$" or ord(c) > 127:
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$" or ord(src[j]) > 127):
                j += 1
            toks.append(Tok("id", src[i:j], line))
            i = j
        elif c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            toks.append(Tok("num", src[i:j], line))
            i = j
        elif c in "'\"":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            toks.append(Tok("str", src[i + 1:j], line))
            i = j + 1 if j < n and src[j] == c else j  # unterminated string: do not swallow the newline (line counting)
        elif c == "`":
            j, raw, interp, nl = _scan_template(src, i)
            toks.append(Tok("tpl", raw, line, interp))
            line += nl
            i = j
        elif c == "/":
            prev = toks[-1] if toks else None
            regex_ok = prev is None or (prev.kind == "punct" and prev.text not in (")", "]", "}")) or (
                prev.kind == "id" and prev.text in KEYWORDS_BEFORE_REGEX)
            j = -1
            if regex_ok:
                k, in_class = i + 1, False
                while k < n and src[k] != "\n":
                    d = src[k]
                    if d == "\\":
                        k += 2
                        continue
                    if d == "[":
                        in_class = True
                    elif d == "]":
                        in_class = False
                    elif d == "/" and not in_class:
                        j = k + 1
                        break
                    k += 1
            if j > 0:
                while j < n and src[j].isalpha():
                    j += 1
                toks.append(Tok("regex", src[i:j], line))
                i = j
            else:
                op = "/=" if src.startswith("/=", i) else "/"
                toks.append(Tok("punct", op, line))
                i += len(op)
        else:
            op = next((m for m in MULTI if src.startswith(m, i)), c)
            toks.append(Tok("punct", op, line))
            i += len(op)
    return toks


class _Analyzer:
    def __init__(self, toks: list[Tok], lines: list[str]):
        self.T, self.lines, self.n = toks, lines, len(toks)
        self.hits: list[tuple] = []  # (rule, line, conf|None, evidence|None)
        self.pair = self._pairs()
        self.alias = self._aliases()
        self.ctx = self._function_context()
        self.flow_sql, self.flow_path = self._flows()
        self.normalises = self._normalises()

    # ---------------------------------------------------------------- structure
    def _pairs(self) -> dict[int, int]:
        pair, stack = {}, []
        for i, t in enumerate(self.T):
            if t.kind != "punct":
                continue
            if t.text in "([{":
                stack.append(i)
            elif t.text in ")]}" and stack:
                j = stack.pop()
                pair[i], pair[j] = j, i
        return pair

    def txt(self, i: int) -> str:
        return self.T[i].text if 0 <= i < self.n else ""

    def kind(self, i: int) -> str:
        return self.T[i].kind if 0 <= i < self.n else ""

    def is_p(self, i: int, s: str) -> bool:
        return 0 <= i < self.n and self.T[i].kind == "punct" and self.T[i].text == s

    def _aliases(self) -> dict[str, str]:
        alias, T, n = {}, self.T, self.n

        def mod(s: str) -> str:
            s = s.removeprefix("node:")
            return "fs" if s in ("fs/promises", "fs-extra") else s

        for i, t in enumerate(T):
            if t.kind != "id":
                continue
            if t.text in ("const", "let", "var"):
                j = i + 1
                if self.kind(j) == "id" and self.is_p(j + 1, "=") and self.txt(j + 2) == "require" and self.is_p(j + 3, "(") \
                        and self.kind(j + 4) == "str":
                    alias[T[j].text] = mod(T[j + 4].text)
                elif self.is_p(j, "{") and j in self.pair:
                    end = self.pair[j]
                    if self.is_p(end + 1, "=") and self.txt(end + 2) == "require" and self.is_p(end + 3, "(") \
                            and self.kind(end + 4) == "str":
                        m, k = mod(T[end + 4].text), j + 1
                        while k < end:
                            if T[k].kind == "id":
                                name = T[k].text
                                local = T[k + 2].text if self.is_p(k + 1, ":") and self.kind(k + 2) == "id" else name
                                alias[local] = f"{m}.{name}"
                            k += 1
            elif t.text == "import":
                j = i + 1
                names, k = {}, j
                while k < n and not (T[k].kind == "id" and T[k].text == "from") and not self.is_p(k, ";") and k - i < 60:
                    k += 1
                if k < n and T[k].text == "from" and self.kind(k + 1) == "str":
                    m = mod(T[k + 1].text)
                    p = j
                    while p < k:
                        if self.is_p(p, "*") and self.txt(p + 1) == "as" and self.kind(p + 2) == "id":
                            names[T[p + 2].text] = m  # import * as X from 'm'
                            p += 3
                            continue
                        if T[p].kind == "id" and T[p].text not in ("as", "type"):
                            nxt = T[p + 2].text if self.txt(p + 1) == "as" and p + 2 < k else None
                            in_braces = any(self.is_p(q, "{") for q in range(j, p))
                            if self.txt(p + 1) == "as" and self.txt(p - 1) != "as":
                                names[nxt or ""] = f"{m}.{T[p].text}" if in_braces else m
                            elif not (p > j and self.txt(p - 1) == "as"):
                                names[T[p].text] = f"{m}.{T[p].text}" if in_braces else m
                        p += 1
                    alias.update(names)
        return alias

    def _function_context(self) -> list[str]:
        """For every token index, the name of the nearest enclosing named function ('' when none)."""
        T, stack, out = self.T, [], []

        def name_before_brace(k: int) -> str | None:
            j = k - 1
            if j >= 0 and self.is_p(j, ")") and j in self.pair:
                j = self.pair[j] - 1
                if j >= 0 and T[j].kind == "id" and T[j].text not in CTRL:
                    return T[j].text
                if j >= 0 and T[j].kind == "id" and T[j].text == "function":
                    j -= 1
                    if j >= 1 and self.is_p(j, "=") and T[j - 1].kind == "id":
                        return T[j - 1].text
                if j >= 0 and T[j].kind == "id" and T[j].text == "function":
                    return None
            elif j >= 0 and self.is_p(j, "=>"):
                j -= 1
                if j >= 0 and self.is_p(j, ")") and j in self.pair:
                    j = self.pair[j] - 1
                elif j >= 0 and T[j].kind == "id":
                    j -= 1
                if j >= 1 and self.is_p(j, "=") and T[j - 1].kind == "id":
                    return T[j - 1].text
            return None

        for i, t in enumerate(T):
            if t.kind == "punct" and t.text == "{":
                stack.append(name_before_brace(i))
            elif t.kind == "punct" and t.text == "}" and stack:
                stack.pop()
            out.append(next((s for s in reversed(stack) if s), ""))
        return out

    def _rhs_end(self, k: int) -> int:
        """Index one past the right-hand side of an assignment whose first RHS token is k."""
        T, n, depth, last_line = self.T, self.n, 0, T_line(self.T, k)
        j = k
        while j < n:
            t = T[j]
            if t.kind == "punct":
                if t.text in "([{":
                    depth += 1
                elif t.text in ")]}":
                    if depth == 0:
                        return j
                    depth -= 1
                elif t.text == ";" and depth == 0:
                    return j
                elif t.text == "," and depth == 0:
                    return j
            if depth == 0 and t.line > last_line and j > k:
                prev = T[j - 1]
                if not (prev.kind == "punct" and prev.text not in (")", "]", "}")):
                    return j
            last_line = t.line
            j += 1
        return n

    def _dynamic_string(self, a: int, b: int) -> tuple[bool, bool]:
        """(builds a string from non-literals, mentions SQL words) for tokens [a, b)."""
        T = self.T
        sql = any(T[x].kind in ("str", "tpl") and SQL_WORDS.search(T[x].text) for x in range(a, b))
        interp = any(T[x].kind == "tpl" and T[x].interp for x in range(a, b))
        concat = any(self.is_p(x, "+") for x in range(a, b)) and any(T[x].kind in ("str", "tpl") for x in range(a, b)) \
            and any(T[x].kind == "id" for x in range(a, b))
        return interp or concat, sql

    def _flows(self) -> tuple[set[str], set[str]]:
        sql, path = set(), set()
        T = self.T
        for i, t in enumerate(T):
            if t.kind == "id" and self.is_p(i + 1, "=") and not self.is_p(i - 1, "."):
                a = i + 2
                b = self._rhs_end(a)
                dyn, has_sql = self._dynamic_string(a, b)
                if dyn and has_sql:
                    sql.add(t.text)
                if dyn:
                    path.add(t.text)
        return sql, path

    def _normalises(self) -> bool:
        T = self.T
        # member calls only (path.resolve(...)): a bare resolve(row) is typically a Promise callback, not path hygiene
        return any(T[i].kind == "id" and T[i].text in NORMALISERS and self.is_p(i + 1, "(") and self.is_p(i - 1, ".")
                   for i in range(self.n))

    # ---------------------------------------------------------------- helpers
    def hit(self, rule: str, line: int, conf: Confidence | None = None, evidence: str | None = None):
        self.hits.append((rule, line, conf, evidence))

    def args(self, open_i: int) -> list[tuple[int, int]]:
        if open_i not in self.pair:
            return []
        close, out, depth, start = self.pair[open_i], [], 0, open_i + 1
        for j in range(open_i + 1, close):
            t = self.T[j]
            if t.kind == "punct":
                if t.text in "([{":
                    depth += 1
                elif t.text in ")]}":
                    depth -= 1
                elif t.text == "," and depth == 0:
                    out.append((start, j))
                    start = j + 1
        if start < close:
            out.append((start, close))
        return out

    def is_literal(self, rng: tuple[int, int]) -> bool:
        a, b = rng
        return b - a == 1 and (self.T[a].kind == "str" or (self.T[a].kind == "tpl" and not self.T[a].interp))

    def lone_str(self, rng) -> str | None:
        a, b = rng
        return self.T[a].text if b - a == 1 and self.T[a].kind == "str" else None

    def security_context(self, i: int) -> bool:
        names = [self.ctx[i]]
        k = i - 1
        while k >= 0 and not (self.T[k].kind == "punct" and self.T[k].text in (";", "{", "}")):
            if self.T[k].kind == "id" and (self.is_p(k + 1, "=") or self.is_p(k + 1, ":")):
                names.append(self.T[k].text)
            k -= 1
        return any(SECURITY_CONTEXT.search(x or "") for x in names)

    # ---------------------------------------------------------------- rules
    def run(self):
        T, n = self.T, self.n
        for i in range(n):
            t = T[i]
            if t.kind != "id":
                if t.kind == "punct" and t.text == "." and self.kind(i + 1) == "id" and i > 0:
                    self._member_assign(i)
                continue
            if i > 0 and T[i - 1].kind == "punct" and T[i - 1].text in (".", "?."):
                continue
            self._call_at(i)
            self._plain_at(i)
        return self.hits

    def _call_at(self, i: int):
        T = self.T
        if T[i].text == "new" and self.txt(i + 1) == "Function" and self.is_p(i + 2, "("):
            args = self.args(i + 2)
            if any(not self.is_literal(a) for a in args):
                self.hit("JS-EVAL", T[i].line)
            return
        names, j = [T[i].text], i + 1
        while j + 1 < self.n and self.txt(j) in (".", "?.") and self.kind(j + 1) == "id":
            names.append(T[j + 1].text)
            j += 2
        if not self.is_p(j, "("):
            return
        line, args = T[i].line, self.args(j)
        head = self.alias.get(names[0], names[0])
        qual = head + ("." + ".".join(names[1:]) if len(names) > 1 else "")
        if names[0] in GLOBALS and names[1:] == ["eval"]:
            qual = "eval"
        last = names[-1]

        if qual == "eval":
            if any(not self.is_literal(a) for a in args):  # eval("require('crypto')") runs a constant: bad style, not injection
                self.hit("JS-EVAL", line)
        elif names[0] in ("setTimeout", "setInterval", "setImmediate") and len(names) == 1 and args \
                and (self.lone_str(args[0]) is not None or (T[args[0][0]].kind == "tpl" and args[0][1] - args[0][0] == 1)):
            self.hit("JS-EVAL", line)

        if qual in VM_EVAL and args and not self.is_literal(args[0]):
            self.hit("JS-EVAL", line)

        if qual in ("child_process.exec", "child_process.execSync") and args and not self.is_literal(args[0]):
            self.hit("JS-CMDI", line)

        if (names[-2:] == ["document", "write"] or names[-2:] == ["document", "writeln"]) and args \
                and not self.is_literal(args[0]):
            self.hit("JS-INNERHTML", line)
        if last == "insertAdjacentHTML" and len(args) >= 2 and not self.is_literal(args[1]):
            self.hit("JS-INNERHTML", line)

        if last in ("send", "write", "end") and args:
            a0 = T[args[0][0]]
            if args[0][1] - args[0][0] == 1 and a0.kind == "tpl" and a0.interp and re.search(r"<[A-Za-z!/]", a0.text) \
                    and not all_interpolations_escaped(a0.text):
                self.hit("JS-XSS-REFLECT", line)

        if last in SQL_SINKS and args and len(names) >= 2:
            a, b = args[0]
            dyn, has_sql = self._dynamic_string(a, b)
            if dyn and has_sql:
                self.hit("JS-SQLI", line)
            elif b - a == 1 and T[a].kind == "id" and T[a].text in self.flow_sql:
                self.hit("JS-SQLI", line, L)

        if qual == "crypto.createHash" and args:
            alg = self.lone_str(args[0])
            if alg and alg.lower() in ("md5", "sha1"):
                self.hit("JS-WEAKHASH", line)

        if names[:2] == ["Math", "random"] and self.security_context(i):
            self.hit("JS-RANDOM", line)

        if qual.startswith("fs.") and last in FS_SINKS and args and not self.normalises:
            a, b = args[0]
            dyn, _ = self._dynamic_string(a, b)
            if dyn:
                self.hit("JS-PATH", line)
            elif b - a == 1 and T[a].kind == "id" and T[a].text in self.flow_path:
                self.hit("JS-PATH", line)

    def _plain_at(self, i: int):
        T = self.T
        t = T[i]
        if t.text == "dangerouslySetInnerHTML":
            self.hit("JS-INNERHTML", t.line)
        if t.text == "rejectUnauthorized" and self.is_p(i + 1, ":") and self.txt(i + 2) == "false":
            self.hit("JS-TLS", t.line)
        # NAME = 'literal'   /   NAME: 'literal'
        if (self.is_p(i + 1, "=") or (self.is_p(i + 1, ":") and self.is_p(i - 1, "{") or self.is_p(i + 1, ":") and self.is_p(i - 1, ","))) \
                and self.kind(i + 2) == "str":
            self._secret(i, i + 2)

    def _member_assign(self, i: int):
        """`. innerHTML = <non-literal>` and `. password = 'literal'`."""
        T = self.T
        name = T[i + 1].text
        if name == "NODE_TLS_REJECT_UNAUTHORIZED" and self.is_p(i + 2, "=") and (
                (self.kind(i + 3) == "str" and self.txt(i + 3) in ("0", "false"))
                or (self.kind(i + 3) == "num" and self.txt(i + 3) == "0")):
            self.hit("JS-TLS", T[i].line)
        elif self.is_p(i + 2, "=") and name in ("innerHTML", "outerHTML"):
            a = i + 3
            b = self._rhs_end(a)
            if b > a and not (b - a == 1 and (T[a].kind == "str" or (T[a].kind == "tpl" and not T[a].interp))):
                self.hit("JS-INNERHTML", T[i].line)
        elif self.is_p(i + 2, "=") and self.kind(i + 3) == "str":
            self._secret(i + 1, i + 3)

    def _secret(self, name_i: int, str_i: int):
        T = self.T
        name, val = T[name_i].text, T[str_i].text
        nxt = str_i + 1
        if nxt < self.n and not (self.txt(nxt) in (";", ",", "}", ")") or T[nxt].line > T[str_i].line):
            return  # part of a larger expression
        if CRED_NAME.search(name) and not CRED_NAME_EXCLUDE.search(name) and looks_like_secret_value(val):
            red = val[:2] + "*" * 6 if len(val) <= 8 else val[:4] + "*" * 6 + val[-2:]
            self.hit("JS-SECRET-ASSIGN", T[name_i].line, L if is_placeholder(val) else None, f"{name} = {red}")


def T_line(T: list[Tok], k: int) -> int:
    return T[k].line if k < len(T) else 0


def scan_js(text: str, rel: str) -> list[RawFinding]:
    toks = tokenize(text)
    lines = text.splitlines()
    an = _Analyzer(toks, lines)
    out, seen = [], set()
    for rule, ln, conf, ev in sorted(an.run(), key=lambda h: (h[1], h[0])):
        if (rule, ln) in seen:
            continue
        seen.add((rule, ln))
        sev, dconf = SEVERITY[rule]
        k = knowledge.RULES[rule]
        evidence = ev if ev is not None else redact_text(lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else "")
        out.append(RawFinding("code-patterns", rule, k["category"], sev, conf or dconf, k["name"], rel, ln, evidence,
                              Exposure.UNKNOWN, k["remediation"], "small"))
    return out
