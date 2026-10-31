"""C# security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer drops comments and understands regular, verbatim, interpolated and raw triple-quoted
strings and char literals, so text inside comments or strings can never trigger a rule. Findings come from call and
construction shapes (`new SqlCommand("..." + id)`, `new BinaryFormatter()`, `MD5.Create()`). Only simple same-file flows are
followed: a value read from an HTTP request, or an SQL text built by concatenation/interpolation, that later reaches a sink.

Honest limits: this is NOT a C# parser. No types, no overload resolution, no cross-method or cross-file data flow and no
knowledge of framework sanitizers. Expect misses and some false positives; each rule's assurance is declared in
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
CS_RULES = ("CS-SQLI", "CS-CMDI", "CS-DESER", "CS-WEAKHASH", "CS-WEAKCIPHER", "CS-RANDOM", "CS-SECRET-ASSIGN", "CS-TLS",
            "CS-XXE", "CS-PATH", "CS-XSS-REFLECT", "CS-EVAL")
SEVERITY = {"CS-SQLI": (Severity.HIGH, M), "CS-CMDI": (Severity.HIGH, M), "CS-DESER": (Severity.HIGH, M),
            "CS-WEAKHASH": (Severity.LOW, M), "CS-WEAKCIPHER": (Severity.MEDIUM, M), "CS-RANDOM": (Severity.MEDIUM, L),
            "CS-SECRET-ASSIGN": (Severity.HIGH, M), "CS-TLS": (Severity.MEDIUM, H), "CS-XXE": (Severity.MEDIUM, M),
            "CS-PATH": (Severity.MEDIUM, L), "CS-XSS-REFLECT": (Severity.MEDIUM, L), "CS-EVAL": (Severity.HIGH, M)}
MAX_TOKENS = 400_000

SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter|where|from|values|union)\b")
SQL_CTORS = {"SqlCommand", "MySqlCommand", "NpgsqlCommand", "OleDbCommand", "OdbcCommand", "SqliteCommand", "SQLiteCommand",
             "SqlDataAdapter", "MySqlDataAdapter", "OracleCommand"}
SQL_CALLS = {"ExecuteSqlRaw", "ExecuteSqlRawAsync", "FromSqlRaw", "SqlQueryRaw", "Query", "QueryAsync", "QueryFirst",
             "QueryFirstOrDefault", "QuerySingle", "Execute", "ExecuteAsync", "ExecuteScalar", "ExecuteScalarAsync"}
DESER_TYPES = {"BinaryFormatter", "NetDataContractSerializer", "SoapFormatter", "LosFormatter", "ObjectStateFormatter"}
SOURCE_MEMBERS = {"QueryString", "Form", "Params", "Query", "Cookies", "RouteValues", "Headers"}
FROM_ATTRS = {"FromQuery", "FromRoute", "FromForm", "FromHeader", "FromBody"}
FILE_SINKS = {"ReadAllText", "ReadAllBytes", "ReadAllLines", "OpenRead", "OpenText", "WriteAllText", "WriteAllBytes", "Delete",
              "Open", "AppendAllText", "Copy", "Move", "Create"}
ESCAPERS = {"HtmlEncode", "Encode", "HtmlAttributeEncode", "JavaScriptStringEncode", "UrlEncode", "GetFileName", "GetFullPath"}
SHELL_PROGS = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "bash", "sh", "/bin/sh", "/bin/bash"}
PUNCT2 = {"=>", "::", "+=", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "??", "?."}
INTERP = re.compile(r"\{[^{}]")


@dataclass
class Tok:
    kind: str       # id | num | str | chr | punct
    text: str
    line: int
    interp: bool = False   # $"..." with {expression} holes: not a constant


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
        elif c in '$@"' and re.match(r'(\$@|@\$|\$|@)?"', src[i:i + 3]):
            m = re.match(r'(\$@|@\$|\$|@)?(""")?"', src[i:i + 5])
            prefix = (m.group(1) if m else "") or ""
            raw = src.startswith('"""', i + len(prefix))
            start = i + len(prefix) + (3 if raw else 1)
            verbatim = "@" in prefix
            j, buf = start, []
            while j < n:
                ch = src[j]
                if raw and src.startswith('"""', j):
                    break
                if not raw and verbatim and ch == '"':
                    if src.startswith('""', j):
                        buf.append('"')
                        j += 2
                        continue
                    break
                if not raw and not verbatim and ch == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if not raw and not verbatim and (ch == '"' or ch == "\n"):
                    break
                buf.append(ch)
                j += 1
            body = "".join(buf)
            out.append(Tok("str", body, line, "$" in prefix and bool(INTERP.search(body))))
            line += src.count("\n", i, j)
            i = j + (3 if raw else 1)
        elif c == "'":
            j, buf = i + 1, []
            while j < n and src[j] != "'" and src[j] != "\n":
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                else:
                    buf.append(src[j])
                    j += 1
            out.append(Tok("chr", "".join(buf), line))
            i = j + 1 if j < n and src[j] == "'" else j
        elif c.isalpha() or c == "_" or (c == "@" and i + 1 < n and src[i + 1].isalpha()):
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok("id", src[i:j].lstrip("@"), line))
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
        self.method_at = self._methods()
        self.tainted: set[str] = set()
        self.built: set[str] = set()
        self._attr_params()
        self.web = bool(self.tainted) or any(self._is_source(i) for i in range(self.n))
        self.shell_file = any(t.kind == "str" and t.text.lower() in SHELL_PROGS for t in toks)

    # ------------------------------------------------------------------ helpers
    def txt(self, i: int) -> str:
        return self.T[i].text if 0 <= i < self.n else ""

    def is_p(self, i: int, s: str) -> bool:
        return 0 <= i < self.n and self.T[i].kind == "punct" and self.T[i].text == s

    def hit(self, rule: str, line: int, conf: Confidence | None = None, evidence: str | None = None):
        self.hits.append((rule, line, conf, evidence))

    def _methods(self) -> list[str]:
        T, names = self.T, [""] * self.n
        stack: list[str] = []
        for i, t in enumerate(T):
            names[i] = next((s for s in reversed(stack) if s), "")
            if t.kind == "punct" and t.text == "{":
                name, k = "", i - 1
                for _ in range(14):
                    if k < 0 or T[k].text in (";", "{", "}"):
                        break
                    if T[k].text == ")":
                        o = self.open_of.get(k)
                        if o is not None and o > 0 and T[o - 1].kind == "id" and T[o - 1].text not in ("if", "for", "foreach", "while", "switch", "catch", "using", "lock", "fixed"):
                            name = T[o - 1].text
                        break
                    k -= 1
                stack.append(name)
            elif t.kind == "punct" and t.text == "}" and stack:
                stack.pop()
        return names

    def _attr_params(self):
        """`[FromQuery] string name` / `[FromRoute] int id`: the declared parameter is request data."""
        T = self.T
        for i, t in enumerate(T):
            if t.kind == "id" and t.text in FROM_ATTRS:
                k = i + 1
                if self.is_p(k, "("):
                    k = self.pair.get(k, k) + 1
                if self.is_p(k, "]"):
                    k += 1
                last = None
                while k < self.n and not self.is_p(k, ",") and not self.is_p(k, ")") and not self.is_p(k, "="):
                    if T[k].kind == "id":
                        last = T[k].text
                    k += 1
                if last:
                    self.tainted.add(last)

    def _is_source(self, i: int) -> bool:
        t = self.T[i]
        return t.kind == "id" and t.text in SOURCE_MEMBERS and self.is_p(i - 1, ".") and self.txt(i - 2) in ("Request", "HttpContext", "context")

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
        return hi > lo and all((t.kind in ("str", "chr", "num") and not t.interp) or t.text in ("+", "(", ")") for t in self.T[lo:hi])

    def has_concat(self, lo: int, hi: int) -> bool:
        seg = self.T[lo:hi]
        if any(t.kind == "str" and t.interp for t in seg):
            return True
        if any(t.kind == "punct" and t.text == "+" for t in seg) and not self.literal_only(lo, hi):
            return True
        return any(t.text == "Format" and k > 1 and seg[k - 2].text == "string" or (t.text == "Format" and k > 1 and seg[k - 2].text == "String")
                   for k, t in enumerate(seg))

    def mentions_source(self, lo: int, hi: int) -> bool:
        return any(self._is_source(k) or (self.T[k].kind == "id" and self.T[k].text in self.tainted) for k in range(lo, hi))

    def receiver(self, i: int) -> list[str]:
        out, k = [], i - 1
        while k >= 1 and (self.is_p(k, ".") or self.is_p(k, "?.")):
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

    def _stmt_names(self, i: int) -> str:
        k = i
        while k > 0 and self.txt(k) not in (";", "{", "}"):
            k -= 1
        return " ".join(t.text for t in self.T[k:i] if t.kind == "id")

    # ------------------------------------------------------------------ analysis
    def run(self):
        self._assignments()
        T, n = self.T, self.n
        for i in range(n):
            t = T[i]
            if t.kind != "id":
                continue
            if t.text == "new" and i + 1 < n and T[i + 1].kind == "id":
                self._constructor(i)
            elif i + 1 < n and self.is_p(i + 1, "(") and (self.is_p(i - 1, ".") or self.is_p(i - 1, "?.")):
                self._call(i)
            elif t.text == "CipherMode" and self.is_p(i + 1, ".") and self.txt(i + 2) == "ECB":
                self.hit("CS-WEAKCIPHER", t.line, M)
            elif t.text == "TypeNameHandling" and self.is_p(i + 1, ".") and self.txt(i + 2) in ("All", "Auto", "Objects", "Arrays"):
                self.hit("CS-DESER", t.line, M)
            elif t.text == "DtdProcessing" and self.is_p(i + 1, ".") and self.txt(i + 2) == "Parse":
                self.hit("CS-XXE", t.line, M)
            elif t.text == "DangerousAcceptAnyServerCertificateValidator":
                self.hit("CS-TLS", t.line, H)
            elif t.text in ("ServerCertificateValidationCallback", "ServerCertificateCustomValidationCallback", "RemoteCertificateValidationCallback") \
                    and self.is_p(i + 1, "=") and self._always_true(i + 2):
                self.hit("CS-TLS", t.line, H)
            elif t.text == "CommandText" and self.is_p(i + 1, "="):
                end = self._stmt_end(i + 2)
                lits = " ".join(x.text for x in T[i + 2:end] if x.kind == "str")
                if self.has_concat(i + 2, end) and (SQL_WORDS.search(lits) or self.mentions_source(i + 2, end)):
                    self.hit("CS-SQLI", t.line, M)
                elif end - (i + 2) == 1 and T[i + 2].text in self.built:
                    self.hit("CS-SQLI", t.line, L)
            elif t.text == "Arguments" and self.is_p(i + 1, "=") and self.shell_file:
                end = self._stmt_end(i + 2)
                if self.has_concat(i + 2, end) or self.mentions_source(i + 2, end):
                    self.hit("CS-CMDI", t.line, M)
        self._secrets()
        return self.hits

    def _stmt_end(self, k: int) -> int:
        while k < self.n and not self.is_p(k, ";") and k < self.n:
            k += 1
        return k

    def _always_true(self, k: int) -> bool:
        """`= (s, c, ch, e) => true;` or `= delegate { return true; };`"""
        end = self._stmt_end(k)
        txts = [t.text for t in self.T[k:end]]
        return txts[-2:] == ["=>", "true"] or ("delegate" in txts and "return" in txts and "true" in txts)

    def _assignments(self):
        T = self.T
        for i in range(1, self.n - 1):
            if not (self.is_p(i, "=") and T[i - 1].kind == "id") or self.is_p(i + 1, "=") or self.is_p(i - 1, "!"):
                continue
            end = self._stmt_end(i + 1)
            end = min(end, i + 80)
            name = T[i - 1].text
            lits = " ".join(t.text for t in T[i + 1:end] if t.kind == "str")
            if self.mentions_source(i + 1, end):
                self.tainted.add(name)
            if self.has_concat(i + 1, end) and SQL_WORDS.search(lits):
                self.built.add(name)
                if self.mentions_source(i + 1, end):
                    self.tainted.add(name)

    def _constructor(self, i: int):
        T = self.T
        cls, k = T[i + 1].text, i + 2
        while k < self.n and (self.is_p(k, ".") or T[k].kind == "id"):
            cls = T[k].text if T[k].kind == "id" else cls
            k += 1
        if self.is_p(k, "<"):
            depth = 0
            while k < self.n:
                depth += (self.is_p(k, "<")) - (self.is_p(k, ">"))
                k += 1
                if depth <= 0:
                    break
        if not self.is_p(k, "("):
            return
        line, a = T[i].line, self.args(k)
        if cls in SQL_CTORS and a:
            lo, hi = a[0]
            lits = " ".join(t.text for t in T[lo:hi] if t.kind == "str")
            if self.has_concat(lo, hi) and (SQL_WORDS.search(lits) or self.mentions_source(lo, hi)):
                self.hit("CS-SQLI", line, M)
            elif hi - lo == 1 and T[lo].text in self.built:
                self.hit("CS-SQLI", line, L)
        elif cls in DESER_TYPES:
            self.hit("CS-DESER", line, M)
        elif cls in ("MD5CryptoServiceProvider", "SHA1CryptoServiceProvider", "SHA1Managed", "MD5Cng"):
            self.hit("CS-WEAKHASH", line, M)
        elif cls in ("DESCryptoServiceProvider", "RC2CryptoServiceProvider", "TripleDESCryptoServiceProvider"):
            self.hit("CS-WEAKCIPHER", line, M)
        elif cls == "Random" and SECURITY_CONTEXT.search(self.method_at[i] + " " + self._stmt_names(i)):
            self.hit("CS-RANDOM", line, L)
        elif cls == "ProcessStartInfo" and a:
            texts = [("".join(T[x].text for x in range(lo, hi) if T[x].kind == "str").lower(), self.literal_only(lo, hi)) for lo, hi in a]
            if texts[0][1] and texts[0][0] in SHELL_PROGS and any(not lit for _, lit in texts[1:]):
                self.hit("CS-CMDI", line, M)
        elif cls == "FileStream" and a and self._path_tainted(a[0]):
            self.hit("CS-PATH", line, M if self.mentions_source(*a[0]) else L)
        elif cls in ("XmlTextReader", "XmlDocument") and "XmlUrlResolver" in self.text:
            self.hit("CS-XXE", line, L)
        elif cls == "HtmlString" and a and self.mentions_source(*a[0]) and not any(T[x].text in ESCAPERS for x in range(*a[0])):
            self.hit("CS-XSS-REFLECT", line, L)

    def _call(self, i: int):
        T, name, line = self.T, self.T[i].text, self.T[i].line
        a, recv = self.args(i + 1), self.receiver(i)
        last = recv[-1] if recv else ""
        first = a[0] if a else None
        if name in SQL_CALLS and first and last not in ("Console", "Math", "Task"):
            lo, hi = first
            lits = " ".join(t.text for t in T[lo:hi] if t.kind == "str")
            if self.has_concat(lo, hi) and (SQL_WORDS.search(lits) or self.mentions_source(lo, hi)):
                self.hit("CS-SQLI", line, M)
            elif hi - lo == 1 and T[lo].text in self.built:
                self.hit("CS-SQLI", line, L)
        elif name == "Start" and last == "Process" and first:
            texts = [("".join(T[x].text for x in range(lo, hi) if T[x].kind == "str").lower(), self.literal_only(lo, hi)) for lo, hi in a]
            if len(a) >= 2 and texts[0][1] and texts[0][0] in SHELL_PROGS and any(not lit for _, lit in texts[1:]):
                self.hit("CS-CMDI", line, M)
            elif not texts[0][1] and (self.mentions_source(*first) or self.has_concat(*first)):
                self.hit("CS-CMDI", line, M if self.mentions_source(*first) else L)
        elif name == "Create" and last in ("MD5", "SHA1", "RIPEMD160"):
            if last != "RIPEMD160":
                self.hit("CS-WEAKHASH", line, M)
        elif name == "Create" and last in ("DES", "RC2", "TripleDES"):
            self.hit("CS-WEAKCIPHER", line, M)
        elif name == "Create" and last == "HashAlgorithm" and first and "".join(T[x].text for x in range(*first) if T[x].kind == "str").upper() in ("MD5", "SHA1", "SHA-1"):
            self.hit("CS-WEAKHASH", line, M)
        elif name in FILE_SINKS and last in ("File", "Directory") and first and self._path_tainted(first):
            self.hit("CS-PATH", line, M if self.mentions_source(*first) else L)
        elif name == "Combine" and last == "Path" and any(self.mentions_source(lo, hi) for lo, hi in a) and \
                not any(T[x].text in ESCAPERS for x in range(a[0][0], a[-1][1])):
            self.hit("CS-PATH", line, L)
        elif name in ("Write", "WriteAsync", "Content", "Raw") and last in ("Response", "Html", "Controller", "this", "") and first:
            lo, hi = first
            if any(T[x].text in FILE_SINKS or T[x].text in ("ExecuteReader", "ExecuteScalar") for x in range(lo, hi)):
                return  # the value is read back from a file or database, not echoed from the request
            if self.mentions_source(lo, hi) and not any(T[x].text in ESCAPERS for x in range(lo, hi)):
                self.hit("CS-XSS-REFLECT", line, L)
        elif name in ("EvaluateAsync", "RunAsync", "Evaluate") and last in ("CSharpScript",) and first and not self.literal_only(*first):
            self.hit("CS-EVAL", line, M)

    def _path_tainted(self, rng) -> bool:
        lo, hi = rng
        if any(self.T[x].text in ESCAPERS for x in range(lo, hi)):
            return False
        return self.mentions_source(lo, hi) or (self.web and self.has_concat(lo, hi))

    def _secrets(self):
        T = self.T
        for i in range(1, self.n - 1):
            if self.is_p(i, "=") and T[i - 1].kind == "id" and T[i + 1].kind == "str" and not T[i + 1].interp:
                nxt = T[i + 2] if i + 2 < self.n else None
                if nxt is not None and nxt.text not in (";", ",", "}", ")"):
                    continue
                name = T[i - 1].text
                if CRED_NAME.search(name) and not CRED_NAME_EXCLUDE.search(name):
                    val = T[i + 1].text
                    if looks_like_secret_value(val):
                        red = val[:2] + "*" * 6 if len(val) <= 8 else val[:4] + "*" * 6 + val[-2:]
                        self.hit("CS-SECRET-ASSIGN", T[i - 1].line, L if is_placeholder(val) else None, f"{name} = {red}")


def scan_csharp(text: str, rel: str) -> list[RawFinding]:
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
