r"""PHP security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer skips the HTML outside <?php ... ?> tags, drops comments, and understands single-quoted, double-quoted
(with $variable interpolation), heredoc/nowdoc and backtick strings, so text inside comments or constant strings can never
trigger a rule. Findings come from call and statement shapes (`mysqli_query($c, "..." . $_GET['id'])`, `system($cmd)`,
`include $_GET['page']`). Only simple same-file flows are followed: a variable assigned from $_GET/$_POST/$_REQUEST/$_COOKIE,
or an SQL text built from one, that is later passed to a sink.

Honest limits: this is NOT a PHP parser. No types, no includes followed, no framework knowledge (Laravel/Symfony escaping and
query builders are invisible), no cross-function or cross-file data flow. Expect misses and some false positives; each rule's
assurance is declared in `avishkar.knowledge`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, SECURITY_CONTEXT, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
PHP_RULES = ("PHP-SQLI", "PHP-CMDI", "PHP-EVAL", "PHP-INCLUDE", "PHP-DESER", "PHP-WEAKHASH", "PHP-RANDOM",
             "PHP-SECRET-ASSIGN", "PHP-PATH", "PHP-XSS-REFLECT", "PHP-TLS")
SEVERITY = {"PHP-SQLI": (Severity.HIGH, M), "PHP-CMDI": (Severity.HIGH, M), "PHP-EVAL": (Severity.HIGH, M),
            "PHP-INCLUDE": (Severity.HIGH, M), "PHP-DESER": (Severity.HIGH, M), "PHP-WEAKHASH": (Severity.LOW, M),
            "PHP-RANDOM": (Severity.MEDIUM, L), "PHP-SECRET-ASSIGN": (Severity.HIGH, M), "PHP-PATH": (Severity.MEDIUM, L),
            "PHP-XSS-REFLECT": (Severity.MEDIUM, L), "PHP-TLS": (Severity.MEDIUM, H)}
MAX_TOKENS = 400_000

SINK_RESULT = {"shell_exec", "system", "exec", "passthru", "file_get_contents", "file", "fread", "fgets", "readfile",
               "mysqli_query", "mysqli_fetch_assoc", "query", "curl_exec", "popen"}
SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter|where|from|values|union)\b")
SUPERGLOBALS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"}
SQL_FUNCS_2 = {"mysqli_query", "mysqli_real_query", "mysqli_multi_query", "pg_query", "sqlite_query"}   # query is argument 2
SQL_FUNCS_1 = {"mysql_query", "pg_query_params", "mssql_query", "odbc_exec"}
SQL_METHODS = {"query", "exec", "prepare", "multi_query", "real_query", "get_results", "get_var", "get_row", "get_col"}
CMD_FUNCS = {"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"}
FILE_FUNCS = {"file_get_contents", "fopen", "file", "readfile", "unlink", "file_put_contents", "move_uploaded_file", "copy",
              "rename", "mkdir", "rmdir", "is_file", "file_exists", "highlight_file", "show_source"}
INCLUDES = {"include", "include_once", "require", "require_once"}
ESCAPERS = {"htmlspecialchars", "htmlentities", "esc_html", "esc_attr", "esc_url", "intval", "floatval", "basename", "realpath",
            "escapeshellarg", "escapeshellcmd", "mysqli_real_escape_string", "real_escape_string", "addslashes", "filter_var",
            "strip_tags", "urlencode", "json_encode", "ctype_digit", "is_numeric", "absint", "sanitize_text_field", "quote"}
PUNCT2 = {"->", "::", "=>", "==", "!=", "<=", ">=", "&&", "||", "++", "--", ".=", "+=", "??", "?->"}
INTERP = re.compile(r"\$[A-Za-z_{]|\{\$")


@dataclass
class Tok:
    kind: str       # id | var | num | str | punct
    text: str
    line: int
    interp: bool = False   # double-quoted / heredoc string containing $var or {$expr}: not a constant


def tokenize(src: str) -> list[Tok]:
    out: list[Tok] = []
    i, n, line = 0, len(src), 1
    in_php = "<?" not in src  # a file with no tags at all is treated as pure code (snippets)
    while i < n and len(out) < MAX_TOKENS:
        if not in_php:
            j = src.find("<?", i)
            j = n if j < 0 else j
            line += src.count("\n", i, j)
            i = j
            if i < n:
                if src.startswith("<?php", i):
                    i += 5
                elif src.startswith("<?=", i):
                    out.append(Tok("id", "echo", line))
                    i += 3
                else:
                    i += 2
                in_php = True
            continue
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r\f":
            i += 1
        elif src.startswith("?>", i):
            out.append(Tok("punct", ";", line))
            i += 2
            in_php = False
        elif src.startswith("//", i) or (c == "#" and not src.startswith("#[", i)):
            while i < n and src[i] != "\n" and not src.startswith("?>", i):
                i += 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
        elif src.startswith("<<<", i):
            m = re.match(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n", src[i:i + 80])
            if not m:
                out.append(Tok("punct", c, line))
                i += 1
                continue
            label, nowdoc = m.group(2), m.group(1) == "'"
            body_start = i + m.end()
            end = re.search(r"(?m)^[ \t]*" + re.escape(label) + r"\b", src[body_start:])
            body_end = body_start + (end.start() if end else n - body_start)
            body = src[body_start:body_end]
            out.append(Tok("str", body, line, (not nowdoc) and bool(INTERP.search(body))))
            line += src.count("\n", i, body_end)
            i = body_end + (end.end() - end.start() if end else 0)
        elif c in "'\"`":
            j, buf = i + 1, []
            while j < n and src[j] != c:
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                else:
                    buf.append(src[j])
                    j += 1
            body = "".join(buf)
            out.append(Tok("str", body, line, c != "'" and bool(INTERP.search(body))))
            if c == "`":
                out.append(Tok("punct", "`", line))  # marks a backtick (shell exec) string
            line += src.count("\n", i, j)
            i = min(n, j + 1)
        elif c == "$" and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] == "_"):
            j = i + 2
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok("var", src[i:j], line))
            i = j
        elif c.isalpha() or c == "_" or c == "\\":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_\\"):
                j += 1
            out.append(Tok("id", src[i:j].lstrip("\\"), line))
            i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            out.append(Tok("num", src[i:j], line))
            i = j
        else:
            three, two = src[i:i + 3], src[i:i + 2]
            if three == "?->":
                out.append(Tok("punct", "->", line))
                i += 3
            elif two in PUNCT2:
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
        self.tainted: set[str] = set()
        self.built: set[str] = set()
        self.safe: set[str] = set()   # names assigned a request value that was cast/escaped on the way in
        self.web = any(t.kind == "var" and t.text in SUPERGLOBALS for t in toks)

    # ------------------------------------------------------------------ helpers
    def txt(self, i: int) -> str:
        return self.T[i].text if 0 <= i < self.n else ""

    def is_p(self, i: int, s: str) -> bool:
        return 0 <= i < self.n and self.T[i].kind == "punct" and self.T[i].text == s

    def hit(self, rule: str, line: int, conf: Confidence | None = None, evidence: str | None = None):
        self.hits.append((rule, line, conf, evidence))

    def _funcs(self) -> list[str]:
        T, names = self.T, [""] * self.n
        stack: list[str] = []
        for i, t in enumerate(T):
            names[i] = next((s for s in reversed(stack) if s), "")
            if t.kind == "punct" and t.text == "{":
                name, k = "", i - 1
                for _ in range(40):
                    if k < 0 or T[k].text in (";", "{", "}"):
                        break
                    if T[k].kind == "id" and T[k].text == "function":
                        if k + 1 < self.n and T[k + 1].kind == "id":
                            name = T[k + 1].text
                        break
                    k -= 1
                stack.append(name)
            elif t.kind == "punct" and t.text == "}" and stack:
                stack.pop()
        return names

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
        return hi > lo and all((t.kind in ("str", "num") and not t.interp) or t.text in (".", "(", ")") for t in self.T[lo:hi])

    def has_concat(self, lo: int, hi: int) -> bool:
        seg = self.T[lo:hi]
        if any(t.kind == "str" and t.interp for t in seg):
            return True
        if any(t.kind == "punct" and t.text == "." for t in seg) and any(t.kind == "var" for t in seg):
            return True
        return any(t.text in ("sprintf", "vsprintf") for t in seg)

    def mentions_source(self, lo: int, hi: int) -> bool:
        for k in range(lo, hi):
            t = self.T[k]
            if t.kind == "var" and (t.text in SUPERGLOBALS or t.text in self.tainted):
                return True
            if t.kind == "str" and t.interp and any(v in t.text for v in self.tainted | SUPERGLOBALS):
                return True
        return False

    def escaped(self, lo: int, hi: int) -> bool:
        return any(self.T[x].kind == "id" and self.T[x].text in ESCAPERS for x in range(lo, hi)) or \
            any(self.T[x].text in ("(int)", ) for x in range(lo, hi)) or \
            any(self.is_p(x, "(") and self.txt(x + 1) in ("int", "integer", "float") and self.is_p(x + 2, ")") for x in range(lo, hi))

    def _stmt_names(self, i: int) -> str:
        k = i
        while k > 0 and self.txt(k) not in (";", "{", "}"):
            k -= 1
        return " ".join(t.text for t in self.T[k:i] if t.kind in ("id", "var", "str"))

    def _stmt_end(self, k: int) -> int:
        depth = 0
        while k < self.n:
            t = self.T[k]
            if t.kind == "punct" and t.text in "([{":
                depth += 1
            elif t.kind == "punct" and t.text in ")]}":
                depth -= 1
                if depth < 0:
                    return k
            elif t.kind == "punct" and t.text == ";" and depth <= 0:
                return k
            k += 1
        return k

    # ------------------------------------------------------------------ analysis
    def run(self):
        self._assignments()
        T, n = self.T, self.n
        for i in range(n):
            t = T[i]
            if t.kind == "id":
                low = t.text.lower()
                nxt_open = i + 1 < n and self.is_p(i + 1, "(")
                if low in INCLUDES:
                    self._include(i)
                elif nxt_open and not self.is_p(i - 1, "->") and not self.is_p(i - 1, "::") and low != "function":
                    self._function(i, low)
                elif nxt_open and (self.is_p(i - 1, "->") or self.is_p(i - 1, "::")):
                    self._method(i, low)
                elif low in ("echo", "print"):
                    self._echo(i)
                elif t.text.upper() == "CURLOPT_SSL_VERIFYPEER" or t.text.upper() == "CURLOPT_SSL_VERIFYHOST":
                    if self._falsey_after(i):
                        self.hit("PHP-TLS", t.line, H)
            elif t.kind == "str" and t.text in ("verify_peer", "verify_peer_name") and self.is_p(i + 1, "=>") and self.txt(i + 2).lower() in ("false", "0"):
                self.hit("PHP-TLS", t.line, H)
            elif t.kind == "punct" and t.text == "`" and i > 0 and T[i - 1].kind == "str":
                s = T[i - 1]
                if s.interp:
                    self.hit("PHP-CMDI", s.line, M)
        self._secrets()
        return self.hits

    def _falsey_after(self, i: int) -> bool:
        return self.txt(i + 1) in (",", "=>") and self.txt(i + 2).lower() in ("false", "0") or (
            self.txt(i + 1) == "=>" and self.txt(i + 2).lower() in ("false", "0"))

    def _assignments(self):
        T = self.T
        for i in range(1, self.n - 1):
            if not (self.is_p(i, "=") and T[i - 1].kind == "var") or self.is_p(i + 1, "=") or self.is_p(i - 2, "!"):
                continue
            end = min(self._stmt_end(i + 1), i + 80)
            name = T[i - 1].text
            lits = " ".join(t.text for t in T[i + 1:end] if t.kind == "str")
            sink_result = any(T[k].kind == "id" and T[k].text.lower() in SINK_RESULT and self.is_p(k + 1, "(") for k in range(i + 1, end))
            from_request = self.mentions_source(i + 1, end) and not sink_result
            if from_request and self.escaped(i + 1, end):
                self.safe.add(name)
            src = from_request and not self.escaped(i + 1, end)
            if src:
                self.tainted.add(name)
            if self.has_concat(i + 1, end) and SQL_WORDS.search(lits):
                self.built.add(name)
                if src:
                    self.tainted.add(name)

    def _sql_check(self, line: int, rng):
        lo, hi = rng
        T = self.T
        lits = " ".join(t.text for t in T[lo:hi] if t.kind == "str")
        names = [t.text for t in T[lo:hi] if t.kind == "var"]
        if names and all(v in self.safe for v in names):
            return  # every variable in the query was cast or escaped when it was read from the request
        if self.has_concat(lo, hi) and (SQL_WORDS.search(lits) or self.mentions_source(lo, hi)) and not self.escaped(lo, hi):
            self.hit("PHP-SQLI", line, M)
        elif hi - lo == 1 and T[lo].kind == "var" and T[lo].text in self.built:
            self.hit("PHP-SQLI", line, L)

    def _function(self, i: int, low: str):
        T, line = self.T, self.T[i].line
        a = self.args(i + 1)
        if low in SQL_FUNCS_2 and len(a) >= 2:
            self._sql_check(line, a[1])
        elif low in SQL_FUNCS_1 and a:
            self._sql_check(line, a[0])
        elif low in CMD_FUNCS and a:
            lo, hi = a[0]
            if not self.literal_only(lo, hi) and not self.escaped(lo, hi):
                self.hit("PHP-CMDI", line, M if (self.has_concat(lo, hi) or self.mentions_source(lo, hi)) else L)
        elif low == "eval" and a and not self.literal_only(*a[0]):
            self.hit("PHP-EVAL", line, M)
        elif low == "assert" and a and any(T[x].kind == "var" for x in range(*a[0])) and not self.literal_only(*a[0]):
            self.hit("PHP-EVAL", line, L)
        elif low == "create_function":
            self.hit("PHP-EVAL", line, M)
        elif low == "unserialize" and a and not self.literal_only(*a[0]):
            self.hit("PHP-DESER", line, M if self.mentions_source(*a[0]) else L)
        elif low in ("md5", "sha1", "crypt") and a and SECURITY_CONTEXT.search(self.func_at[i] + " " + self._stmt_names(i)):
            self.hit("PHP-WEAKHASH", line, M)
        elif low in ("rand", "mt_rand", "uniqid", "lcg_value", "str_shuffle", "mt_srand", "srand") and \
                SECURITY_CONTEXT.search(self.func_at[i] + " " + self._stmt_names(i)):
            self.hit("PHP-RANDOM", line, L)
        elif low in FILE_FUNCS and a and self._path_tainted(a[0]):
            self.hit("PHP-PATH", line, M if self.mentions_source(*a[0]) else L)
        elif low == "define" and len(a) >= 2 and T[a[0][0]].kind == "str" and a[1][1] - a[1][0] == 1 and T[a[1][0]].kind == "str":
            self._secret_value(line, T[a[0][0]].text, T[a[1][0]].text)
        elif low == "curl_setopt" and len(a) >= 3 and self.txt(a[1][0]).upper() in ("CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST") \
                and self.txt(a[2][0]).lower() in ("false", "0"):
            self.hit("PHP-TLS", line, H)
        elif low in ("printf", "vprintf", "print_r") and a and self.mentions_source(a[0][0], a[-1][1]) and not self.escaped(a[0][0], a[-1][1]):
            self.hit("PHP-XSS-REFLECT", line, L)

    def _method(self, i: int, low: str):
        a = self.args(i + 1)
        if low in SQL_METHODS and a:
            self._sql_check(self.T[i].line, a[0])

    def _include(self, i: int):
        end = self._stmt_end(i + 1)
        if i + 1 < self.n and self.is_p(i + 1, "("):
            end = self.pair.get(i + 1, end)
        lo, hi = i + 1, end
        if self.source_only_as_index(lo, hi):
            return  # include $pages[$_GET['p']] ?? 'home.php': the request value only selects a key of a fixed map
        if (self.mentions_source(lo, hi) or (self.web and self.has_concat(lo, hi))) and not self.escaped(lo, hi):
            self.hit("PHP-INCLUDE", self.T[i].line, M if self.mentions_source(lo, hi) else L)

    def source_only_as_index(self, lo: int, hi: int) -> bool:
        """True when every request value in [lo, hi) is used as an array subscript of some other variable."""
        T, seen = self.T, False
        for k in range(lo, hi):
            t = T[k]
            if t.kind != "var" or not (t.text in SUPERGLOBALS or t.text in self.tainted):
                continue
            seen = True
            depth, j, indexed = 0, k - 1, False
            while j >= lo:
                if self.is_p(j, "]"):
                    depth += 1
                elif self.is_p(j, "["):
                    if depth == 0:
                        indexed = j > lo and T[j - 1].kind == "var" and T[j - 1].text != t.text
                        break
                    depth -= 1
                j -= 1
            if not indexed:
                return False
        return seen

    def _echo(self, i: int):
        end = self._stmt_end(i + 1)
        if self.mentions_source(i + 1, end) and not self.escaped(i + 1, end):
            self.hit("PHP-XSS-REFLECT", self.T[i].line, L)

    def _path_tainted(self, rng) -> bool:
        lo, hi = rng
        if self.escaped(lo, hi):
            return False
        return self.mentions_source(lo, hi) or (self.web and self.has_concat(lo, hi))

    def _secret_value(self, line: int, name: str, val: str):
        if CRED_NAME.search(name) and not CRED_NAME_EXCLUDE.search(name) and looks_like_secret_value(val):
            red = val[:2] + "*" * 6 if len(val) <= 8 else val[:4] + "*" * 6 + val[-2:]
            self.hit("PHP-SECRET-ASSIGN", line, L if is_placeholder(val) else None, f"{name} = {red}")

    def _secrets(self):
        """`$password = '...';`, `'password' => '...'`, `const SECRET = '...';`"""
        T = self.T
        for i in range(1, self.n - 1):
            if T[i + 1].kind != "str" or T[i + 1].interp:
                continue
            nxt = T[i + 2] if i + 2 < self.n else None
            if nxt is not None and nxt.text not in (";", ",", ")", "]"):
                continue
            if self.is_p(i, "=") and T[i - 1].kind in ("var", "id"):
                self._secret_value(T[i - 1].line, T[i - 1].text.lstrip("$"), T[i + 1].text)
            elif self.is_p(i, "=>") and T[i - 1].kind == "str":
                self._secret_value(T[i - 1].line, T[i - 1].text, T[i + 1].text)


def scan_php(text: str, rel: str) -> list[RawFinding]:
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
