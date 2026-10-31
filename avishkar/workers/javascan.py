"""Java security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer drops comments and understands strings, char literals and text blocks, so text inside comments or strings
can never trigger a rule. Findings are derived from call and construction shapes (`Runtime.getRuntime().exec(cmd + x)`,
`new ObjectInputStream(in)`, `MessageDigest.getInstance("MD5")`). Only simple same-file flows are followed: a string
built from a request parameter or concatenated into an SQL text and later passed to a sink.

Honest limits: this is NOT a Java parser. No types, no inheritance, no cross-file or cross-method data flow, no
framework-aware sanitizer knowledge. Expect misses (for example a query built in another class) and some false
positives; each rule's assurance (structural vs heuristic) is declared in `avishkar.knowledge`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, SECURITY_CONTEXT, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
JAVA_RULES = ("JAVA-SQLI", "JAVA-CMDI", "JAVA-DESER", "JAVA-WEAKHASH", "JAVA-WEAKCIPHER", "JAVA-RANDOM",
              "JAVA-SECRET-ASSIGN", "JAVA-TLS", "JAVA-XXE", "JAVA-PATH", "JAVA-XSS-REFLECT", "JAVA-EVAL")
SEVERITY = {"JAVA-SQLI": (Severity.HIGH, M), "JAVA-CMDI": (Severity.HIGH, M), "JAVA-DESER": (Severity.MEDIUM, M),
            "JAVA-WEAKHASH": (Severity.LOW, M), "JAVA-WEAKCIPHER": (Severity.MEDIUM, M), "JAVA-RANDOM": (Severity.MEDIUM, L),
            "JAVA-SECRET-ASSIGN": (Severity.HIGH, M), "JAVA-TLS": (Severity.MEDIUM, H), "JAVA-XXE": (Severity.MEDIUM, L),
            "JAVA-PATH": (Severity.MEDIUM, L), "JAVA-XSS-REFLECT": (Severity.MEDIUM, L), "JAVA-EVAL": (Severity.HIGH, M)}
MAX_TOKENS = 400_000

SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter|where|from|values|union)\b")
SQL_SINKS = {"executeQuery", "executeUpdate", "execute", "executeLargeUpdate", "addBatch", "prepareStatement",
             "prepareCall", "createNativeQuery", "createQuery", "nativeQuery"}
SOURCES = {"getParameter", "getParameterValues", "getHeader", "getQueryString", "getPathInfo", "getRequestURI",
           "getRequestURL", "getCookies", "getParameterMap"}
ESCAPERS = {"escapeHtml", "escapeHtml4", "escapeXml", "escapeXml10", "htmlEscape", "encodeForHTML", "encodeForHtml",
            "forHtml", "encode", "sanitize"}
FILE_CTORS = {"File", "FileInputStream", "FileReader", "FileOutputStream", "FileWriter", "RandomAccessFile"}
XML_FACTORIES = {"DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory", "TransformerFactory", "SchemaFactory"}
XXE_SAFE = ("disallow-doctype-decl", "FEATURE_SECURE_PROCESSING", "IS_SUPPORTING_EXTERNAL_ENTITIES", "ACCESS_EXTERNAL_DTD",
            "external-general-entities", "SUPPORT_DTD")
SHELL_PROGS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "/bin/sh", "/bin/bash"}
SHELL_FLAGS = {"-c", "/c", "-command"}
CONTROL = {"if", "for", "while", "switch", "catch", "synchronized", "try", "return", "new", "else", "do"}
PUNCT2 = {"->", "::", "+=", "==", "!=", "<=", ">=", "&&", "||", "++", "--"}


@dataclass
class Tok:
    kind: str       # id | num | str | chr | punct
    text: str       # for str/chr the unquoted content
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
        elif src.startswith('"""', i):
            j = src.find('"""', i + 3)
            while j > 0 and src[j - 1] == "\\":
                j = src.find('"""', j + 1)
            j = n if j < 0 else j
            out.append(Tok("str", src[i + 3:j], line))
            line += src.count("\n", i, j)
            i = min(n, j + 3)
        elif c == '"' or c == "'":
            j, buf = i + 1, []
            while j < n and src[j] != c and src[j] != "\n":
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2])
                    j += 2
                else:
                    buf.append(src[j])
                    j += 1
            out.append(Tok("str" if c == '"' else "chr", "".join(buf), line))  # unterminated: stop at the newline
            i = j + 1 if j < n and src[j] == c else j
        elif c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
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
        self.method_at = self._methods()
        self.tainted: set[str] = set()   # names assigned from an HTTP request source (simple same-file flow)
        self.built: set[str] = set()     # names assigned an SQL text built by concatenation / formatting
        self.runtimes: set[str] = set()  # names assigned Runtime.getRuntime()
        self.argv: set[str] = set()      # String[] names whose first element is a fixed, non-shell program: no shell parses them
        # a web handler reads HTTP request data somewhere in the file; only then is a concatenated path suspicious
        self.web = any(t.kind == "id" and (t.text in SOURCES or t.text in ("HttpServletRequest", "MultipartFile", "RequestParam", "PathVariable"))
                       for t in toks)

    # ------------------------------------------------------------------ helpers
    def txt(self, i: int) -> str:
        return self.T[i].text if 0 <= i < self.n else ""

    def is_p(self, i: int, s: str) -> bool:
        return 0 <= i < self.n and self.T[i].kind == "punct" and self.T[i].text == s

    def hit(self, rule: str, line: int, conf: Confidence | None = None, evidence: str | None = None):
        self.hits.append((rule, line, conf, evidence))

    def _methods(self) -> list[str]:
        """For every token index, the name of the nearest enclosing method ('' when none)."""
        T, names = self.T, [""] * self.n
        stack: list[str] = []
        for i, t in enumerate(T):
            names[i] = next((s for s in reversed(stack) if s), "")
            if t.kind == "punct" and t.text == "{":
                name, k = "", i - 1
                for _ in range(14):  # skip `throws A, B` back to the closing paren of the parameter list
                    if k < 0 or T[k].text in (";", "{", "}"):
                        break
                    if T[k].text == ")":
                        o = next((a for a, b in self.pair.items() if b == k), None)
                        if o is not None and o > 0 and T[o - 1].kind == "id" and T[o - 1].text not in CONTROL:
                            name = T[o - 1].text
                        break
                    k -= 1
                stack.append(name)
            elif t.kind == "punct" and t.text == "}" and stack:
                stack.pop()
        return names

    def args(self, open_i: int) -> list[tuple[int, int]]:
        """Token index ranges [lo, hi) of the top-level arguments of the call whose '(' is at open_i."""
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
        return all(t.kind in ("str", "chr", "num") or t.text in ("+", "(", ")") for t in self.T[lo:hi]) and hi > lo

    def has_concat(self, lo: int, hi: int) -> bool:
        seg = self.T[lo:hi]
        if any(t.kind == "punct" and t.text == "+" for t in seg) and not self.literal_only(lo, hi):
            return True
        return any(t.text in ("format", "formatted", "concat") and k > 0 and self.T[lo + k - 1].text in (".",)
                   for k, t in enumerate(seg))

    def mentions_source(self, lo: int, hi: int) -> bool:
        return any((t.kind == "id" and (t.text in SOURCES or t.text in self.tainted)) for t in self.T[lo:hi])

    def receiver(self, i: int) -> list[str]:
        """Identifiers of the dotted chain before the method name at index i: `Runtime.getRuntime().exec` -> [Runtime, getRuntime]."""
        out, k = [], i - 1
        while k >= 1 and self.is_p(k, "."):
            k -= 1
            if self.is_p(k, ")"):
                o = next((a for a, b in self.pair.items() if b == k), None)
                if o is None:
                    break
                k = o - 1
            if k >= 0 and self.T[k].kind == "id":
                out.append(self.T[k].text)
                k -= 1
            else:
                break
        return list(reversed(out))

    def evidence(self, line: int) -> str:
        return redact_text(self.lines[line - 1].strip()[:160]) if 0 < line <= len(self.lines) else ""

    # ------------------------------------------------------------------ analysis
    def run(self):
        self._assignments()
        T, n = self.T, self.n
        for i in range(n):
            t = T[i]
            if t.kind != "id":
                continue
            nxt_open = i + 1 < n and self.is_p(i + 1, "(")
            if t.text == "new" and i + 1 < n and T[i + 1].kind == "id":
                self._constructor(i)
            elif nxt_open and self.is_p(i - 1, "."):
                self._method_call(i)
            elif t.text == "checkServerTrusted" and nxt_open:
                self._trust_manager(i)
            elif t.text in ("NoopHostnameVerifier", "ALLOW_ALL_HOSTNAME_VERIFIER", "TrustAllStrategy"):
                self.hit("JAVA-TLS", t.line, M)
        for i, t in enumerate(T):
            if t.kind == "punct" and t.text == "->" and self.txt(i + 1) == "true" and self.is_p(i - 1, ")"):
                o = next((a for a, b in self.pair.items() if b == i - 1), None)
                if o is not None and len(self.args(o)) == 2 and self._near("HostnameVerifier", i):
                    self.hit("JAVA-TLS", t.line, H)
        self._xxe()
        return self.hits

    def _near(self, word: str, i: int, span: int = 12) -> bool:
        return any(self.txt(k) in (word, "setHostnameVerifier", "setDefaultHostnameVerifier") for k in range(max(0, i - span), i))

    def _assignments(self):
        """Collect `name = <expr>;` flows: names fed by request sources, and SQL texts built by concatenation."""
        T = self.T
        for i in range(1, self.n - 1):
            if not (self.is_p(i, "=") and T[i - 1].kind == "id") or self.is_p(i + 1, "="):
                continue
            end = i + 1
            while end < self.n and not self.is_p(end, ";") and end - i < 80:
                end += 1
            name = T[i - 1].text
            if any(t.text == "getRuntime" for t in T[i + 1:end]):
                self.runtimes.add(name)
            self._argv_decl(i, end)
            if self.mentions_source(i + 1, end):
                self.tainted.add(name)
            lits = " ".join(t.text for t in T[i + 1:end] if t.kind == "str")
            if self.has_concat(i + 1, end) and SQL_WORDS.search(lits):
                self.built.add(name)
                if self.mentions_source(i + 1, end):
                    self.tainted.add(name)

    def _argv_decl(self, eq: int, end: int):
        """`String[] cmd = {"xxd", path};` / `= new String[] {"xxd", path}`: a fixed program name followed by arguments."""
        T = self.T
        b = next((k for k in range(eq + 1, end) if self.is_p(k, "{")), None)
        if b is None or not (self.txt(eq - 2) == "]" or any(t.text == "String" for t in T[max(0, eq - 4):eq])):
            return
        first = T[b + 1] if b + 1 < self.n else None
        if first is not None and first.kind == "str" and first.text.lower() not in SHELL_PROGS:
            self.argv.add(T[eq - 1].text)

    def _constructor(self, i: int):
        T = self.T
        cls = T[i + 1].text
        k = i + 2
        while k < self.n and (self.is_p(k, ".") or T[k].kind == "id"):
            cls = T[k].text if T[k].kind == "id" else cls
            k += 1
        # generics: new Foo<Bar>(...)
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
        if cls in ("ObjectInputStream", "XMLDecoder"):
            self.hit("JAVA-DESER", line, M)
        elif cls == "Yaml" and not any(t.text in ("SafeConstructor",) for t in T[k:self.pair.get(k, k)]):
            self.hit("JAVA-DESER", line, L)
        elif cls == "Random" and SECURITY_CONTEXT.search(self.method_at[i] + " " + self._stmt_names(i)):
            self.hit("JAVA-RANDOM", line, L)
        elif cls == "ProcessBuilder":
            # a shell program followed by its "run this string" flag, with a variable part: `new ProcessBuilder("sh", "-c", cmd)`
            texts = [("".join(T[x].text for x in range(lo, hi) if T[x].kind == "str").lower(), self.literal_only(lo, hi)) for lo, hi in a]
            shell = bool(texts) and texts[0][1] and texts[0][0] in SHELL_PROGS and any(t in SHELL_FLAGS for t, _ in texts[1:])
            if shell and any(not lit for _, lit in texts):
                self.hit("JAVA-CMDI", line, M)
        elif cls in FILE_CTORS and a and self._path_tainted(a[0]):
            self.hit("JAVA-PATH", line, M if self.mentions_source(*a[0]) else L)

    def _stmt_names(self, i: int) -> str:
        k = i
        while k > 0 and self.txt(k) not in (";", "{", "}"):
            k -= 1
        return " ".join(t.text for t in self.T[k:i] if t.kind == "id")

    def _path_tainted(self, rng) -> bool:
        lo, hi = rng
        if any(self.T[x].text in ("getName", "normalize", "getCanonicalPath", "toRealPath", "basename") for x in range(lo, hi)):
            return False  # a normalising / base-name call is in the expression
        return self.mentions_source(lo, hi) or (self.web and self.has_concat(lo, hi))

    def _method_call(self, i: int):
        T, name, line = self.T, self.T[i].text, self.T[i].line
        a, recv = self.args(i + 1), self.receiver(i)
        first = a[0] if a else None
        if name in SQL_SINKS and first:
            lo, hi = first
            lits = " ".join(t.text for t in T[lo:hi] if t.kind == "str")
            if self.has_concat(lo, hi) and (SQL_WORDS.search(lits) or self.mentions_source(lo, hi)):
                self.hit("JAVA-SQLI", line, M)
            elif hi - lo == 1 and T[lo].kind == "id" and T[lo].text in self.built:
                self.hit("JAVA-SQLI", line, L)
        elif name == "exec" and ("getRuntime" in recv or recv[-1:] and recv[-1] in self.runtimes) and first:
            lo, hi = first
            fixed_argv = (hi - lo == 1 and T[lo].text in self.argv) or (T[lo].text == "new" and self.txt(lo + 1) == "String" and any(
                self.is_p(k, "{") and T[k + 1].kind == "str" and T[k + 1].text.lower() not in SHELL_PROGS for k in range(lo, min(hi, lo + 5))))
            if not self.literal_only(lo, hi) and not fixed_argv:
                self.hit("JAVA-CMDI", line, M if (self.has_concat(lo, hi) or self.mentions_source(lo, hi)) else L)
        elif name == "getInstance" and first and recv[-1:] == ["MessageDigest"]:
            alg = "".join(t.text for t in T[first[0]:first[1]] if t.kind == "str").upper()
            if alg in ("MD5", "MD2", "MD4", "SHA-1", "SHA1", "SHA"):
                self.hit("JAVA-WEAKHASH", line, M)
        elif name == "getInstance" and first and recv[-1:] == ["Cipher"]:
            alg = "".join(t.text for t in T[first[0]:first[1]] if t.kind == "str").upper()
            if re.match(r"^(DES|DESEDE|RC2|RC4|ARCFOUR|BLOWFISH)\b", alg) or "/ECB/" in alg or alg == "AES":
                self.hit("JAVA-WEAKCIPHER", line, M)
        elif name == "random" and recv[-1:] == ["Math"] and SECURITY_CONTEXT.search(self.method_at[i] + " " + self._stmt_names(i)):
            self.hit("JAVA-RANDOM", line, L)
        elif name in ("get", "of") and recv[-1:] in (["Paths"], ["Path"]) and first and self._path_tainted(first):
            self.hit("JAVA-PATH", line, M if self.mentions_source(*first) else L)
        elif name == "eval" and "ScriptEngine" in self.text and first and not self.literal_only(*first):
            self.hit("JAVA-EVAL", line, M)
        elif name in ("println", "print", "write", "append", "printf", "format") and first and \
                (any(r in ("getWriter", "out", "writer", "pw") or r.lower().endswith("writer") for r in recv)):
            lo, hi = first
            esc = any(T[x].text in ESCAPERS for x in range(lo, hi))
            if self.mentions_source(lo, hi) and not esc:
                self.hit("JAVA-XSS-REFLECT", line, L)
        elif name == "setPassword" and first and len(T[first[0]:first[1]]) == 1 and T[first[0]].kind == "str":
            self._secret_value(line, "password", T[first[0]].text)
        elif name == "getConnection" and len(a) >= 3 and len(T[a[2][0]:a[2][1]]) == 1 and T[a[2][0]].kind == "str":
            self._secret_value(line, "password", T[a[2][0]].text)
        elif name in ("setHostnameVerifier", "setDefaultHostnameVerifier") and first:
            if any(T[x].text in ("NoopHostnameVerifier", "ALLOW_ALL_HOSTNAME_VERIFIER") for x in range(*first)):
                self.hit("JAVA-TLS", line, H)

    def _secret_value(self, line: int, name: str, val: str):
        if looks_like_secret_value(val):
            red = val[:2] + "*" * 6 if len(val) <= 8 else val[:4] + "*" * 6 + val[-2:]
            self.hit("JAVA-SECRET-ASSIGN", line, L if is_placeholder(val) else None, f"{name} = {red}")

    def _trust_manager(self, i: int):
        close = self.pair.get(i + 1)
        if close is None or not self.is_p(close + 1, "{"):
            return
        body = self.pair.get(close + 1)
        if body is None:
            return
        inner = [t.text for t in self.T[close + 2:body]]
        if inner in ([], ["return", ";"]):
            self.hit("JAVA-TLS", self.T[i].line, H)

    def _xxe(self):
        if any(w in self.text for w in XXE_SAFE):
            return
        parses_input = any(t.text in ("StreamSource", "SAXSource", "InputSource", "parse", "createXMLStreamReader",
                                      "createXMLEventReader", "newSAXParser", "newDocumentBuilder") for t in self.T)
        for i in range(self.n - 2):
            # a TransformerFactory that only writes XML out (DOMSource -> StreamResult) is not an XXE risk
            if self.T[i].text == "TransformerFactory" and not any(t.text in ("StreamSource", "SAXSource") for t in self.T):
                continue
            if not parses_input and self.T[i].text != "TransformerFactory":
                continue
            if self.T[i].text in XML_FACTORIES and self.is_p(i + 1, ".") and self.txt(i + 2) in ("newInstance", "newFactory"):
                self.hit("JAVA-XXE", self.T[i].line, L)

    def secrets(self):
        """`String password = "literal";` style declarations and assignments (also fields and constants)."""
        T = self.T
        for i in range(1, self.n - 2):
            if self.is_p(i, "=") and T[i - 1].kind == "id" and T[i + 1].kind == "str" and (self.is_p(i + 2, ";") or self.is_p(i + 2, ",")):
                name = T[i - 1].text
                if CRED_NAME.search(name) and not CRED_NAME_EXCLUDE.search(name):
                    self._secret_value(T[i - 1].line, name, T[i + 1].text)


def scan_java(text: str, rel: str) -> list[RawFinding]:
    toks = tokenize(text)
    lines = text.splitlines()
    an = _Analyzer(toks, lines, text)
    an.run()
    an.secrets()
    hits = an.hits
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
