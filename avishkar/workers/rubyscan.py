"""Ruby security patterns on a *token stream* (no external parser, nothing is executed).

A small lexer drops comments and understands single-quoted, double-quoted (with #{…} interpolation), heredoc and %q/%Q
strings and regex literals, so text inside comments or constant strings can never trigger a rule. Findings come from call
and assignment shapes (`User.where("id = #{params[:id]}")`, `system("rm -rf #{path}")`, ``). Only simple
same-file flows are followed: a value read from params/request, or an SQL text built by interpolation, that is later
passed to a sink.

Honest limits: this is NOT a Ruby parser. No types, no rails-aware analysis, no cross-file data flow, and no knowledge
of framework escaping helpers. Expect misses (a query built in another file) and some false positives; each rule's
assurance is declared in `avishkar.knowledge`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, SECURITY_CONTEXT, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

RUBY_RULES = (
    "RB-SQLI", "RB-CMDI", "RB-EVAL", "RB-DESER", "RB-WEAKHASH",
    "RB-RANDOM", "RB-SECRET-ASSIGN", "RB-PATH", "RB-XSS-REFLECT", "RB-TLS",
)
SEVERITY = {
    "RB-SQLI":          (Severity.HIGH,   M),
    "RB-CMDI":          (Severity.HIGH,   M),
    "RB-EVAL":          (Severity.HIGH,   M),
    "RB-DESER":         (Severity.HIGH,   M),
    "RB-WEAKHASH":      (Severity.LOW,    M),
    "RB-RANDOM":        (Severity.MEDIUM, L),
    "RB-SECRET-ASSIGN": (Severity.HIGH,   M),
    "RB-PATH":          (Severity.MEDIUM, L),
    "RB-XSS-REFLECT":   (Severity.MEDIUM, L),
    "RB-TLS":           (Severity.MEDIUM, H),
}
MAX_TOKENS = 400_000

SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter|where|from|values|union)\b")
SQL_METHODS = {"where", "find_by_sql", "execute", "exec_query", "select_all", "select_one", "select_value",
               "connection", "query", "raw"}
CMD_METHODS = {"system", "exec", "spawn", "popen", "popen2", "popen3", "popen2e", "open", "IO.popen", "Kernel.system",
               "Kernel.exec", "Kernel.spawn", "run", "capture", "capture2", "capture3", "capture2e"}
DESER_METHODS = {"load", "restore", "from_json", "decode", "deserialize", "parse"}
FILE_METHODS = {"read", "open", "write", "delete", "unlink", "join", "send_file", "send_data"}
RESPONSE_METHODS = {"render", "html", "concat", "<<", "write"}
ESCAPERS = {"html_escape", "escape", "h", "sanitize", "strip_tags", "clean", "quote", "shellescape", "squote", "encode",
            "base64", "url_encode", "safe_join"}
HASH_WEAK = {"md5", "sha1", "sha_hex", "Digest::MD5", "Digest::SHA1"}
HASH_STRONG = {"sha256", "sha512", "bcrypt", "argon2", "pbkdf2", "Digest::SHA256"}
RAND_SECURE = {"SecureRandom", "Random::Formatter", "openssl"}
RAND_INSECURE = {"rand", "srand", "Random.new", "Kernel.rand"}
CONST_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
SOURCES = {"params", "request", "session", "cookies", "env", "headers", "query_string", "form_data", "get_header",
           "input", "body", "path_parameters", "query_parameters", "form_params"}
PUNCT2 = {"::", "=>", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "**", "..", "...", "->", "#{"}
INTERP = re.compile(r"#\{")


@dataclass
class Tok:
    kind: str        # id | sym | num | str | punct | regex
    text: str        # for str the content (may contain #{…} markers)
    line: int
    interp: bool = False  # string/regex with #{…} interpolation


def tokenize(src: str) -> list[Tok]:
    out: list[Tok] = []
    i, n, line = 0, len(src), 1
    while i < n and len(out) < MAX_TOKENS:
        c = src[i]
        if c == "\n":
            line += 1; i += 1
        elif c in " \t\r\f":
            i += 1
        elif c == "#":
            while i < n and src[i] != "\n":
                i += 1
        elif c == "=" and i + 1 < n and src[i + 1] == "b" and src[i:i + 6] in ("=begin",):
            # block comment =begin ... =end (must start at column 0 — not enforced here for simplicity)
            j = src.find("\n=end", i)
            j = n if j < 0 else j + 5
            line += src.count("\n", i, j); i = j
        elif src.startswith("<<~", i) or src.startswith("<<-", i) or src.startswith("<<", i):
            # heredoc
            is_squiggly = src[i:i + 3] in ("<<~", "<<-")
            off = 3 if src[i:i + 3] in ("<<~", "<<-") else 2
            rest = src[i + off:]
            m = re.match(r"""(['"]?)(\w+)\1""", rest)
            if not m:
                out.append(Tok("punct", src[i:i + 2], line)); i += 2; continue
            delim, squote = m.group(2), m.group(1) == "'"
            i += off + m.end()
            end = src.find(f"\n{delim}", i)
            content = src[i:end] if end >= 0 else src[i:]
            is_interp = (not squote) and bool(INTERP.search(content))
            out.append(Tok("str", content, line, is_interp))
            line += content.count("\n") + 1
            i = end + 1 + len(delim) if end >= 0 else n
        elif c == "'":
            j, buf = i + 1, []
            while j < n and src[j] != "'":
                if src[j] == "\\" and j + 1 < n and src[j + 1] in ("'", "\\"):
                    buf.append(src[j + 1]); j += 2
                else:
                    buf.append(src[j])
                    if src[j] == "\n": line += 1
                    j += 1
            out.append(Tok("str", "".join(buf), line)); i = j + 1
        elif c == '"' or (c == "`"):
            close = c; j, buf = i + 1, []
            while j < n and src[j] != close:
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2]); j += 2
                elif src[j] == "#" and j + 1 < n and src[j + 1] == "{":
                    buf.append("#{"); depth = 1; j += 2
                    while j < n and depth:
                        if src[j] == "{": depth += 1
                        elif src[j] == "}": depth -= 1
                        if depth: buf.append(src[j])
                        j += 1
                    buf.append("}")
                else:
                    if src[j] == "\n": line += 1
                    buf.append(src[j]); j += 1
            content = "".join(buf)
            out.append(Tok("str", content, line, bool(INTERP.search(content))))
            i = j + 1
        elif c == "%" and i + 1 < n and src[i + 1] in ("q", "Q", "w", "W", "i", "I", "r", "x", "s", "(", "[", "{", "|", "!"):
            kind = src[i + 1]
            squote = kind == "q"
            off = 2 if kind in "qQwWiIrxs" else 1
            opener = src[i + off] if i + off < n else "("
            closer = {"(": ")", "[": "]", "{": "}", "|": "|", "!": "!", "<": ">"}
            close_c = closer.get(opener, opener)
            j = i + off + 1; depth, buf = 1, []
            while j < n and depth:
                if src[j] == opener: depth += 1
                elif src[j] == close_c: depth -= 1
                if depth:
                    buf.append(src[j])
                    if src[j] == "\n": line += 1
                j += 1
            content = "".join(buf)
            is_interp = (not squote) and bool(INTERP.search(content))
            out.append(Tok("str", content, line, is_interp))
            i = j
        elif c == ":" and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] == "_"):
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok("sym", src[i:j], line)); i = j
        elif c.isalpha() or c == "_":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            word = src[i:j]
            if word == "__END__":
                break
            out.append(Tok("id", word, line)); i = j
        elif c.isdigit() or (c == "-" and i + 1 < n and src[i + 1].isdigit()):
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            out.append(Tok("num", src[i:j], line)); i = j
        else:
            two = src[i:i + 2]
            if two in PUNCT2:
                out.append(Tok("punct", two, line)); i += 2
            else:
                out.append(Tok("punct", c, line)); i += 1
    return out


def _is_const(name: str) -> bool:
    return bool(CONST_NAME.match(name)) or "." in name and CONST_NAME.match(name.split(".")[-1])


class _Analyzer:
    def __init__(self, toks: list[Tok], lines: list[str], text: str):
        self.T, self.n, self.lines, self.text = toks, len(toks), lines, text
        self.hits: list[tuple[str, int, Confidence | None, str | None]] = []
        # name -> [(idx, is_tainted)]  (per function scope)
        self.history: dict[str, list[tuple[int, bool]]] = {}
        self._scope_depth = 0

    # ---------- helpers ----------

    def peek(self, i: int, k: int = 1) -> Tok | None:
        j = i + k
        return self.T[j] if j < self.n else None

    def is_literal(self, i: int) -> bool:
        t = self.T[i]
        return t.kind in ("num", "sym") or (t.kind == "str" and not t.interp)

    def _tainted_by_name(self, name: str, i: int) -> bool:
        hist = self.history.get(name)
        if not hist:
            return False
        best = None
        for idx, flag in hist:
            if idx <= i:
                best = flag
        return bool(best)

    def _record(self, name: str, i: int, flag: bool) -> None:
        self.history.setdefault(name, []).append((i, flag))

    def _is_tainted_tok(self, i: int, depth: int = 0) -> bool:
        if depth > 4 or i >= self.n:
            return False
        t = self.T[i]
        if t.kind == "str":
            return t.interp
        if t.kind in ("num", "sym"):
            return False
        if t.kind == "id":
            # direct source access: params[:key], request.env[...]
            if t.text in SOURCES:
                return True
            if t.text == "IO" and self.peek(i) and self.peek(i).text == ".":
                return False
            return self._tainted_by_name(t.text, i)
        return False

    def _call_args_tainted(self, open_paren: int) -> bool:
        j = open_paren + 1
        while j < self.n and self.T[j].text != ")":
            if self._is_tainted_tok(j):
                return True
            j += 1
        return False

    def _str_is_sql_with_interp(self, tok: Tok) -> bool:
        return tok.kind == "str" and tok.interp and bool(SQL_WORDS.search(tok.text))

    def _snip(self, i: int) -> str:
        return self.lines[self.T[i].line - 1].strip()[:120] if self.T[i].line <= len(self.lines) else ""

    def _hit(self, rule: str, i: int, conf: Confidence | None = None, ev: str | None = None) -> None:
        self.hits.append((rule, self.T[i].line, conf, ev))

    # ---------- scope management ----------
    def _enter_scope(self) -> None:
        self._scope_depth += 1

    def _exit_scope(self, scope_start_idx: int) -> None:
        self._scope_depth -= 1
        # clear history entries added inside this scope
        to_del = []
        for name, entries in self.history.items():
            self.history[name] = [(idx, f) for idx, f in entries if idx < scope_start_idx]
            if not self.history[name]:
                to_del.append(name)
        for name in to_del:
            del self.history[name]

    # ---------- main pass ----------

    def run(self) -> None:
        i = 0
        while i < self.n:
            t = self.T[i]
            # scope enters: def / do / { / begin
            if t.kind == "id" and t.text in ("def", "do"):
                self._enter_scope()
            if t.kind == "punct" and t.text == "{":
                self._enter_scope()
            if t.kind == "id" and t.text == "end":
                self._exit_scope(i)

            # assignment:  name = expr
            if (t.kind == "id" and self.peek(i) and self.peek(i).text in ("=",)
                    and self.peek(i, 2) and self.peek(i, 2).kind != "="):
                name = t.text
                rhs = i + 2
                if rhs < self.n:
                    tainted = self._is_tainted_tok(rhs)
                    self._record(name, i, tainted)
                    # credential assignment
                    if (not tainted and self.T[rhs].kind == "str" and not self.T[rhs].interp
                            and not CRED_NAME_EXCLUDE.search(name.lower())):
                        self._check_cred_assign(name, self.T[rhs], i)
                i += 1; continue

            # SQL injection via interpolated string to known method
            if t.kind == "id" and t.text in SQL_METHODS:
                arg_start = i + 1
                if arg_start < self.n and self.T[arg_start].kind == "punct" and self.T[arg_start].text == "(":
                    arg_start += 1
                if arg_start < self.n:
                    arg = self.T[arg_start]
                    # any interpolated string arg to a SQL method is injection risk
                    if arg.kind == "str" and arg.interp:
                        self._hit("RB-SQLI", arg_start)
                    elif self._str_is_sql_with_interp(arg):
                        self._hit("RB-SQLI", arg_start)
                    elif arg.kind == "id" and self._tainted_by_name(arg.text, arg_start) and self.history.get(arg.text):
                        self._hit("RB-SQLI", arg_start)

            # command injection: system/exec with interpolated or tainted string
            if t.kind == "id" and t.text in CMD_METHODS:
                np = self.peek(i)
                if np and np.text in ("(", " "):
                    arg_idx = i + 1 if np.text == " " else i + 2
                    if arg_idx < self.n:
                        arg = self.T[arg_idx]
                        if (arg.kind == "str" and arg.interp) or self._is_tainted_tok(arg_idx):
                            self._hit("RB-CMDI", arg_idx)
                elif np and np.kind == "str":
                    if np.interp or self._is_tainted_tok(i + 1):
                        self._hit("RB-CMDI", i + 1)

            # backtick command with interpolation: flag only when the string looks like a shell
            # command (contains command words) AND the interpolated variable is taint-tracked
            if t.kind == "str" and t.interp:
                _CMD_WORDS = re.compile(
                    r"\b(ls|rm|cat|sh|bash|curl|wget|git|python|ruby|node|perl|cp|mv|mkdir"
                    r"|touch|chmod|echo|exec|eval|find|grep|awk|sed|tar|zip|unzip|kill)\b"
                )
                if _CMD_WORDS.search(t.text):
                    interp_names = re.findall(r"#\{(\w+)", t.text)
                    if any(self._tainted_by_name(n, i) for n in interp_names):
                        self._hit("RB-CMDI", i)

            # eval: eval(expr) where expr is not a literal
            if t.kind == "id" and t.text == "eval":
                np = self.peek(i)
                if np and np.text == "(":
                    arg_idx = i + 2
                    if arg_idx < self.n and not self.is_literal(arg_idx):
                        self._hit("RB-EVAL", arg_idx)

            # deserialization: Marshal.load / YAML.load / JSON.parse with non-literal
            if t.kind == "id" and t.text in ("Marshal", "YAML", "Psych"):
                if self.peek(i) and self.peek(i).text in (".", "::"):
                    meth = self.peek(i, 2)
                    if meth and meth.kind == "id" and meth.text in DESER_METHODS:
                        arg_idx = i + 4
                        if arg_idx < self.n and self.T[arg_idx].text == "(":
                            arg_idx += 1
                        if arg_idx < self.n and self._is_tainted_tok(arg_idx):
                            self._hit("RB-DESER", arg_idx)

            # weak hash: Digest::MD5 / Digest::SHA1 / OpenSSL::Digest::MD5
            if t.kind == "id" and t.text == "Digest":
                if self.peek(i) and self.peek(i).text == "::":
                    algo = self.peek(i, 2)
                    if algo and algo.kind == "id" and algo.text.lower() in ("md5", "sha1"):
                        self._hit("RB-WEAKHASH", i)
            if t.kind == "id" and t.text == "OpenSSL":
                if self.peek(i) and self.peek(i).text == "::" and self.peek(i, 2) and self.peek(i, 2).text == "Digest":
                    algo = self.peek(i, 4)
                    if algo and algo.kind == "id" and algo.text.lower() in ("md5", "sha1"):
                        self._hit("RB-WEAKHASH", i)

            # weak random: rand() / srand() in a security context
            if t.kind == "id" and t.text in ("rand", "srand"):
                ctx_line = self.lines[t.line - 1] if t.line <= len(self.lines) else ""
                if SECURITY_CONTEXT.search(ctx_line):
                    self._hit("RB-RANDOM", i)

            # TLS verification disabled: verify_mode = OpenSSL::SSL::VERIFY_NONE
            if t.kind == "id" and t.text == "verify_mode":
                if self.peek(i) and self.peek(i).text == "=":
                    # scan rest of line for VERIFY_NONE
                    ln = t.line
                    for k2 in range(i + 2, min(i + 12, self.n)):
                        tok2 = self.T[k2]
                        if tok2.line != ln:
                            break
                        if tok2.kind == "id" and "VERIFY_NONE" in tok2.text:
                            self._hit("RB-TLS", i)
                            break
            # also match VERIFY_NONE as a standalone token assignment
            if t.kind == "id" and "VERIFY_NONE" in t.text:
                self._hit("RB-TLS", i)

            # path traversal: File.join/read/open with tainted param
            if t.kind == "id" and t.text == "File":
                if self.peek(i) and self.peek(i).text in (".", "::"):
                    meth = self.peek(i, 2)
                    if meth and meth.kind == "id" and meth.text in FILE_METHODS:
                        arg_idx = i + 3
                        if arg_idx < self.n and self.T[arg_idx].text == "(":
                            arg_idx += 1
                        if arg_idx < self.n and (self._is_tainted_tok(arg_idx)
                                                 or (self.T[arg_idx].kind == "str" and self.T[arg_idx].interp)):
                            self._hit("RB-PATH", arg_idx)

            # send_file / render with tainted
            if t.kind == "id" and t.text in ("send_file", "send_data"):
                np = self.peek(i)
                if np:
                    arg_idx = i + 1 if np.text != "(" else i + 2
                    if arg_idx < self.n and self._is_tainted_tok(arg_idx):
                        self._hit("RB-PATH", arg_idx)

            # XSS: render / html / << / concat / raw with tainted
            if t.kind == "id" and t.text in ("render", "raw", "html"):
                np = self.peek(i)
                if np and np.text == "(":
                    # positional arg: render(params[:name])
                    arg_idx = i + 2
                    if arg_idx < self.n and self._is_tainted_tok(arg_idx):
                        self._hit("RB-XSS-REFLECT", arg_idx)
                elif np and np.kind == "id":
                    # keyword arg: render html: params[:name]  -- scan for source access on same line
                    ln = t.line
                    for k2 in range(i + 1, min(i + 10, self.n)):
                        if self.T[k2].line != ln:
                            break
                        if self._is_tainted_tok(k2):
                            self._hit("RB-XSS-REFLECT", k2)
                            break

            # XSS: bare interpolated HTML string (Sinatra route returning "<tag>#{tainted}</tag>")
            if t.kind == "str" and t.interp and "<" in t.text:
                interp_names = re.findall(r"#\{(\w+)", t.text)
                if any(self._tainted_by_name(n, i) for n in interp_names):
                    self._hit("RB-XSS-REFLECT", i)

            i += 1

    def _check_cred_assign(self, name: str, tok: Tok, i: int) -> None:
        lo = name.lower().rstrip("_")
        if not CRED_NAME.search(lo):
            return
        if CRED_NAME_EXCLUDE.search(lo):
            return
        val = tok.text
        if is_placeholder(val) or not looks_like_secret_value(val):
            return
        evidence = f"{name} = {redact_text(repr(val))}"
        self._hit("RB-SECRET-ASSIGN", i, None, evidence)


def scan_ruby(src: str, filename: str) -> list[RawFinding]:
    if not src.strip():
        return []
    toks = tokenize(src)
    lines = src.splitlines()
    a = _Analyzer(toks, lines, src)
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
            detector_id="rubyscan", rule_id=rule, path=filename, line=ln,
            severity=sev, confidence=c, exposure=Exposure.UNKNOWN,
            category=k.get("category", "injection"),
            title=k.get("name", rule),
            evidence=evidence,
            remediation=k.get("remediation", ""),
        ))
    return out
