"""AST-based Python security patterns. Aliases are resolved (`import subprocess as sp`, `from os import system`),
comments/docstrings/strings never match, multi-line calls are handled, and a few *same-function* data flows are followed
(a string formatted into a variable and later executed/opened). It never imports or executes the scanned code.

Titles, categories and remediation text come from `avishkar.knowledge` (single source of truth); this module only decides
*where* a rule fires and at what severity/confidence. Confidence values are provisional and equal the previous regex
rules' values where a rule already existed (an AST match is not yet measured to be more precise).
"""
from __future__ import annotations

import ast

from .. import knowledge
from ..domain.models import Confidence, Exposure, RawFinding, Severity
from ..domain.redaction import redact_text
from .shapes import CRED_NAME, CRED_NAME_EXCLUDE, SECURITY_CONTEXT, is_placeholder, looks_like_secret_value

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
SAFE_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw"}  # raw: Django-style ORM escape hatch
PATH_SINKS = {"open", "io.open", "builtins.open", "send_file", "flask.send_file", "FileResponse",
              "fastapi.responses.FileResponse", "starlette.responses.FileResponse"}
RANDOM_FUNCS = {"random", "randint", "choice", "choices", "randrange", "getrandbits", "sample", "uniform", "shuffle"}
NORMALISERS = {"basename", "realpath", "abspath", "resolve", "secure_filename", "normpath", "is_relative_to",
               "commonpath", "safe_join", "relative_to"}
XML_PARSE = {f"xml.etree.ElementTree.{n}" for n in ("fromstring", "parse", "XML", "iterparse")} | {
    "xml.dom.minidom.parseString", "xml.dom.minidom.parse", "xml.sax.parseString", "xml.sax.parse",
    "xml.dom.pulldom.parseString", "xml.dom.pulldom.parse", "lxml.etree.fromstring", "lxml.etree.parse", "lxml.etree.XML"}

# rule -> (severity, confidence)
SEVERITY = {
    "PY-EVAL": (Severity.HIGH, M), "PY-SHELL": (Severity.HIGH, M), "PY-SQLI": (Severity.HIGH, M),
    "PY-SQLI-FLOW": (Severity.HIGH, L), "PY-PICKLE": (Severity.MEDIUM, M), "PY-YAML": (Severity.MEDIUM, M),
    "PY-WEAKHASH": (Severity.LOW, M), "PY-NOVERIFY": (Severity.MEDIUM, H), "PY-DEBUG": (Severity.MEDIUM, L),
    "PY-SECRET-ASSIGN": (Severity.HIGH, M), "PY-XML-PARSE": (Severity.MEDIUM, L), "PY-TEMPFILE": (Severity.MEDIUM, M),
    "PY-TEMPPATH": (Severity.LOW, L), "PY-RANDOM": (Severity.MEDIUM, L), "PY-PATH": (Severity.MEDIUM, L),
}
PY_RULES = tuple(SEVERITY)


def _dotted(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_const(node, value) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def _is_str(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _formatted(arg) -> bool:
    """A string assembled from non-constant parts: f-string with {..}, '..' % x, '..' + x, '..'.format(x)."""
    if isinstance(arg, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add)):
        sides = (arg.left, arg.right)
        return any(_is_str(s) for s in sides) and not all(isinstance(s, ast.Constant) for s in sides)
    return (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format"
            and _is_str(arg.func.value))


def _names_in(node) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _joined(arg) -> bool:
    """os.path.join(...) / Path(...) / Path / part: a path assembled from several pieces."""
    if isinstance(arg, ast.Call):
        d = _dotted(arg.func) or ""
        return d.split(".")[-1] in ("join", "Path", "PurePath", "joinpath")
    return isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Div)


def _sql_text(arg) -> ast.AST | None:
    """sqlalchemy.text(<sql>) -> the inner SQL expression, so f"..." inside text() is seen as the query."""
    if isinstance(arg, ast.Call) and (_dotted(arg.func) or "").split(".")[-1] == "text" and arg.args:
        return arg.args[0]
    return None


def _redact(v: str) -> str:
    return v[:2] + "*" * 6 if len(v) <= 8 else v[:4] + "*" * 6 + v[-2:]


class _Scope:
    __slots__ = ("name", "params", "normalised", "fmt", "built")

    def __init__(self, name=None, params=frozenset(), normalised=False):
        self.name, self.params, self.normalised = name, params, normalised
        self.fmt: set[str] = set()              # variables assigned a formatted string
        self.built: dict[str, set[str]] = {}    # variable -> function parameters used to build it


class _Visitor(ast.NodeVisitor):
    def __init__(self):
        self.alias: dict[str, str] = {}
        self.hits: list[tuple] = []  # (rule, line, confidence|None, evidence|None)
        self.scopes = [_Scope()]
        self.ctx_names: list[str] = []  # names being assigned while visiting a value

    # ---------------------------------------------------------------- helpers
    @property
    def scope(self) -> _Scope:
        return self.scopes[-1]

    def hit(self, rule, node, conf=None, evidence=None):
        self.hits.append((rule, node.lineno, conf, evidence))

    def resolve(self, func) -> str | None:
        d = _dotted(func)
        if not d:
            return None
        head, _, rest = d.partition(".")
        base = self.alias.get(head, head)
        return f"{base}.{rest}" if rest else base

    # ---------------------------------------------------------------- imports & scopes
    def visit_Import(self, node):
        for a in node.names:
            self.alias[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.level == 0:
            for a in node.names:
                self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    def _function(self, node):
        a = node.args
        names = [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
        names += [x.arg for x in (a.vararg, a.kwarg) if x]
        params = frozenset(n for n in names if n not in ("self", "cls"))
        norm = any(isinstance(c, ast.Call) and (_dotted(c.func) or "").split(".")[-1] in NORMALISERS
                   for c in ast.walk(node))
        self.scopes.append(_Scope(node.name, params, norm))
        self.generic_visit(node)
        self.scopes.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = _function

    # ---------------------------------------------------------------- assignments
    def _secret_target(self, name, value_node, node):
        if (name and CRED_NAME.search(name) and not CRED_NAME_EXCLUDE.search(name) and _is_str(value_node)
                and looks_like_secret_value(value_node.value)):
            self.hit("PY-SECRET-ASSIGN", node, L if is_placeholder(value_node.value) else None,
                     f"{name} = {_redact(value_node.value)}")

    @staticmethod
    def _target_names(t) -> list[str]:
        if isinstance(t, ast.Name):
            return [t.id]
        if isinstance(t, ast.Attribute):
            return [t.attr]
        if isinstance(t, ast.Subscript) and _is_str(t.slice):
            return [t.slice.value]
        return []

    def _assign(self, targets, value, node):
        names = [n for t in targets for n in self._target_names(t)]
        for n in names:
            self._secret_target(n, value, node)
            if n.lower() == "debug" and _is_const(value, True):
                self.hit("PY-DEBUG", node)
            if n == "verify" and _is_const(value, False):
                self.hit("PY-NOVERIFY", node)  # session.verify = False
        for t in targets:
            if isinstance(t, ast.Name) and value is not None and _formatted(value):
                self.scope.fmt.add(t.id)
                used = _names_in(value) & self.scope.params
                if used:
                    self.scope.built[t.id] = used
            elif isinstance(t, ast.Name) and value is not None and _joined(value):
                used = _names_in(value) & self.scope.params
                if used:
                    self.scope.built[t.id] = used
        for t in targets:
            if not isinstance(t, ast.Name):
                self.visit(t)  # a[f(x)] = ..., obj.attr = ...: sub-expressions can still contain dangerous calls
        prev = self.ctx_names
        self.ctx_names = names
        if value is not None:
            self.visit(value)
        self.ctx_names = prev

    def visit_Assign(self, node):
        self._assign(node.targets, node.value, node)

    def visit_AnnAssign(self, node):
        self._assign([node.target], node.value, node)

    def visit_Dict(self, node):
        for k, v in zip(node.keys, node.values):
            if k is not None and _is_str(k):
                self._secret_target(k.value, v, k)
        self.generic_visit(node)

    # ---------------------------------------------------------------- calls
    def visit_Call(self, node):
        name = self.resolve(node.func) or ""
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        first = node.args[0] if node.args else None

        if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            self.hit("PY-EVAL", node)
        if (name.startswith("subprocess.") and _is_const(kws.get("shell"), True)) or name in ("os.system", "os.popen"):
            self.hit("PY-SHELL", node)

        if isinstance(node.func, ast.Attribute) and node.func.attr in SQL_METHODS and first is not None:
            inner = _sql_text(first) or first
            if _formatted(inner):
                self.hit("PY-SQLI", node)
            elif isinstance(inner, ast.Name) and inner.id in self.scope.fmt:
                self.hit("PY-SQLI-FLOW", node)

        if name.split(".")[0] in ("pickle", "cPickle", "dill", "_pickle") and name.split(".")[-1] in ("load", "loads"):
            self.hit("PY-PICKLE", node)
        if name == "yaml.load":
            loader = kws.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            lname = (_dotted(loader) or "").split(".")[-1] if loader is not None else ""
            if lname not in SAFE_LOADERS:
                self.hit("PY-YAML", node)
        if name in ("hashlib.md5", "hashlib.sha1"):
            self.hit("PY-WEAKHASH", node)
        if name == "hashlib.new" and first is not None and _is_str(first) and first.value.lower() in ("md5", "sha1"):
            self.hit("PY-WEAKHASH", node)
        if _is_const(kws.get("verify"), False):
            self.hit("PY-NOVERIFY", node)
        if _is_const(kws.get("debug"), True):
            self.hit("PY-DEBUG", node)

        # credentials passed as literal keyword arguments: connect(password="...")
        for k, v in kws.items():
            self._secret_target(k, v, node)

        if name in XML_PARSE:
            self.hit("PY-XML-PARSE", node)
        if name == "tempfile.mktemp":
            self.hit("PY-TEMPFILE", node)
        if name in PATH_SINKS or name.split(".")[-1] == "send_file":
            if first is not None and name in ("open", "io.open", "builtins.open") and _is_str(first) \
                    and first.value.startswith("/tmp/"):
                self.hit("PY-TEMPPATH", node)
            if first is not None:
                self._maybe_path(first, node)
        if (name.startswith("random.") and name.split(".")[-1] in RANDOM_FUNCS
                and name.split(".")[0] == "random"):
            ctx = [self.scope.name or ""] + self.ctx_names
            if any(SECURITY_CONTEXT.search(c) for c in ctx):
                self.hit("PY-RANDOM", node)
        self.generic_visit(node)

    def _maybe_path(self, arg, node):
        """open() of a path built from a function parameter, in a function that never normalises paths."""
        s = self.scope
        if not s.params or s.normalised:
            return
        if (_formatted(arg) or _joined(arg)) and (_names_in(arg) & s.params):
            self.hit("PY-PATH", node)
        elif isinstance(arg, ast.Name) and arg.id in s.built:
            self.hit("PY-PATH", node)


def scan_python(text: str, rel: str) -> list[RawFinding]:
    """Raises SyntaxError for unparsable source; the caller decides on a fallback."""
    tree = ast.parse(text)
    v = _Visitor()
    v.visit(tree)
    lines = text.splitlines()
    out, seen = [], set()
    for rule, ln, conf, ev in sorted(v.hits, key=lambda h: (h[1], h[0])):
        if (rule, ln) in seen:
            continue
        seen.add((rule, ln))
        sev, dconf = SEVERITY[rule]
        k = knowledge.RULES[rule]
        evidence = ev if ev is not None else redact_text(lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else "")
        out.append(RawFinding("code-patterns", rule, k["category"], sev, conf or dconf, k["name"], rel, ln, evidence,
                              Exposure.UNKNOWN, k["remediation"], "small"))
    return out
