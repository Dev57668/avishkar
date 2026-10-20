"""AST-based Python security patterns. Same rule ids as the regex rules so labels, fingerprints and
policy keep working, but: aliases are resolved (`import subprocess as sp`, `from os import system`),
comments/docstrings/strings never match, and multi-line calls are handled.
"""
from __future__ import annotations

import ast

from ..domain.models import Confidence, Exposure, RawFinding, Severity

SAFE_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
SQL_METHODS = {"execute", "executemany", "executescript"}
RULES = {  # id: (severity, confidence, title, remediation, category)
    "PY-EVAL": (Severity.HIGH, Confidence.MEDIUM, "Dynamic code execution (eval/exec)",
                "Avoid eval/exec; use ast.literal_eval or explicit dispatch.", "injection"),
    "PY-SHELL": (Severity.HIGH, Confidence.MEDIUM, "Shell command execution",
                 "Pass an argument list with shell=False and validate inputs.", "injection"),
    "PY-SQLI": (Severity.HIGH, Confidence.MEDIUM, "SQL built by string formatting", "Use parameterized queries.", "injection"),
    "PY-PICKLE": (Severity.MEDIUM, Confidence.MEDIUM, "Unsafe deserialization (pickle)",
                  "Use a safe format such as JSON for untrusted data.", "deserialization"),
    "PY-YAML": (Severity.MEDIUM, Confidence.MEDIUM, "yaml.load without SafeLoader", "Use yaml.safe_load.", "deserialization"),
    "PY-WEAKHASH": (Severity.LOW, Confidence.MEDIUM, "Weak hash algorithm",
                    "Use SHA-256+ or a password KDF (argon2/bcrypt).", "crypto"),
    "PY-NOVERIFY": (Severity.MEDIUM, Confidence.HIGH, "TLS certificate verification disabled", "Remove verify=False.", "transport"),
    "PY-DEBUG": (Severity.MEDIUM, Confidence.LOW, "Debug mode enabled", "Disable debug in deployed configuration.", "config"),
}


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


def _formatted_sql(arg) -> bool:
    """f-string with interpolation, '...' % x, '...' + x, or '...'.format(x)."""
    if isinstance(arg, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add)):
        return any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in (arg.left, arg.right))
    return (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format"
            and isinstance(arg.func.value, ast.Constant) and isinstance(arg.func.value.value, str))


class _Visitor(ast.NodeVisitor):
    def __init__(self):
        self.alias: dict[str, str] = {}
        self.hits: list[tuple[str, int]] = []

    def visit_Import(self, node):
        for a in node.names:
            self.alias[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.level == 0:
            for a in node.names:
                self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    def resolve(self, func) -> str | None:
        d = _dotted(func)
        if not d:
            return None
        head, _, rest = d.partition(".")
        base = self.alias.get(head, head)
        return f"{base}.{rest}" if rest else base

    def hit(self, rule, node):
        self.hits.append((rule, node.lineno))

    def visit_Assign(self, node):
        if any(isinstance(t, ast.Name) and t.id == "debug" for t in node.targets) and _is_const(node.value, True):
            self.hit("PY-DEBUG", node)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.resolve(node.func) or ""
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            self.hit("PY-EVAL", node)
        if (name.startswith("subprocess.") and _is_const(kws.get("shell"), True)) or name in ("os.system", "os.popen"):
            self.hit("PY-SHELL", node)
        if isinstance(node.func, ast.Attribute) and node.func.attr in SQL_METHODS and node.args and _formatted_sql(node.args[0]):
            self.hit("PY-SQLI", node)
        if name.split(".")[0] in ("pickle", "cPickle", "dill", "_pickle") and name.split(".")[-1] in ("load", "loads"):
            self.hit("PY-PICKLE", node)
        if name == "yaml.load":
            loader = kws.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            lname = (_dotted(loader) or "").split(".")[-1] if loader is not None else ""
            if lname not in SAFE_LOADERS:
                self.hit("PY-YAML", node)
        if name in ("hashlib.md5", "hashlib.sha1"):
            self.hit("PY-WEAKHASH", node)
        if name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) \
                and str(node.args[0].value).lower() in ("md5", "sha1"):
            self.hit("PY-WEAKHASH", node)
        if _is_const(kws.get("verify"), False):
            self.hit("PY-NOVERIFY", node)
        if _is_const(kws.get("debug"), True):
            self.hit("PY-DEBUG", node)
        self.generic_visit(node)


def scan_python(text: str, rel: str) -> list[RawFinding]:
    """Raises SyntaxError for unparsable source; the caller decides on a fallback."""
    tree = ast.parse(text)
    v = _Visitor()
    v.visit(tree)
    lines = text.splitlines()
    out, seen = [], set()
    for rule, ln in sorted(v.hits, key=lambda h: (h[1], h[0])):
        if (rule, ln) in seen:
            continue
        seen.add((rule, ln))
        sev, conf, title, fix, cat = RULES[rule]
        ev = lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else ""
        out.append(RawFinding("code-patterns", rule, cat, sev, conf, title, rel, ln, ev, Exposure.UNKNOWN, fix, "small"))
    return out
