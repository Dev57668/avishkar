"""Bundled educational samples and their *fix packs* for the live demo.

A fix is a real source edit (exact string replacement) applied to a COPY of a bundled sample; the demo then runs the real
scan pipeline on that copy. Nothing here fabricates scan output: results always come from scanning the edited files.
Every fix is verified by tests to remove the finding it targets without introducing new ones.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "sample_projects"


@dataclass(frozen=True)
class Fix:
    id: str
    title: str
    file: str
    removes: tuple[str, ...]                    # rule ids this fix is meant to remove (verified by tests)
    explanation: str
    edits: tuple[tuple[str, str], ...] = ()     # exact (old, new) replacements; each `old` must occur exactly once
    imports: tuple[str, ...] = ()               # import lines to ensure exist (after the leading imports)


@dataclass(frozen=True)
class Sample:
    id: str
    name: str
    language: str
    kind: str                                   # vulnerable | secure | unsupported
    folder: str
    description: str
    expected: str
    fixes: tuple[Fix, ...] = field(default_factory=tuple)


def _ensure_import(text: str, line: str, js: bool = False) -> str:
    if re.search(rf"(?m)^{re.escape(line)}\s*$", text):
        return text
    lines = text.split("\n")
    last = -1
    for i, l in enumerate(lines):
        if (not js and l.startswith(("import ", "from "))) or (js and re.match(r"(const|let|var)\s+.*=\s*require\(", l)):
            last = i
    lines.insert(last + 1, line)
    return "\n".join(lines)


PY = Fix
PY_FIXES = (
    PY("py-secrets-app", "Load app secrets from the environment", "app.py", ("PY-SECRET-ASSIGN",),
       "Hard-coded API key, database password and JWT secret are replaced by environment variables so the values never "
       "live in the repository (rotate the old ones: they are already exposed).",
       (('API_KEY = "sk-1234567890abcdef"\nDATABASE_PASSWORD = "admin123"\nJWT_SECRET = "super_secret_key_do_not_share"',
         'API_KEY = os.environ["API_KEY"]\nDATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]\nJWT_SECRET = os.environ["JWT_SECRET"]'),)),
    PY("py-sqli-login", "Parameterize the login query", "app.py", ("PY-SQLI-FLOW",),
       "User input is passed to the database as bound parameters instead of being formatted into the SQL text.",
       (("    # SQL Injection: User input directly concatenated into query\n"
         "    query = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\n    cursor.execute(query)",
         "    # Parameterized query: user input is data, never SQL\n"
         "    cursor.execute(\"SELECT * FROM users WHERE username=? AND password=?\", (username, password))"),)),
    PY("py-cmd-ping", "Run ping without a shell", "app.py", ("PY-SHELL",),
       "The command is an argument list, so shell metacharacters in the host value cannot start another command.",
       (('    result = os.system(f"ping {host}")', '    result = subprocess.run(["ping", "-c", "1", host], check=False).returncode'),),
       ("import subprocess",)),
    PY("py-hash-password", "Use salted key derivation instead of MD5", "app.py", ("PY-WEAKHASH",),
       "PBKDF2-HMAC-SHA256 with a random salt and a high iteration count replaces unsalted MD5.",
       (("    # Weak Crypto: MD5 is cryptographically broken\n    return hashlib.md5(password.encode()).hexdigest()",
         "    salt = os.urandom(16)\n    digest = hashlib.pbkdf2_hmac(\"sha256\", password.encode(), salt, 600_000)\n"
         "    return salt.hex() + \":\" + digest.hex()"),)),
    PY("py-path-read", "Confine file reads to the uploads directory", "app.py", ("PY-PATH",),
       "The final path is resolved and must stay under the base directory, which blocks ../ traversal.",
       (("    filepath = f\"/uploads/{filename}\"\n    with open(filepath, 'r') as f:\n        return f.read()",
         "    base = os.path.realpath(\"/uploads\")\n    filepath = os.path.realpath(os.path.join(base, filename))\n"
         "    if not filepath.startswith(base + os.sep):\n        raise ValueError(\"invalid path\")\n"
         "    with open(filepath, 'r') as f:\n        return f.read()"),)),
    PY("py-eval-calc", "Evaluate literals only", "app.py", ("PY-EVAL",),
       "ast.literal_eval accepts only Python literals, so an expression cannot call functions or import modules.",
       (("    return eval(expression)", "    return ast.literal_eval(expression)"),), ("import ast",)),
    PY("py-pickle-load", "Parse JSON instead of unpickling", "app.py", ("PY-PICKLE",),
       "A data-only format cannot execute code while loading.",
       (("    return pickle.loads(data)", "    return json.loads(data)"),), ("import json",)),
    PY("py-debug-off", "Turn debug mode off and bind to localhost", "app.py", ("PY-DEBUG",),
       "Debug mode exposes an interactive console; the server also stops listening on every interface.",
       (("    app.run(debug=True, host='0.0.0.0', port=5000)", "    app.run(debug=False, host='127.0.0.1', port=5000)"),)),
    PY("py-secrets-config", "Load credentials in config.py from the environment", "config.py", ("PY-SECRET-ASSIGN", "SEC-GH-TOKEN"),
       "Database password, cloud keys, GitHub token and the app secret are read from the environment.",
       (("    'password': 'Password123!',  # Hardcoded password", "    'password': os.environ['DB_PASSWORD'],"),
        ("AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nAWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
         "AWS_ACCESS_KEY = os.environ['AWS_ACCESS_KEY']\nAWS_SECRET_KEY = os.environ['AWS_SECRET_KEY']"),
        ("GITHUB_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'", "GITHUB_TOKEN = os.environ['GITHUB_TOKEN']"),
        ("DEBUG = True\nSECRET_KEY = 'dev-secret-key-not-for-production'",
         "DEBUG = os.environ.get('APP_DEBUG') == '1'\nSECRET_KEY = os.environ['SECRET_KEY']"))),
    PY("py-hash-sha256", "Use SHA-256 for the fingerprint", "config.py", ("PY-WEAKHASH",),
       "SHA-1 is collision-prone; SHA-256 is appropriate for non-password integrity hashes.",
       (("    return hashlib.sha1(data.encode()).hexdigest()", "    return hashlib.sha256(data.encode()).hexdigest()"),)),
    PY("py-token-secrets", "Generate tokens with the secrets module", "config.py", ("PY-RANDOM",),
       "secrets.token_urlsafe draws from the operating system's CSPRNG; random.randint is predictable.",
       (("    return random.randint(1000, 9999)", "    return secrets.token_urlsafe(32)"),), ("import secrets",)),
    PY("py-tls-verify", "Keep TLS verification on", "config.py", ("PY-NOVERIFY",),
       "Certificates are validated again, and a timeout stops a hung server from blocking the request.",
       (("    response = requests.get(url, verify=False)", "    response = requests.get(url, timeout=10)"),)),
    PY("py-cmd-convert", "Call convert without a shell", "utils.py", ("PY-SHELL",),
       "Arguments are passed as a list; file names can no longer inject shell commands.",
       (("    cmd = f\"convert {input_file} {output_file}\"\n    subprocess.call(cmd, shell=True)  # shell=True with user input is dangerous",
         "    subprocess.call([\"convert\", input_file, output_file])"),)),
    PY("py-path-user-file", "Confine per-user file reads", "utils.py", ("PY-PATH",),
       "Both the user directory and the file are resolved, and the result must stay inside the user's directory.",
       (("    filepath = f\"/home/{username}/{filename}\"\n    with open(filepath, 'r') as f:\n        return f.read()",
         "    base = os.path.realpath(os.path.join(\"/home\", os.path.basename(username)))\n"
         "    filepath = os.path.realpath(os.path.join(base, filename))\n    if not filepath.startswith(base + os.sep):\n"
         "        raise ValueError(\"invalid path\")\n    with open(filepath, 'r') as f:\n        return f.read()"),)),
    PY("py-xml-defused", "Parse XML with defusedxml", "utils.py", ("PY-XML-PARSE",),
       "defusedxml blocks entity-expansion and external-entity attacks that the standard-library parser allows.",
       (("import xml.etree.ElementTree as ET", "from defusedxml import ElementTree as ET"),)),
    PY("py-sqli-search", "Parameterize the user search", "utils.py", ("PY-SQLI-FLOW",),
       "The LIKE pattern is bound as a parameter instead of being formatted into the query text.",
       (("    query = f\"SELECT * FROM users WHERE name LIKE '%{search_term}%'\"\n    cursor.execute(query)",
         "    cursor.execute(\"SELECT * FROM users WHERE name LIKE ?\", (f\"%{search_term}%\",))"),)),
    PY("py-upload-name", "Strip directories from uploaded file names", "utils.py", ("PY-PATH",),
       "os.path.basename removes any ../ components, so uploads land only in the uploads directory.",
       (("    with open(f\"./uploads/{filename}\", 'wb') as f:",
         "    safe_name = os.path.basename(filename)\n    with open(os.path.join(\"./uploads\", safe_name), 'wb') as f:"),)),
    PY("py-temp-file", "Create temporary files atomically", "utils.py", (),
       "NamedTemporaryFile picks an unpredictable name and sets private permissions, unlike a fixed /tmp path. "
       "Second Read does not currently flag this pattern (the path sits in a variable), so the score will not move: the "
       "fix is correct even though the scanner cannot see the problem.",
       (("    temp_path = \"/tmp/data.txt\"\n    with open(temp_path, 'w') as f:\n        f.write(data)\n    return temp_path",
         "    with tempfile.NamedTemporaryFile('w', delete=False) as f:\n        f.write(data)\n        return f.name"),)),
)

JS = Fix
JS_FIXES = (
    JS("js-secrets", "Read secrets from process.env", "app.js", ("JS-SECRET-ASSIGN",),
       "Credentials come from the environment instead of source code (rotate the exposed values).",
       (("const API_KEY = 'sk-test-1234567890abcdef';\nconst DATABASE_PASSWORD = 'admin123';",
         "const API_KEY = process.env.API_KEY;\nconst DATABASE_PASSWORD = process.env.DATABASE_PASSWORD;"),
        ("const JWT_SECRET = 'secret123';", "const JWT_SECRET = process.env.JWT_SECRET;"),
        ("    console.log(`API Key: ${API_KEY}`);  // Logging sensitive data", "    console.log('API key loaded from the environment');"))),
    JS("js-sqli-login", "Use bound parameters in the login query", "app.js", ("JS-SQLI",),
       "The query text is constant and the values are passed separately to the driver.",
       (("    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;",
         "    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';"),
        ("        db.get(query, (err, row) => {", "        db.get(query, [username, password], (err, row) => {"))),
    JS("js-cmd-ping", "Use execFile instead of exec", "app.js", ("JS-CMDI",),
       "execFile runs the program directly with an argument array, without a shell.",
       (("const { exec } = require('child_process');", "const { execFile } = require('child_process');"),
        ("    exec(`ping ${host}`, (error, stdout, stderr) => {", "    execFile('ping', ['-c', '1', host], (error, stdout, stderr) => {"))),
    JS("js-eval-calc", "Parse JSON instead of eval", "app.js", ("JS-EVAL",),
       "JSON.parse reads data and cannot execute code.",
       (("    return eval(expression);", "    return JSON.parse(expression);"),)),
    JS("js-hash-password", "Hash passwords with scrypt and a salt", "app.js", ("JS-WEAKHASH",),
       "scrypt with a random salt is a slow, memory-hard password hash; MD5 is neither.",
       (("    return crypto.createHash('md5').update(password).digest('hex');",
         "    const salt = crypto.randomBytes(16);\n    return salt.toString('hex') + ':' + crypto.scryptSync(password, salt, 64).toString('hex');"),)),
    JS("js-path-read", "Confine file reads to the uploads directory", "app.js", ("JS-PATH",),
       "The path is resolved and must stay inside the base directory.",
       (("const fs = require('fs');", "const fs = require('fs');\nconst path = require('path');"),
        ("    const filepath = `./uploads/${filename}`;\n    return fs.readFileSync(filepath, 'utf8');",
         "    const base = path.resolve('./uploads');\n    const filepath = path.resolve(base, filename);\n"
         "    if (!filepath.startsWith(base + path.sep)) throw new Error('invalid path');\n    return fs.readFileSync(filepath, 'utf8');"))),
    JS("js-xss-search", "Escape the search term in the HTML response", "app.js", ("JS-XSS-REFLECT",),
       "User input is HTML-escaped before it is placed in the page.",
       (("const app = express();", "const app = express();\nconst escapeHtml = (s) => String(s).replace(/[&<>\"']/g, (c) => '&#' + c.charCodeAt(0) + ';');"),
        ("    res.send(`<h1>Search results for: ${query}</h1>`);", "    res.send(`<h1>Search results for: ${escapeHtml(query)}</h1>`);"))),
)

SAMPLES: dict[str, Sample] = {s.id: s for s in (
    Sample("vulnerable-python", "Vulnerable Python app", "Python", "vulnerable", "vulnerable-python",
           "A small Flask app with injection, secrets, weak crypto and unsafe file handling. Intentionally insecure, for education.",
           "Many findings across critical, high and medium severities; a high index.", tuple(PY_FIXES)),
    Sample("vulnerable-javascript", "Vulnerable Node.js app", "JavaScript", "vulnerable", "vulnerable-javascript",
           "An Express app with command injection, eval, SQL built from templates, weak hashing, path traversal and reflected XSS.",
           "Findings from the JavaScript token scanner.", tuple(JS_FIXES)),
    Sample("secure-python", "Secure Python app", "Python", "secure", "secure-python",
           "The same features written with safe patterns. Expected: no findings. That is not proof of security.",
           "No findings, complete analysis, index 0."),
)}


class SampleError(ValueError):
    pass


def _discover() -> None:
    """Add every `sample_projects/<id>/sample.json` folder to SAMPLES, so a new demo sample needs no code change.

    Manifest: {"name","language","kind": vulnerable|secure|unsupported,"description","expected",
               "fixes":[{"id","title","file","explanation","removes":[rule ids],"edits":[[old,new],...]}]}
    Built-in samples above take precedence. A malformed manifest is skipped (never half-loaded); the tests load every one.
    """
    import json

    for mf in sorted(SAMPLES_DIR.glob("*/sample.json")):
        sid = mf.parent.name
        if sid in SAMPLES or not re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,40}", sid):
            continue
        try:
            m = json.loads(mf.read_text(encoding="utf8"))
            fixes = tuple(Fix(f["id"], f["title"], f["file"], tuple(f.get("removes", ())), f["explanation"],
                              tuple((e[0], e[1]) for e in f.get("edits", ())), tuple(f.get("imports", ())))
                          for f in m.get("fixes", ()))
            if m["kind"] not in ("vulnerable", "secure", "unsupported") or len({f.id for f in fixes}) != len(fixes):
                continue
            if any(not re.fullmatch(r"[a-z0-9\-]{1,60}", f.id) for f in fixes):
                continue
            SAMPLES[sid] = Sample(sid, m["name"], m["language"], m["kind"], sid, m["description"], m["expected"], fixes)
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            continue


def _read(sample: Sample) -> dict[str, str]:
    root = SAMPLES_DIR / sample.folder
    if not root.is_dir():
        raise SampleError(f"sample folder missing: {sample.folder}")
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in (".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".md", ".json", ".txt", ".yml", ".yaml") and p.name != "sample.json" and "__pycache__" not in p.parts:
            out[p.relative_to(root).as_posix()] = p.read_text(encoding="utf8", errors="replace")
    return out


def variant_files(sample_id: str, fix_ids: list[str] | tuple[str, ...] = ()) -> dict[str, str]:
    """The sample's files after applying the chosen fixes in catalogue order. Unknown or duplicate ids are rejected."""
    sample = SAMPLES.get(sample_id)
    if not sample:
        raise SampleError(f"unknown sample {sample_id!r}")
    chosen = list(dict.fromkeys(fix_ids))
    known = {f.id: f for f in sample.fixes}
    for fid in chosen:
        if fid not in known:
            raise SampleError(f"unknown fix {fid!r} for {sample_id}")
    files = _read(sample)
    for fix in sample.fixes:  # catalogue order, so results do not depend on the order the client sent
        if fix.id not in chosen:
            continue
        if fix.file not in files:
            raise SampleError(f"fix {fix.id}: file {fix.file} missing")
        text = files[fix.file]
        for old, new in fix.edits:
            if text.count(old) != 1:
                raise SampleError(f"fix {fix.id}: expected exactly one match for edit, found {text.count(old)}")
            text = text.replace(old, new)
        for line in fix.imports:
            text = _ensure_import(text, line, js=sample.language in ("JavaScript", "TypeScript"))
        files[fix.file] = text
    return files


def fix_diff(sample_id: str, fix_id: str) -> str:
    """Unified diff of one fix against the pristine sample (for display)."""
    sample = SAMPLES[sample_id]
    fix = next(f for f in sample.fixes if f.id == fix_id)
    before = variant_files(sample_id)[fix.file].splitlines(keepends=True)
    after = variant_files(sample_id, [fix_id])[fix.file].splitlines(keepends=True)
    return "".join(difflib.unified_diff(before, after, f"a/{fix.file}", f"b/{fix.file}", n=1))


def describe(sample: Sample) -> dict:
    files = _read(sample) if (SAMPLES_DIR / sample.folder).is_dir() else {}
    return {"id": sample.id, "name": sample.name, "language": sample.language, "kind": sample.kind,
            "description": sample.description, "expected": sample.expected,
            "files": [{"path": p, "lines": t.count("\n") + 1} for p, t in files.items() if not p.endswith(".md")],
            "fixes": [{"id": f.id, "title": f.title, "file": f.file, "removes": list(f.removes), "explanation": f.explanation}
                      for f in sample.fixes]}


def write_variant(sample_id: str, fix_ids, dest: Path) -> None:
    for rel, text in variant_files(sample_id, fix_ids).items():
        if rel.endswith(".md"):
            continue
        t = dest / rel
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_text(text, encoding="utf8", newline="\n")


_discover()
