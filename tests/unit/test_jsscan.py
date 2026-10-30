import pytest

from avishkar.workers.jsscan import scan_js, tokenize


def hits(src, name="a.js"):
    return {(f.rule_id, f.line) for f in scan_js(src, name)}


def rules(src, name="a.js"):
    return {r for r, _ in hits(src, name)}


# ------------------------------------------------------------------ lexer
def test_comments_strings_and_regex_never_match():
    src = ("// eval(x); child_process.exec(`ls ${a}`)\n/* el.innerHTML = a */\n"
           "const s = 'eval(x) and rejectUnauthorized: false';\nconst re = /eval\\(x\\)/g;\nconst t = `plain text eval(x)`;\n")
    assert hits(src) == set()


def test_line_numbers_survive_multiline_templates_comments_and_unterminated_strings():
    src = "/* a\nb */\nconst t = `x\ny\nz`;\nconst bad = 'oops\neval(q);\n"
    assert hits(src) == {("JS-EVAL", 7)}


def test_division_vs_regex_context():
    toks = tokenize("const a = b / c / d; const r = /x\\/y/.test(s); const e = a /= 2;")
    kinds = [t.kind for t in toks]
    assert kinds.count("regex") == 1


def test_template_literal_with_nested_template_and_braces():
    src = "const q = `a ${ fn({k: `in ${y}`}) } b`;\neval(z);\n"
    assert hits(src) == {("JS-EVAL", 2)}


# ------------------------------------------------------------------ eval / command injection
def test_eval_forms_and_non_global_eval():
    assert hits("eval(x);\n") == {("JS-EVAL", 1)}
    assert hits("window.eval(x);\n") == {("JS-EVAL", 1)}
    assert hits("const f = new Function('a', body);\n") == {("JS-EVAL", 1)}
    assert hits("setTimeout('doIt()', 10);\n") == {("JS-EVAL", 1)}
    assert hits("model.eval();\nnet.eval(x);\n") == set()                      # PyTorch-style method, not the global
    assert hits("setTimeout(() => run(), 10);\nnew Function('return 1');\n") == set()  # function arg / constant body


@pytest.mark.parametrize("src,expect", [
    ("const cp = require('child_process');\ncp.exec(`ping ${host}`);\n", True),
    ("const { exec } = require('child_process');\nexec('ls ' + dir);\n", True),
    ("import { execSync as run } from 'child_process';\nrun(cmd);\n", True),
    ("import * as cp from 'node:child_process';\ncp.execSync(command);\n", True),
    ("const { exec } = require('child_process');\nexec('ls -la');\n", False),                    # constant command
    ("const { execFile } = require('child_process');\nexecFile('ping', [host]);\n", False),        # no shell
    ("const exec = (x) => x;\nexec(`a ${b}`);\n", False),                                         # not child_process
])
def test_command_injection_alias_resolution(src, expect):
    assert ("JS-CMDI" in rules(src)) is expect


# ------------------------------------------------------------------ XSS
def test_html_sinks():
    assert rules("el.innerHTML = location.hash;\n") == {"JS-INNERHTML"}
    assert rules("el.outerHTML = `<b>${x}</b>`;\n") == {"JS-INNERHTML"}
    assert rules("el.insertAdjacentHTML('beforeend', html);\n") == {"JS-INNERHTML"}
    assert rules("document.write(userHtml);\n") == {"JS-INNERHTML"}
    assert rules("<div dangerouslySetInnerHTML={{__html: x}} />;\n", "a.jsx") == {"JS-INNERHTML"}
    assert rules("el.innerHTML = '<b>static</b>';\nel.textContent = x;\nel.innerHTML = `<i>plain</i>`;\n") == set()


def test_reflected_xss_heuristic_needs_html_template_with_interpolation():
    assert rules("res.send(`<h1>Hi ${q}</h1>`);\n") == {"JS-XSS-REFLECT"}
    assert rules("res.send(`Hi ${q}`);\nres.send('<h1>x</h1>');\nres.json({a: 1});\n") == set()


# ------------------------------------------------------------------ TLS, weak crypto, random
def test_tls_and_weak_hash_and_random():
    assert rules("const a = new https.Agent({ rejectUnauthorized: false });\n") == {"JS-TLS"}
    assert rules("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n") == {"JS-TLS"}
    assert rules("const a = { rejectUnauthorized: true };\n") == set()
    assert rules("const crypto = require('crypto');\ncrypto.createHash('md5').update(p);\n") == {"JS-WEAKHASH"}
    assert rules("const crypto = require('crypto');\ncrypto.createHash('sha256').update(p);\n") == set()
    assert rules("function makeToken() {\n  return Math.random().toString(36);\n}\n") == {"JS-RANDOM"}
    assert rules("const sessionId = Math.random();\n") == {"JS-RANDOM"}
    assert rules("function shuffle() {\n  return Math.random() - 0.5;\n}\nconst jitter = Math.random() * 100;\n") == set()
    assert rules("const makeToken = () => {\n  return Math.random();\n};\n") == {"JS-RANDOM"}


# ------------------------------------------------------------------ SQL
@pytest.mark.parametrize("src,expect", [
    ("db.get(`SELECT * FROM u WHERE n='${name}'`, cb);\n", True),
    ("db.query(\"SELECT * FROM u WHERE id=\" + id);\n", True),
    ("const q = `SELECT * FROM u WHERE n='${n}'`;\ndb.get(q, cb);\n", True),                  # flow through a variable
    ("db.get('SELECT * FROM u WHERE n = ?', [n], cb);\n", False),
    ("cache.get(`user:${id}`);\nmap.get(key);\n", False),                                     # not SQL
    ("const q = 'SELECT 1';\ndb.get(q, cb);\n", False),
])
def test_sql_injection(src, expect):
    assert ("JS-SQLI" in rules(src)) is expect


def test_sql_flow_has_lower_confidence_than_direct():
    direct = scan_js("db.get(`SELECT * FROM u WHERE n='${n}'`);\n", "a.js")[0]
    flow = scan_js("const q = `SELECT * FROM u WHERE n='${n}'`;\ndb.get(q);\n", "a.js")[0]
    assert direct.confidence.value == "medium" and flow.confidence.value == "low"


# ------------------------------------------------------------------ path traversal
def test_path_traversal_requires_dynamic_path_and_no_normalisation():
    assert rules("const fs = require('fs');\nfs.readFileSync(`./up/${name}`);\n") == {"JS-PATH"}
    assert rules("const fs = require('fs');\nconst p = `./up/${name}`;\nfs.readFileSync(p, 'utf8');\n") == {"JS-PATH"}
    assert rules("const { readFile } = require('fs');\nreadFile('./up/' + name, cb);\n") == {"JS-PATH"}
    assert rules("const fs = require('fs');\nfs.readFileSync('./config.json');\n") == set()
    safe = "const fs = require('fs');\nconst path = require('path');\nconst p = path.resolve(BASE, name);\nfs.readFileSync(`${p}`);\n"
    assert rules(safe) == set()
    promise = "const fs = require('fs');\nnew Promise((resolve) => resolve(1));\nfs.readFileSync(`./up/${n}`);\n"
    assert rules(promise) == {"JS-PATH"}  # a bare resolve() callback is not path hygiene


# ------------------------------------------------------------------ secrets
def test_secret_assignment_redacts_and_skips_placeholders_and_non_secrets():
    f = scan_js("const API_KEY = 'zx9Q-7sd82hKd02jf';\n", "a.js")
    assert [x.rule_id for x in f] == ["JS-SECRET-ASSIGN"] and "zx9Q-7sd82hKd02jf" not in f[0].evidence
    assert f[0].confidence.value == "medium"
    p = scan_js("const API_KEY = 'your_api_key_here_please';\n", "a.js")[0]
    assert p.confidence.value == "low"
    assert rules("const cfg = { password: 'S3cure-Pass-99' };\n") == {"JS-SECRET-ASSIGN"}
    assert rules("obj.apiKey = 'abcd1234efgh5678';\n") == {"JS-SECRET-ASSIGN"}
    assert rules("const PASSWORD_FIELD = 'password';\nconst TOKEN_URL = 'https://x.io/token';\nconst key = process.env.KEY;\n") == set()
    assert rules("const secret = 'abcdefghij' + suffix;\n") == set()   # part of a larger expression
    assert rules("const password = 'short';\n") == set()               # too short to be meaningful


def test_typescript_syntax_does_not_break_scanning():
    src = ("import { exec } from 'child_process';\ninterface A<T> { x: T }\n"
           "export async function run<T>(cmd: string): Promise<T> {\n  exec(`ls ${cmd}`);\n  return eval(cmd) as T;\n}\n")
    assert hits(src, "a.ts") == {("JS-CMDI", 4), ("JS-EVAL", 5)}


def test_hits_are_deduplicated_per_rule_and_line():
    assert len(scan_js("eval(a); eval(b);\n", "a.js")) == 1


def test_oversized_or_odd_input_does_not_crash():
    assert scan_js("", "a.js") == []
    assert scan_js("`unterminated ${ x", "a.js") == []
    assert scan_js("}{)(][ ;;; ??? ::: eval", "a.js") == []
    scan_js("a" * 5000 + "(" * 3000, "a.js")


# ------------------------------------------------------------------ gap fixes found by the holdout cases
def test_vm_code_execution_and_prisma_unsafe_raw():
    assert rules("const vm = require('vm');\nvm.runInNewContext(userCode);\n") == {"JS-EVAL"}
    assert rules("const vm = require('vm');\nvm.runInNewContext('1+1');\n") == set()
    assert rules("prisma.$queryRawUnsafe(`SELECT * FROM u WHERE n = '${n}'`);\n") == {"JS-SQLI"}
    assert rules("prisma.$queryRaw`SELECT * FROM u WHERE n = ${n}`;\n") == set()  # tagged template is parameterised by Prisma


def test_reflected_xss_not_reported_when_every_value_is_escaped():
    assert rules("res.send(`<h1>${escapeHtml(q)}</h1>`);\n") == set()
    assert rules("res.send(`<h1>${DOMPurify.sanitize(q)} ${he.encode(r)}</h1>`);\n") == set()
    assert rules("res.send(`<h1>${escapeHtml(q)} ${raw}</h1>`);\n") == {"JS-XSS-REFLECT"}   # one unescaped value remains
