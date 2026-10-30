import pytest

from avishkar.workers.pyast import scan_python


def rules(src):
    return {(f.rule_id, f.line) for f in scan_python(src, "a.py")}


def ids(src):
    return {r for r, _ in rules(src)}


# ------------------------------------------------------------------ SQL through a variable (same function)
def test_sql_flow_through_variable_is_found_and_marked_low_confidence():
    src = "def q(db, n):\n    sql = f\"SELECT * FROM u WHERE n='{n}'\"\n    db.execute(sql)\n"
    f = scan_python(src, "a.py")
    assert [(x.rule_id, x.line, x.confidence.value) for x in f] == [("PY-SQLI-FLOW", 3, "low")]


@pytest.mark.parametrize("src", [
    "def q(db, n):\n    sql = 'SELECT * FROM u WHERE n = ?'\n    db.execute(sql, (n,))\n",           # constant SQL
    "def q(db, n):\n    db.execute(sql)\n",                                                        # unknown variable
    "def a():\n    sql = f'SELECT {x}'\ndef b(db):\n    db.execute(sql)\n",                         # other function's variable
    "def q(db):\n    sql = 'SELECT ' + 'x'\n    db.execute(sql)\n",                                # constants only
])
def test_sql_flow_not_triggered_for_safe_shapes(src):
    assert ids(src) == set()


# ------------------------------------------------------------------ hard-coded credentials
def test_secret_assignment_forms_are_found_and_redacted():
    src = ('API_KEY = "sk-1234567890abcdef"\nDB = {"password": "Password123!"}\nconnect(user="u", password="hunter2hunter2")\n'
           'self.token = "tok_live_abcdef123456"\ncfg["secret"] = "abcdefgh12345678"\n')
    f = scan_python(src, "a.py")
    assert {x.line for x in f if x.rule_id == "PY-SECRET-ASSIGN"} == {1, 2, 3, 4, 5}
    for x in f:
        assert "1234567890abcdef" not in x.evidence and "hunter2hunter2" not in x.evidence and "Password123!" not in x.evidence
        assert "****" in x.evidence


@pytest.mark.parametrize("src", [
    "PASSWORD_FIELD = 'password'\nTOKEN_URL = 'https://auth.example.com/token'\nSECRET_KEY_NAME = 'my_secret_value_name'\n",
    "API_KEY = os.environ['API_KEY']\npassword = input('Password: ')\ntoken = get_token()\n",
    "password = 'short'\nsecret = ''\n",
    "message = 'Please enter your password to continue with the process'\nhelp_text = 'the api key is required'\n",
    "x = {'password_field': 'abcdefgh123', 'is_secret': 'abcdefghijkl'}\n",
    "login(password=pw)\ncheck(token=token)\n",
])
def test_secret_assignment_ignores_non_credentials(src):
    assert ids(src) == set()


def test_secret_placeholder_is_reported_at_low_confidence():
    f = scan_python("password = 'changeme-placeholder-1234'\n", "a.py")
    assert [(x.rule_id, x.confidence.value) for x in f] == [("PY-SECRET-ASSIGN", "low")]


# ------------------------------------------------------------------ XML, temp files, random
def test_xml_stdlib_parsers_found_defusedxml_not():
    src = ("import xml.etree.ElementTree as ET\nfrom xml.dom import minidom\nimport defusedxml.ElementTree as DET\n"
           "ET.fromstring(s)\nminidom.parseString(s)\nDET.fromstring(s)\n")
    assert rules(src) == {("PY-XML-PARSE", 4), ("PY-XML-PARSE", 5)}


def test_tempfile_rules():
    assert rules("import tempfile\np = tempfile.mktemp()\n") == {("PY-TEMPFILE", 2)}
    assert rules("f = open('/tmp/data.txt', 'w')\n") == {("PY-TEMPPATH", 1)}
    assert rules("import tempfile\nf = tempfile.NamedTemporaryFile()\nopen('/var/data/x.txt')\n") == set()


def test_weak_random_only_in_security_context():
    assert rules("import random\ndef generate_token():\n    return random.randint(1000, 9999)\n") == {("PY-RANDOM", 3)}
    assert rules("import random\nsession_id = random.random()\n") == {("PY-RANDOM", 2)}
    assert rules("import random\ndef pick_color():\n    return random.choice(['r', 'g'])\nx = random.random()\n") == set()
    assert rules("import secrets, random\ndef generate_token():\n    return secrets.token_hex(16)\n") == set()
    assert rules("import numpy.random as random\ndef generate_token():\n    return random.rand()\n") == set()


# ------------------------------------------------------------------ path traversal
def test_path_from_parameter_direct_and_through_variable():
    direct = "def save(data, filename):\n    with open(f'./uploads/{filename}', 'wb') as f:\n        f.write(data)\n"
    flow = "def read(name):\n    p = f'/uploads/{name}'\n    return open(p).read()\n"
    assert rules(direct) == {("PY-PATH", 2)} and rules(flow) == {("PY-PATH", 3)}


@pytest.mark.parametrize("src", [
    "def read(name):\n    base = os.path.realpath('/uploads')\n    p = os.path.realpath(base + '/' + name)\n    return open(p).read()\n",
    "from pathlib import Path\ndef read(name):\n    p = (Path('/up') / name).resolve()\n    return open(p).read()\n",
    "def read():\n    return open('/etc/app.conf').read()\n",
    "def read():\n    name = 'x'\n    return open(f'/up/{name}').read()\n",            # not a parameter
    "def read(path):\n    return open(path).read()\n",                                   # not built by formatting
    "def read(name):\n    safe = os.path.basename(name)\n    return open(f'/up/{safe}').read()\n",
])
def test_path_not_reported_when_normalised_or_not_param_built(src):
    assert ids(src) == set()


# ------------------------------------------------------------------ debug in any case, nested functions, robustness
def test_debug_constant_case_insensitive():
    assert rules("DEBUG = True\n") == {("PY-DEBUG", 1)}
    assert rules("debug = True\nDEBUG = False\nDEBUG = os.environ.get('X') == '1'\n") == {("PY-DEBUG", 1)}


def test_nested_function_scopes_do_not_leak_variables():
    src = ("def outer(db, n):\n    sql = f\"SELECT {n}\"\n    def inner():\n        db.execute(sql)\n    return inner\n")
    assert ids(src) == set()  # `sql` belongs to outer's scope; inner is not tracked (conservative)


def test_subscript_target_subexpressions_are_still_visited():
    assert rules("cfg[eval(key)] = 1\n") == {("PY-EVAL", 1)}


def test_evidence_never_contains_a_literal_secret_for_any_rule():
    src = "import requests\nrequests.get(url, headers={'x': 'ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "'}, verify=False)\n"
    f = scan_python(src, "a.py")
    assert f and all("ghp_a1B2" not in x.evidence for x in f)


# ------------------------------------------------------------------ gap fixes found by the holdout cases
def test_orm_raw_and_sqlalchemy_text_wrappers():
    assert rules("def f(cls, t):\n    return cls.objects.raw(\"SELECT * FROM a WHERE n='%s'\" % t)\n") == {("PY-SQLI", 2)}
    assert rules("from sqlalchemy import text\ndef f(conn, i):\n    return conn.execute(text(f\"SELECT * FROM t WHERE id={i}\"))\n") == {("PY-SQLI", 3)}
    assert rules("from sqlalchemy import text\ndef f(conn, i):\n    return conn.execute(text(\"SELECT * FROM t WHERE id=:i\"), {'i': i})\n") == set()
    assert rules("def f(cls, t):\n    q = f\"SELECT {t}\"\n    return cls.objects.raw(q)\n") == {("PY-SQLI-FLOW", 3)}


def test_path_from_join_and_file_response_sinks():
    assert rules("import os\nfrom flask import send_file\ndef d(filename):\n    return send_file(os.path.join('/srv', filename))\n") == {("PY-PATH", 4)}
    assert rules("from fastapi.responses import FileResponse\ndef g(name):\n    return FileResponse(f'/data/{name}')\n") == {("PY-PATH", 3)}
    assert rules("import os\ndef r(name):\n    p = os.path.join('/srv', name)\n    return open(p).read()\n") == {("PY-PATH", 4)}
    assert rules("import os\ndef r(name):\n    p = os.path.join('/srv', os.path.basename(name))\n    return open(p).read()\n") == set()
    assert rules("import os\ndef r():\n    return open(os.path.join('/srv', 'static.txt')).read()\n") == set()
    assert rules("from flask import send_from_directory\ndef d(filename):\n    return send_from_directory('/srv', filename)\n") == set()


def test_verify_disabled_by_attribute_assignment():
    assert rules("import requests\ns = requests.Session()\ns.verify = False\n") == {("PY-NOVERIFY", 3)}
    assert rules("s.verify = True\ns.verify = '/etc/ca.pem'\n") == set()
