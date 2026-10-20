from pathlib import Path

import pytest

from avishkar.workers.detectors import detect_patterns
from avishkar.workers.pyast import scan_python


def rules(src):
    return {(f.rule_id, f.line) for f in scan_python(src, "a.py")}


def test_alias_resolution_catches_what_regex_cannot():
    src = ("import subprocess as sp\nfrom os import system as run\nimport hashlib as h\n"
           "sp.run(c, shell=True)\nrun(cmd)\nh.md5(b'x')\n")
    assert rules(src) == {("PY-SHELL", 4), ("PY-SHELL", 5), ("PY-WEAKHASH", 6)}


def test_strings_comments_and_docstrings_never_match():
    src = '"""eval(x) and verify=False in docs"""\n# os.system("rm")\nmsg = "subprocess.run(c, shell=True)"\nrx = r"verify\\s*=\\s*False"\n'
    assert rules(src) == set()


def test_multiline_call_and_nested():
    src = "import subprocess\nsubprocess.run(\n    cmd,\n    shell=True,\n)\n"
    assert rules(src) == {("PY-SHELL", 2)}


def test_safe_variants_are_clean():
    src = ("import subprocess, yaml, hashlib, json\nsubprocess.run(['ls'], shell=False)\nyaml.safe_load(s)\n"
           "yaml.load(s, Loader=yaml.SafeLoader)\nhashlib.sha256(b'x')\njson.loads(b)\ndb.execute('SELECT ?', (x,))\n"
           "requests.get(u, verify=True)\n")
    assert rules(src) == set()


def test_sql_formatting_forms():
    src = ('db.execute(f"SELECT {x}")\ndb.execute("SELECT %s" % x)\ndb.execute("SELECT " + x)\n'
           'db.execute("SELECT {}".format(x))\ndb.execute(f"SELECT 1")\ndb.execute("SELECT 1")\ndb.execute(q, (a,))\n')
    assert {ln for r, ln in rules(src) if r == "PY-SQLI"} == {1, 2, 3, 4}


def test_yaml_pickle_eval_debug_noverify():
    src = ("import yaml, pickle\nyaml.load(s)\nyaml.load(s, Loader=yaml.Loader)\npickle.loads(b)\neval(x)\nexec(y)\n"
           "app.run(debug=True)\nrequests.post(u, verify=False)\n")
    assert rules(src) == {("PY-YAML", 2), ("PY-YAML", 3), ("PY-PICKLE", 4), ("PY-EVAL", 5), ("PY-EVAL", 6),
                          ("PY-DEBUG", 7), ("PY-NOVERIFY", 8)}


def test_evidence_is_the_source_line():
    f = scan_python("x = 1\ny = eval(s)\n", "a.py")[0]
    assert f.evidence == "y = eval(s)" and f.path == "a.py" and f.detector_id == "code-patterns"


def test_unparsable_python_falls_back_to_regex(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n    x = eval(s)\n")
    found = detect_patterns(tmp_path, [tmp_path / "bad.py"])
    assert {f.rule_id for f in found} == {"PY-EVAL"}  # still covered, not silently skipped


def test_syntaxerror_raised_by_scan_python():
    with pytest.raises(SyntaxError):
        scan_python("def (:", "a.py")


def test_self_scan_has_no_false_positives_on_rule_definitions():
    root = Path(__file__).resolve().parents[2] / "avishkar" / "workers"
    files = [p for p in root.glob("*.py")]
    assert [f for f in detect_patterns(root, files) if f.rule_id == "PY-NOVERIFY"] == []
