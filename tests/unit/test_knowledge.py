import ast
import re

from avishkar import knowledge
from avishkar.workers import csscan, cscan, detectors, goscan, javascan, jsscan, phpscan, pyast, rubyscan, rustscan


def emitted_rule_ids() -> set[str]:
    ids = {r[0] for r in detectors.PATTERN_RULES} | {r[0] for r in detectors.SECRET_RULES}
    ids |= set(pyast.PY_RULES) | set(jsscan.JS_RULES) | set(javascan.JAVA_RULES) | set(goscan.GO_RULES) | set(csscan.CS_RULES) | set(phpscan.PHP_RULES)
    ids |= set(rubyscan.RUBY_RULES) | set(cscan.C_RULES) | set(rustscan.RUST_RULES)
    ids |= {row[1] for rows in detectors.ADVISORIES.values() for row in rows} | {"DEP-UNPINNED", "DEP-NOLOCK", "DEP-VULN"}
    return ids


def test_every_emitted_rule_has_curated_knowledge_and_nothing_is_orphaned():
    emitted = emitted_rule_ids()
    assert emitted - set(knowledge.RULES) == set(), "rules with no knowledge-base entry"
    assert set(knowledge.RULES) - emitted == set(), "knowledge-base entries no detector emits"


def test_entries_are_complete_and_well_formed():
    for rid, k in knowledge.RULES.items():
        assert k["name"] and len(k["why"]) > 30 and len(k["impact"]) > 15 and len(k["remediation"]) > 10, rid
        assert k["cwe"] and all(isinstance(c, int) and c in knowledge.CWE_NAMES for c in k["cwe"]), rid
        assert k["detection"]["method"] in ("ast", "tokens", "regex", "manifest", "external"), rid
        assert k["detection"]["assurance"] in ("structural", "heuristic", "database"), rid
        assert k["secureExample"]["code"].strip() and k["secureExample"]["language"], rid


def test_python_secure_examples_are_valid_python():
    for rid, k in knowledge.RULES.items():
        if k["secureExample"]["language"] == "python":
            ast.parse(k["secureExample"]["code"])  # a secure example that does not parse would be embarrassing


def test_secure_examples_do_not_trigger_their_own_rule():
    """The advice must not be flagged by the scanner that gave it (checked for the languages we scan)."""
    for rid, k in knowledge.RULES.items():
        ex = k["secureExample"]
        if ex["language"] == "python" and rid.startswith("PY-"):
            assert rid not in {f.rule_id for f in pyast.scan_python(ex["code"], "x.py")}, rid
        if ex["language"] == "javascript" and rid.startswith("JS-"):
            assert rid not in {f.rule_id for f in jsscan.scan_js(ex["code"], "x.js")}, rid
        if ex["language"] == "csharp" and rid.startswith("CS-"):
            assert rid not in {f.rule_id for f in csscan.scan_csharp(ex["code"], "X.cs")}, rid
        if ex["language"] == "php" and rid.startswith("PHP-"):
            assert rid not in {f.rule_id for f in phpscan.scan_php(ex["code"], "x.php")}, rid
        if ex["language"] == "go" and rid.startswith("GO-"):
            assert rid not in {f.rule_id for f in goscan.scan_go(ex["code"], "x.go")}, rid
        if ex["language"] == "java" and rid.startswith("JAVA-"):
            assert rid not in {f.rule_id for f in javascan.scan_java(ex["code"], "X.java")}, rid
        if ex["language"] == "ruby" and rid.startswith("RB-"):
            assert rid not in {f.rule_id for f in rubyscan.scan_ruby(ex["code"], "x.rb")}, rid
        if ex["language"] == "c" and rid.startswith("C-"):
            assert rid not in {f.rule_id for f in cscan.scan_c(ex["code"], "x.c")}, rid
        if ex["language"] == "rust" and rid.startswith("RS-"):
            assert rid not in {f.rule_id for f in rustscan.scan_rust(ex["code"], "x.rs")}, rid


def test_describe_returns_cwe_urls_and_honest_fallback():
    d = knowledge.describe("PY-SQLI")
    assert d["curated"] and d["cwe"][0]["id"] == "CWE-89" and d["cwe"][0]["url"].endswith("/89.html")
    assert re.match(r"^A\d\d:2021", d["owasp"])
    ext = knowledge.describe("SG:some-semgrep-rule", "injection")
    assert ext["curated"] is False and ext["cwe"] == [] and "No curated explanation" in ext["why"]
    assert knowledge.describe("GL:aws-access-token", "secret")["cwe"][0]["id"] == "CWE-798"


def test_knowledge_never_carries_severity_or_scores():
    for k in knowledge.RULES.values():
        assert not ({"severity", "confidence", "score", "weight"} & set(k))  # reference text only
