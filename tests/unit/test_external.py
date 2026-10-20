import json
import subprocess
from pathlib import Path

import pytest

from avishkar.domain.policy import Policy
from avishkar.domain.scoring import ScoreConfig
from avishkar.workers import external
from avishkar.workers.external import ScannerFailed, ScannerUnavailable, parse_gitleaks, parse_semgrep
from avishkar.workers.pipeline import assemble, collect_findings

FULL = ScoreConfig.load(Path(__file__).resolve().parents[2] / "config" / "profiles" / "full.json")

SEMGREP_OUT = json.dumps({"results": [
    {"check_id": "avishkar.py.subprocess-shell-true", "path": "app.py", "start": {"line": 2},
     "extra": {"severity": "ERROR", "message": "shell=True", "lines": "x",
               "metadata": {"confidence": "HIGH", "category": "injection"}}},
    {"check_id": "avishkar.py.flask-debug", "path": "app.py", "start": {"line": 3},
     "extra": {"severity": "WARNING", "message": "debug", "metadata": {}}}], "errors": []})

GITLEAKS_OUT = json.dumps([
    {"RuleID": "aws-access-token", "Description": "AWS key", "File": "app.py", "StartLine": 4,
     "Match": "AWS = REDACTED", "Secret": "REDACTED"},
    {"RuleID": "generic-api-key", "Description": "Generic", "File": "cfg.py", "StartLine": 9, "Match": "k = REDACTED"}])


def proc(out="", code=0, err=""):
    return subprocess.CompletedProcess([], code, out, err)


def test_semgrep_mapping(tmp_path):
    (tmp_path / "app.py").write_text("import subprocess\nsubprocess.run(c, shell=True)\napp.run(debug=True)\n")
    f = parse_semgrep(SEMGREP_OUT, tmp_path)
    assert [x.rule_id for x in f] == ["SG:subprocess-shell-true", "SG:flask-debug"]
    assert f[0].severity.value == "high" and f[0].confidence.value == "high" and f[0].category == "injection"
    assert f[1].severity.value == "medium" and f[1].confidence.value == "medium"
    assert f[0].evidence == "subprocess.run(c, shell=True)" and f[0].detector_id == "semgrep"


@pytest.mark.parametrize("bad", ["", "not json", "{}", '{"results": "x"}',
                                 '{"results": [{"check_id": "x"}]}'])
def test_semgrep_garbage_raises(bad, tmp_path):
    with pytest.raises(ScannerFailed):
        parse_semgrep(bad, tmp_path)


def test_semgrep_snippet_redacts_secrets(tmp_path):
    (tmp_path / "app.py").write_text('x = 1\ny = {"password": "supersecretvalue"}\npassword = "supersecretvalue"\n')
    out = json.dumps({"results": [{"check_id": "r.x", "path": "app.py", "start": {"line": 3},
                                   "extra": {"severity": "INFO", "message": "m", "metadata": {}}}]})
    assert "supersecretvalue" not in parse_semgrep(out, tmp_path)[0].evidence


def test_gitleaks_mapping_and_no_raw_secret(tmp_path):
    f = parse_gitleaks(GITLEAKS_OUT, tmp_path)
    assert f[0].category == "secret" and f[0].severity.value == "critical" and f[0].confidence.value == "high"
    assert f[1].confidence.value == "medium" and f[1].severity.value == "high"  # generic rules are noisier
    assert parse_gitleaks("", tmp_path) == [] and parse_gitleaks("[]", tmp_path) == [] and parse_gitleaks("null", tmp_path) == []
    leaked = parse_gitleaks(json.dumps([{"RuleID": "r", "File": "a", "StartLine": 1,
                                         "Match": 'token = "AKIAQ3EXZ4HT7WN2K5ML"'}]), tmp_path)
    assert "AKIAQ3EXZ4HT7WN2K5ML" not in leaked[0].evidence  # second redaction barrier


@pytest.mark.parametrize("bad", ["{", '{"a":1}', '[{"nope": 1}]'])
def test_gitleaks_garbage_raises(bad, tmp_path):
    with pytest.raises(ScannerFailed):
        parse_gitleaks(bad, tmp_path)


def test_missing_binary_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.delenv("SEMGREP_PATH", raising=False)
    monkeypatch.setattr(external.shutil, "which", lambda _: None)
    with pytest.raises(ScannerUnavailable):
        external.detect_semgrep(tmp_path, [])
    with pytest.raises(ScannerUnavailable):
        external.detect_gitleaks(tmp_path, [])


def test_nonzero_exit_and_timeout_fail(monkeypatch, tmp_path):
    monkeypatch.setenv("SEMGREP_PATH", "semgrep")
    monkeypatch.setattr(external.subprocess, "run", lambda *a, **k: proc("", 2, "boom"))
    with pytest.raises(ScannerFailed, match="exited 2"):
        external.detect_semgrep(tmp_path, [])

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(external.subprocess, "run", timeout)
    with pytest.raises(ScannerFailed, match="timed out"):
        external.detect_semgrep(tmp_path, [])


def test_semgrep_invocation_is_offline_and_pinned(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setenv("SEMGREP_PATH", "semgrep")
    monkeypatch.setattr(external.subprocess, "run", lambda cmd, **k: seen.update(cmd=cmd) or proc('{"results": []}'))
    external.detect_semgrep(tmp_path, [])
    assert "auto" not in " ".join(seen["cmd"]) and "--metrics" in seen["cmd"] and "off" in seen["cmd"]
    assert str(external.RULES_PATH) in seen["cmd"]


def test_gitleaks_invocation_redacts_and_ignores_history(monkeypatch, tmp_path):
    seen = {}

    def fake(cmd, **k):
        seen["cmd"] = cmd
        Path(cmd[cmd.index("--report-path") + 1]).write_text("[]")
        return proc("", 0)
    monkeypatch.setenv("GITLEAKS_PATH", "gitleaks")
    monkeypatch.setattr(external.subprocess, "run", fake)
    assert external.detect_gitleaks(tmp_path, []) == []
    assert "--redact" in seen["cmd"] and "--no-git" in seen["cmd"]


def test_full_profile_missing_tools_is_incomplete_not_clean(monkeypatch, tmp_path):
    monkeypatch.delenv("SEMGREP_PATH", raising=False)
    monkeypatch.delenv("GITLEAKS_PATH", raising=False)
    monkeypatch.setattr(external.shutil, "which", lambda _: None)
    (tmp_path / "a.py").write_text("x = 1\n")
    res = collect_findings(FULL.required_detectors, source_dir=tmp_path)
    assert set(res["failed"]) == {"semgrep", "gitleaks"} and set(res["completed"]) == {"secrets", "code-patterns", "dependencies"}
    out = assemble(FULL, Policy.load(), res)
    assert out["status"] == "incomplete" and out["securityDebt"]["normalizedIndex"] is None
    assert out["decision"]["outcome"] == "not_evaluated" and FULL.version == "score-v1-full"


def test_full_profile_complete_with_tools_and_secret_dedupe(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text('import subprocess\nsubprocess.run(c, shell=True)\nAWS_KEY = "AKIAQ3EXZ4HT7WN2K5ML"\n')
    monkeypatch.setenv("SEMGREP_PATH", "semgrep")
    monkeypatch.setenv("GITLEAKS_PATH", "gitleaks")

    def fake(cmd, **k):
        if "--report-path" in cmd:
            Path(cmd[cmd.index("--report-path") + 1]).write_text(json.dumps(
                [{"RuleID": "aws-access-token", "File": str(Path(cmd[cmd.index("--source") + 1]) / "app.py"), "StartLine": 3,
                  "Match": "AWS_KEY = REDACTED"}]))
            return proc("", 1)
        return proc(json.dumps({"results": [{"check_id": "a.subprocess-shell-true", "path": str(Path(cmd[-1]) / "app.py"),
                                             "start": {"line": 2}, "extra": {"severity": "ERROR", "message": "m",
                                                                              "metadata": {"confidence": "HIGH"}}}]}))
    monkeypatch.setattr(external.subprocess, "run", fake)
    res = collect_findings(FULL.required_detectors, source_dir=tmp_path)
    assert res["failed"] == {}
    out = assemble(FULL, Policy.load(), res)
    secrets = [f for f in out["findings"] if f.raw.category == "secret"]
    assert out["status"] == "complete" and len(secrets) == 1  # builtin + gitleaks hit on one line count once
    assert any(f.raw.detector_id == "semgrep" for f in out["findings"])
