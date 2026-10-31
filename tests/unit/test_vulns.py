import json
from pathlib import Path

import httpx
import pytest

from avishkar.adapters import vulns
from avishkar.domain.policy import Policy
from avishkar.domain.scoring import ScoreConfig
from avishkar.workers.manifests import parse_manifests
from avishkar.workers.pipeline import assemble, collect_findings

CFG, POL = ScoreConfig.load(), Policy.load()


def parse(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf8")
    return parse_manifests(tmp_path, sorted(x for x in tmp_path.rglob("*") if x.is_file()))


def by_name(deps):
    return {(d["eco"], d["name"]): d for d in deps}


# ------------------------------------------------------------------ manifest parsing
def test_parses_every_supported_manifest(tmp_path):
    deps = by_name(parse(tmp_path, {
        "requirements.txt": "Django==3.0.1  # old\nflask>=1.0\n-r other.txt\nrequests[security]==2.20.0\n",
        "package.json": json.dumps({"dependencies": {"lodash": "4.17.15", "express": "^4.16.0", "left": "latest", "git": "github:a/b"}}),
        "package-lock.json": json.dumps({"packages": {"": {}, "node_modules/minimist": {"version": "1.2.0"}, "node_modules/x": {"link": True}}}),
        "pom.xml": "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
                   "<dependency><groupId>a</groupId><artifactId>b</artifactId><version>${v}</version></dependency></dependencies></project>",
        "build.gradle": "dependencies {\n  implementation 'com.google.guava:guava:30.0-jre'\n  testImplementation(\"junit:junit:4.12\")\n}",
        "go.mod": "module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n\tgolang.org/x/text v0.3.0 // indirect\n)\nrequire github.com/a/b v1.0.0\n",
        "App.csproj": '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>',
        "composer.lock": json.dumps({"packages": [{"name": "monolog/monolog", "version": "v1.0.0"}]}),
        "Gemfile.lock": "GEM\n  specs:\n    rails (5.2.0)\n      actionpack (= 5.2.0)\n    nokogiri (1.8.0)\n",
    }))
    assert by_name  # sanity
    assert deps[("PyPI", "django")]["version"] == "3.0.1" and deps[("PyPI", "django")]["exact"]
    assert ("PyPI", "flask") not in deps  # unpinned: no exact version to ask about
    assert ("PyPI", "requests") in deps
    assert deps[("npm", "lodash")]["exact"] and not deps[("npm", "express")]["exact"]  # caret = lower bound only
    assert ("npm", "left") not in deps and ("npm", "git") not in deps
    assert deps[("npm", "minimist")]["version"] == "1.2.0"
    assert deps[("Maven", "org.apache.logging.log4j:log4j-core")]["version"] == "2.14.1"
    assert ("Maven", "a:b") not in deps  # unresolved ${property}
    assert ("Maven", "com.google.guava:guava") in deps and ("Maven", "junit:junit") in deps
    assert ("Go", "github.com/gin-gonic/gin") in deps and deps[("Go", "golang.org/x/text")]["version"] == "0.3.0"
    assert ("Go", "github.com/a/b") in deps
    assert ("NuGet", "Newtonsoft.Json") in deps
    assert deps[("Packagist", "monolog/monolog")]["version"] == "1.0.0"
    assert ("RubyGems", "rails") in deps and ("RubyGems", "nokogiri") in deps and ("RubyGems", "actionpack") not in deps


def test_malformed_manifests_never_raise_or_invent_dependencies(tmp_path):
    assert parse(tmp_path, {"package.json": "{not json", "package-lock.json": "[]", "pom.xml": "<<<", "go.mod": "\x00\x01",
                            "composer.lock": "null", "requirements.txt": "==\n\n==1.0"}) == []


def test_hostile_names_and_versions_are_dropped(tmp_path):
    deps = parse(tmp_path, {"requirements.txt": "evil;rm==1.0\nok-pkg==1.0\n", "package.json": json.dumps({"dependencies": {"a b": "1.0.0", "fine": "1.0.0"}})})
    assert {(d["eco"], d["name"]) for d in deps} == {("PyPI", "ok-pkg"), ("npm", "fine")}


# ------------------------------------------------------------------ the OSV client (mocked transport; no network)
def osv(handler):
    return vulns.OsvClient(transport=httpx.MockTransport(handler))


def fake_osv(request: httpx.Request):
    if request.url.path == "/v1/querybatch":
        qs = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]} if q["package"]["name"] == "lodash" else {} for q in qs]})
    if request.url.path.startswith("/v1/vulns/"):
        return httpx.Response(200, json={"id": "GHSA-aaaa-bbbb-cccc", "summary": "Prototype pollution in lodash", "aliases": ["CVE-2020-8203"],
                                         "database_specific": {"severity": "HIGH"},
                                         "affected": [{"package": {"name": "lodash"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]})
    return httpx.Response(404)


DEPS = [{"eco": "npm", "name": "lodash", "version": "4.17.15", "exact": True, "path": "package-lock.json", "line": 1},
        {"eco": "npm", "name": "safe-pkg", "version": "1.0.0", "exact": True, "path": "package-lock.json", "line": 1}]


def test_lookup_turns_advisories_into_findings_with_fix_version():
    out = osv(fake_osv).lookup(DEPS)
    assert len(out) == 1
    f = out[0]
    assert f["rule_id"] == "DEP-VULN" and f["severity"] == "high" and f["confidence"] == "high"
    assert "GHSA-aaaa-bbbb-cccc" in f["title"] and "4.17.19" in f["remediation"] and "CVE-2020-8203" in f["evidence"]


def test_range_lower_bound_is_reported_at_lower_confidence():
    d = dict(DEPS[0], exact=False)
    assert osv(fake_osv).lookup([d])[0]["confidence"] == "medium"


def test_only_ecosystem_name_and_version_are_sent():
    sent = []

    def h(req):
        sent.append(req.content.decode())
        return fake_osv(req)
    osv(h).lookup(DEPS)
    body = " ".join(sent)
    assert "package-lock.json" not in body and "lodash" in body and "4.17.15" in body


@pytest.mark.parametrize("handler", [
    lambda r: httpx.Response(500),
    lambda r: httpx.Response(200, text="not json"),
    lambda r: httpx.Response(200, json=["unexpected"]),
    lambda r: httpx.Response(200, json={"results": []}),  # wrong length
    lambda r: (_ for _ in ()).throw(httpx.ConnectError("down")),
])
def test_any_lookup_failure_raises(handler):
    with pytest.raises(vulns.VulnLookupError):
        osv(handler).lookup(DEPS)


def test_invalid_dependency_records_are_never_sent():
    sent = []
    osv(lambda r: (sent.append(1), fake_osv(r))[1]).lookup([{"eco": "npm", "name": "x; drop", "version": "1.0", "path": "p", "line": 1},
                                                            {"eco": "Evil", "name": "ok", "version": "1.0", "path": "p", "line": 1}])
    assert sent == []


# ------------------------------------------------------------------ pipeline: the honest-failure contract
def collected_with_deps(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.15"}}}))
    return collect_findings(CFG.required_detectors, source_dir=tmp_path)


def test_sandbox_stage_reports_dependencies_without_looking_anything_up(tmp_path):
    c = collected_with_deps(tmp_path)
    assert c["deps"] and c["deps"][0]["name"] == "lodash"


def test_findings_from_the_feed_reach_the_score(tmp_path):
    res = assemble(CFG, POL, collected_with_deps(tmp_path), vuln_source=osv(fake_osv))
    assert res["status"] == "complete" and any(f.raw.rule_id == "DEP-VULN" for f in res["findings"])
    assert res["securityDebt"]["normalizedIndex"] > 0


def test_a_failed_lookup_makes_the_scan_incomplete_never_clean(tmp_path):
    res = assemble(CFG, POL, collected_with_deps(tmp_path), vuln_source=osv(lambda r: httpx.Response(503)))
    assert res["status"] == "incomplete"
    assert res["securityDebt"]["normalizedIndex"] is None
    assert "vulnerability lookup failed" in res["completeness"]["failures"]["dependencies"]


def test_builtin_advisories_are_replaced_by_the_feed_not_doubled(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    c = collect_findings(CFG.required_detectors, source_dir=tmp_path)
    assert any(r["rule_id"] == "DEP-PYYAML" for r in c["raw"])
    res = assemble(CFG, POL, c, vuln_source=osv(lambda r: httpx.Response(200, json={"results": [{}]}) if r.url.path.endswith("batch") else fake_osv(r)))
    assert not any(f.raw.rule_id == "DEP-PYYAML" for f in res["findings"])


def test_without_a_feed_the_builtin_list_still_works(tmp_path, monkeypatch):
    monkeypatch.delenv("AVISHKAR_VULN_FEED", raising=False)
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    res = assemble(CFG, POL, collect_findings(CFG.required_detectors, source_dir=tmp_path))
    assert any(f.raw.rule_id == "DEP-PYYAML" for f in res["findings"])


def test_default_source_is_off_unless_enabled(monkeypatch):
    monkeypatch.delenv("AVISHKAR_VULN_FEED", raising=False)
    assert vulns.default_source() is None
    monkeypatch.setenv("AVISHKAR_VULN_FEED", "osv")
    assert isinstance(vulns.default_source(), vulns.OsvClient)


def test_sandbox_side_modules_do_not_need_httpx_or_the_adapters_package(tmp_path):
    """Regression: the scan worker (and the Docker worker image) ships only domain/ and workers/ and has no httpx."""
    import subprocess
    import sys

    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    code = (
        "import sys; sys.modules['httpx'] = None; sys.modules['avishkar.adapters'] = None\n"
        "from pathlib import Path\n"
        "from avishkar.workers.pipeline import collect_findings\n"
        "from avishkar.domain.scoring import ScoreConfig\n"
        f"r = collect_findings(ScoreConfig.load().required_detectors, source_dir=Path({str(tmp_path)!r}))\n"
        "assert r['deps'] and not r['failed'], r\n"
    )
    root = Path(__file__).resolve().parents[2]
    p = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
