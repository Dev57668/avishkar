import math

import pytest

from avishkar.workers.sandbox import Sandbox

from .conftest import FIX, Env, zip_dir

INSEC = zip_dir(FIX / "insecure")
SEC = zip_dir(FIX / "secure")


def two_runs(env, name="r/x"):
    a = env.scan(name, INSEC)
    b = env.scan(name, SEC)
    return a.json(), b.json()


# ------------------------------------------------------------------ findings explorer
def test_findings_filters_sort_and_total(env):
    q = env.scan("r/f", INSEC).json()
    rid = q["repositoryId"]
    get = lambda **kw: env.client.get(f"/v1/repositories/{rid}/findings", params=kw, headers=env.h).json()
    allf = get(limit=200)
    assert allf["total"] == len(allf["items"]) > 5
    assert {i["state"] for i in allf["items"]} == {"open"}
    crit = get(severity="critical")
    assert crit["total"] >= 1 and all(i["severity"] == "critical" for i in crit["items"])
    assert get(confidence="high")["total"] >= 1 and get(category="secret")["total"] >= 1
    # text search over title, rule id, path and evidence; wildcards in the term are treated literally
    assert {i["rule_id"] for i in get(q="shell")["items"]} == {"PY-SHELL"}
    assert get(q="requirements")["total"] >= 1 and get(q="app.py")["total"] >= 1
    assert get(q="%")["total"] == 0 and get(q="_")["total"] == 0
    assert get(q="zzz-no-such-thing")["total"] == 0
    assert get(path="requirements.txt")["total"] >= 1
    # CWE filter goes through the knowledge base
    sqli = get(cwe="CWE-89")
    assert sqli["total"] >= 1 and all(i["rule_id"].startswith("PY-SQLI") for i in sqli["items"])
    assert get(cwe="CWE-99999")["total"] == 0
    # sorting + offset paging
    by_sev = get(sort="severity", limit=200)["items"]
    order = ["critical", "high", "medium", "low", "informational"]
    assert [order.index(i["severity"]) for i in by_sev] == sorted(order.index(i["severity"]) for i in by_sev)
    desc = get(sort="severity", order="desc", limit=200)["items"]
    assert desc[0]["severity"] == by_sev[-1]["severity"]
    p1 = get(sort="path", limit=3)
    p2 = get(sort="path", limit=3, offset=p1["nextOffset"])
    assert p1["nextOffset"] == 3 and not ({i["id"] for i in p1["items"]} & {i["id"] for i in p2["items"]})
    paths = [i["location"].split(":")[0] for i in get(sort="path", limit=200)["items"]]
    assert paths == sorted(paths)
    # cursor paging still works for the default sort
    c1 = get(limit=2)
    c2 = get(limit=2, cursor=c1["nextCursor"])
    assert not ({i["id"] for i in c1["items"]} & {i["id"] for i in c2["items"]})


@pytest.mark.parametrize("params", [{"severity": "catastrophic"}, {"state": "x"}, {"sort": "drop table"}, {"order": "up"},
                                    {"cwe": "89"}, {"limit": 0}, {"limit": 500}, {"offset": -1}, {"q": "x" * 101},
                                    {"category": "a b;c"}])
def test_findings_rejects_bad_query_parameters(env, params):
    rid = env.scan("r/v", SEC).json()["repositoryId"]
    assert env.client.get(f"/v1/repositories/{rid}/findings", params=params, headers=env.h).status_code == 422


def test_sql_special_characters_in_search_are_inert(env):
    rid = env.scan("r/s", INSEC).json()["repositoryId"]
    for term in ("'; DROP TABLE finding; --", "\\", "a\\%b", "%' OR '1'='1"):
        r = env.client.get(f"/v1/repositories/{rid}/findings", params={"q": term}, headers=env.h)
        assert r.status_code == 200 and r.json()["total"] == 0
    assert env.client.get(f"/v1/repositories/{rid}/findings", headers=env.h).json()["total"] > 0  # table intact


def test_finding_detail_has_knowledge_cwe_and_debt_breakdown(env):
    rid = env.scan("r/d", INSEC).json()["repositoryId"]
    item = next(i for i in env.client.get(f"/v1/repositories/{rid}/findings", headers=env.h).json()["items"] if i["rule_id"] == "PY-EVAL")
    assert item["cwe"] == ["CWE-95"] and item["assurance"] == "structural" and item["debt"]["units"] == 3.0
    d = env.client.get(f"/v1/findings/{item['id']}", headers=env.h).json()
    k = d["knowledge"]
    assert k["curated"] and k["cwe"][0]["url"].endswith("/95.html") and "ast.literal_eval" in k["secureExample"]["code"]
    assert d["instances"][0]["path"] == "app.py" and "eval" in d["instances"][0]["evidence"]
    assert d["debt"] == {"impact": 4.0, "exposure": 1.0, "confidence": 0.75, "age": 1.0, "units": 3.0}


def test_rules_catalog(env):
    r = env.client.get("/v1/rules", headers=env.h).json()
    assert r["kbVersion"] and len(r["items"]) >= 40 and all(i["cwe"] for i in r["items"])
    assert env.client.get("/v1/rules/PY-SHELL", headers=env.h).json()["cwe"][0]["id"] == "CWE-78"
    assert env.client.get("/v1/rules/NOPE", headers=env.h).status_code == 404
    assert env.client.get("/v1/rules").status_code == 401


# ------------------------------------------------------------------ score explanation
def test_explanation_reconciles_with_the_stored_score(env):
    run = env.scan("r/e", INSEC).json()
    ex = env.client.get(f"/v1/analyses/{run['runId']}/explain", headers=env.h).json()
    t = ex["totals"]
    assert ex["status"] == "calculated" and t["reproducible"] is True and t["recomputedIndex"] == t["normalizedIndex"]
    assert math.isclose(sum(c["D"] for c in ex["contributions"]), t["grossUnits"], abs_tol=1e-6)
    assert math.isclose(sum(c["share"] for c in ex["contributions"]), 100.0, abs_tol=0.6)
    ds = [c["D"] for c in ex["contributions"]]
    assert ds == sorted(ds, reverse=True)
    top = ex["contributions"][0]
    assert math.isclose(top["I"] * top["E"] * top["C"] * top["A"], top["D"], abs_tol=1e-9) and "= " in top["calculation"]
    m = ex["method"]
    assert m["calibrated"] is False and "not a probability" in m["disclaimer"] and "NOT part of the score" in " ".join(m["notes"])
    assert m["factors"]["age (A)"]["enabled"] is False
    assert ex["flags"]["exposureUnknown"] == len(ex["contributions"])  # no reachability data: all unknown, none treated as safe


def test_explanation_is_deterministic(env):
    a = env.client.get(f"/v1/analyses/{env.scan('r/e1', INSEC).json()['runId']}/explain", headers=env.h).json()
    b = env.client.get(f"/v1/analyses/{env.scan('r/e2', INSEC).json()['runId']}/explain", headers=env.h).json()
    strip = lambda e: [(c["rule"], c["path"], c["line"], c["D"]) for c in e["contributions"]]
    assert strip(a) == strip(b) and a["totals"]["normalizedIndex"] == b["totals"]["normalizedIndex"]


def test_explanation_of_an_incomplete_run_is_not_zero(env, monkeypatch):
    monkeypatch.setattr(env.sandbox, "collect", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    run = env.scan("r/inc", SEC).json()
    ex = env.client.get(f"/v1/analyses/{run['runId']}/explain", headers=env.h).json()
    assert ex["status"] == "not_calculated" and ex["totals"] is None and ex["contributions"] == []
    assert "never reported as zero" in ex["reason"]


def test_explanation_excluded_states_and_tenant_isolation(env):
    run = env.scan("r/ex", INSEC).json()
    rid = run["repositoryId"]
    f = env.client.get(f"/v1/repositories/{rid}/findings", headers=env.h).json()["items"][0]
    ok = env.client.post(f"/v1/findings/{f['id']}/dispositions", headers=env.h,
                         json={"type": "false_positive", "rationale": "test fixture only", "expected_version": f["version"]})
    assert ok.status_code == 200
    run2 = env.scan("r/ex", INSEC).json()
    ex = env.client.get(f"/v1/analyses/{run2['runId']}/explain", headers=env.h).json()
    assert ex["totals"]["findingsExcluded"] == {"false_positive": 1}
    other = env.store.create_org("globex")
    env.add_user(other["id"], "eve@globex.test", "viewer")
    assert env.client.get(f"/v1/analyses/{run['runId']}/explain", headers=env.login("eve@globex.test")).status_code == 404


# ------------------------------------------------------------------ before / after
def test_compare_explains_exactly_why_the_score_moved(env):
    a, b = two_runs(env)
    c = env.client.get(f"/v1/repositories/{a['repositoryId']}/compare", headers=env.h).json()
    assert c["comparable"] and c["base"]["runId"] == a["runId"] and c["head"]["runId"] == b["runId"]
    assert c["delta"]["index"] < 0 and c["delta"]["grossUnits"] == round(-c["base"]["grossUnits"], 6)
    assert len(c["fixed"]) > 5 and c["introduced"] == [] and c["reconciles"] is True
    assert sum(x["D"] for x in c["fixed"]) == pytest.approx(c["base"]["grossUnits"])
    assert c["fixed"][0]["D"] >= c["fixed"][-1]["D"] and c["fixed"][0]["title"] and c["fixed"][0]["path"]
    assert any("no longer present" in s for s in c["explanation"]) and "saturating curve" in c["explanation"][-1]
    # reversed direction: the same findings are "introduced"
    r = env.client.get(f"/v1/repositories/{a['repositoryId']}/compare", params={"base": b["runId"], "head": a["runId"]}, headers=env.h).json()
    assert len(r["introduced"]) == len(c["fixed"]) and r["fixed"] == [] and r["delta"]["index"] > 0 and r["reconciles"]


def test_compare_same_run_has_no_change(env):
    a = env.scan("r/same", INSEC).json()
    c = env.client.get(f"/v1/repositories/{a['repositoryId']}/compare", params={"base": a["runId"], "head": a["runId"]}, headers=env.h).json()
    assert c["comparable"] and c["fixed"] == [] and c["introduced"] == [] and c["delta"]["index"] == 0
    assert "identical" in c["explanation"][0]


def test_compare_needs_two_complete_runs_and_valid_ids(env):
    a = env.scan("r/one", INSEC).json()
    url = f"/v1/repositories/{a['repositoryId']}/compare"
    assert env.client.get(url, headers=env.h).status_code == 422
    assert env.client.get(url, params={"base": "run_nope", "head": a["runId"]}, headers=env.h).status_code == 404
    assert env.client.get(url, params={"base": "bad id"}, headers=env.h).status_code == 422


def test_compare_refuses_incomplete_or_cross_version(env, monkeypatch):
    a = env.scan("r/cv", INSEC).json()
    rid = a["repositoryId"]
    monkeypatch.setattr(env.sandbox, "collect", lambda *a_, **k: (_ for _ in ()).throw(OSError("x")))
    bad = env.scan("r/cv", SEC).json()
    c = env.client.get(f"/v1/repositories/{rid}/compare", params={"base": a["runId"], "head": bad["runId"]}, headers=env.h).json()
    assert c["comparable"] is False and "incomplete" in c["reason"] and c["fixed"] == []
    # a different score version/K is never presented as a real improvement
    monkeypatch.undo()
    b = env.scan("r/cv", SEC).json()
    env.store.d.execute("UPDATE analysis_run SET score=REPLACE(score, '\"k\": 20.0', '\"k\": 13.0') WHERE id=?", (b["runId"],))
    c2 = env.client.get(f"/v1/repositories/{rid}/compare", params={"base": a["runId"], "head": b["runId"]}, headers=env.h).json()
    assert c2["comparable"] is False and "not equivalent" in c2["reason"]


# ------------------------------------------------------------------ dashboard & overview
def test_dashboard_numbers_come_from_stored_scan_data(env):
    a, b = two_runs(env)
    rid = a["repositoryId"]
    d = env.client.get(f"/v1/repositories/{rid}/dashboard", headers=env.h).json()
    assert d["repository"]["name"] == "r/x" and d["runs"] == 2 and len(d["trend"]) == 2
    assert d["trend"][0]["normalizedIndex"] > d["trend"][1]["normalizedIndex"] == d["score"]["normalizedIndex"] == 0.0
    assert d["score"]["previousIndex"] == d["trend"][0]["normalizedIndex"] and d["score"]["delta"] < 0
    assert d["totalFindings"] == 0 and sum(d["severity"].values()) == 0 and d["states"].get("fixed", 0) > 5
    assert d["filesScanned"] == 2 and d["health"]["status"] == "none_detected" and "does not prove" in d["health"]["reason"]
    assert d["topFiles"] == []  # nothing open: no invented "most vulnerable files"
    assert [x["type"] for x in d["activity"]][:2] == ["scan", "scan"]
    # now the insecure state
    ins = env.client.get(f"/v1/repositories/{env.scan('r/y', INSEC).json()['repositoryId']}/dashboard", headers=env.h).json()
    assert ins["severity"]["critical"] >= 1 and ins["health"]["status"] == "critical"
    assert ins["totalFindings"] == sum(ins["severity"].values()) and ins["topFiles"][0]["debt"] >= ins["topFiles"][-1]["debt"]
    assert sum(f["debt"] for f in ins["topFiles"]) <= ins["score"]["grossUnits"] + 1e-6
    assert set(ins["topFiles"][0]) == {"path", "findings", "debt", "worst"} and ins["score"]["calibrated"] is False
    assert sum(ins["categories"].values()) == ins["totalFindings"]


def test_dashboard_incomplete_latest_run_is_not_healthy(env, monkeypatch):
    rid = env.scan("r/h", SEC).json()["repositoryId"]
    monkeypatch.setattr(env.sandbox, "collect", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    env.scan("r/h", SEC)
    d = env.client.get(f"/v1/repositories/{rid}/dashboard", headers=env.h).json()
    assert d["health"]["status"] == "incomplete" and "not a pass" in d["health"]["reason"]
    assert d["latest"]["status"] == "incomplete" and d["score"]["normalizedIndex"] == 0.0  # last COMPLETE score, labeled by latest


def test_dashboard_empty_and_unsupported_languages(env, tmp_path):
    rid = env.store.get_or_create_repo(env.org["id"], "empty/repo")["id"]
    d = env.client.get(f"/v1/repositories/{rid}/dashboard", headers=env.h).json()
    assert d["health"]["status"] == "no_data" and d["score"] is None and d["trend"] == []
    mixed = zip_dir(FIX / "secure", {"B.rs": "fn main() {}\n"})
    dm = env.client.get(f"/v1/repositories/{env.scan('r/mix', mixed).json()['repositoryId']}/dashboard", headers=env.h).json()
    assert dm["coverage"]["notEvaluated"] == {".rs": 1}


def test_overview_ranks_repositories_by_real_index(env):
    env.scan("r/clean", SEC)
    env.scan("r/dirty", INSEC)
    o = env.client.get("/v1/overview", headers=env.h).json()
    assert [r["name"] for r in o["repositories"]] == ["r/dirty", "r/clean"]
    assert o["repositoryCount"] == 2 and o["highestIndex"] == o["repositories"][0]["normalizedIndex"]
    assert o["severity"]["critical"] == o["repositories"][0]["severity"]["critical"] >= 1
    other = env.store.create_org("globex")
    env.add_user(other["id"], "eve@globex.test", "viewer")
    assert env.client.get("/v1/overview", headers=env.login("eve@globex.test")).json()["repositoryCount"] == 0


# ------------------------------------------------------------------ report
def test_report_json_contains_real_data_and_no_secret(env):
    a, b = two_runs(env)
    r = env.client.get(f"/v1/analyses/{a['runId']}/report", headers=env.h).json()
    assert r["reportVersion"] and r["repository"]["name"] == "r/x" and r["scan"]["filesScanned"] == 3
    assert r["securityDebt"]["normalizedIndex"] > 0 and r["openFindings"] == len(r["findings"]) > 5
    assert "AKIAQ3EXZ4HT7WN2K5ML" not in str(r)
    f = next(x for x in r["findings"] if x["ruleId"] == "PY-SHELL")
    assert f["cwe"][0]["id"] == "CWE-78" and f["debt"]["units"] == 3.0 and f["secureExample"]["code"] and f["why"] and f["impact"]
    assert "heuristic" in " ".join(r["limitations"]) or "Zero findings" in " ".join(r["limitations"])
    assert r["comparison"] is None                                   # first analysis: nothing to compare
    rb = env.client.get(f"/v1/analyses/{b['runId']}/report", headers=env.h).json()
    assert rb["comparison"]["comparable"] and rb["comparison"]["delta"]["index"] < 0 and rb["openFindings"] == 0
    assert "does not prove" not in rb["executiveSummary"] and "0 critical" in rb["executiveSummary"]


def test_report_incomplete_run_says_so(env, monkeypatch):
    monkeypatch.setattr(env.sandbox, "collect", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    run = env.scan("r/ri", SEC).json()
    r = env.client.get(f"/v1/analyses/{run['runId']}/report", headers=env.h).json()
    assert r["securityDebt"]["normalizedIndex"] is None and "not a pass" in r["executiveSummary"]
    assert any("INCOMPLETE ANALYSIS" in x for x in r["limitations"])
    html = env.client.get(f"/v1/analyses/{run['runId']}/report?format=html", headers=env.h).text
    assert "Incomplete analysis" in html and "not a pass" in html


def test_report_html_is_escaped_and_printable(env):
    evil = zip_dir(FIX / "secure", {"x.py": 'y = eval("<script>alert(1)</script>")\n'})
    run = env.scan("r/evil", evil).json()
    r = env.client.get(f"/v1/analyses/{run['runId']}/report?format=html", headers=env.h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    body = r.text
    assert "<script>alert(1)</script>" not in body and "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "@media print" in body and "<script" not in body.lower().replace("&lt;script", "")
    assert env.client.get(f"/v1/analyses/{run['runId']}/report?format=pdf", headers=env.h).status_code == 422


def test_report_requires_auth_and_tenant(env):
    run = env.scan("r/ra", SEC).json()
    assert env.client.get(f"/v1/analyses/{run['runId']}/report").status_code == 401
    other = env.store.create_org("globex")
    env.add_user(other["id"], "eve@globex.test", "viewer")
    assert env.client.get(f"/v1/analyses/{run['runId']}/report", headers=env.login("eve@globex.test")).status_code == 404
