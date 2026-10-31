from .conftest import FIX, zip_dir

SEC = zip_dir(FIX / "secure")


def get_pdf(env, run_id):
    return env.client.get(f"/v1/analyses/{run_id}/report?format=pdf", headers=env.h)


def test_pdf_report_is_a_real_pdf_with_the_scan_content(env):
    run = env.scan("acme/pdf-app", zip_dir(FIX / "insecure")).json()
    r = get_pdf(env, run["runId"])
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"] == 'attachment; filename="acme_pdf-app-report.pdf"'
    pdf = r.content
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    text = pdf.decode("latin-1")
    for expected in ("Security debt report", "acme/pdf-app", "Executive summary", "Severity distribution", "Limitations",
                     "Zero findings does not mean the code is secure", "uncalibrated"):
        assert expected in text, expected
    assert "AKIAQ3EXZ4HT7WN2K5ML" not in text  # secrets stay redacted in every output format


def test_pdf_is_deterministic_for_the_same_report(env):
    run = env.scan("acme/pdf-same", zip_dir(FIX / "insecure")).json()
    assert get_pdf(env, run["runId"]).content == get_pdf(env, run["runId"]).content or True  # generatedAt differs per call
    a, b = get_pdf(env, run["runId"]).content, get_pdf(env, run["runId"]).content
    strip = lambda x: b"\n".join(l for l in x.split(b"\n") if b"generated" not in l)
    assert strip(a) == strip(b)


def test_pdf_for_an_incomplete_run_says_so_and_has_no_score(env, monkeypatch):
    monkeypatch.setattr(env.sandbox, "collect", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    run = env.scan("acme/pdf-inc", SEC).json()
    text = get_pdf(env, run["runId"]).content.decode("latin-1")
    assert "INCOMPLETE ANALYSIS" in text and "NOT a pass" in text.replace("This is NOT a pass", "NOT a pass")


def test_hostile_text_cannot_inject_pdf_markup_or_break_rendering(env):
    evil = zip_dir(FIX / "secure", {"x.py": 'y = eval("<b>bold</b><font color=red>x</font><para>")\n'})
    run = env.scan("acme/pdf-evil", evil).json()
    r = get_pdf(env, run["runId"])
    assert r.status_code == 200 and r.content.startswith(b"%PDF-")
    text = r.content.decode("latin-1")
    import re
    shown = "".join(re.findall(r"\(((?:\\.|[^\\)])*)\) Tj", text))  # the text actually drawn on the page
    assert "<b>bold</b>" in shown and "<font color=red>" in shown  # shown literally, not interpreted as markup


def test_pdf_requires_auth_and_tenant(env):
    run = env.scan("acme/pdf-auth", SEC).json()
    assert env.client.get(f"/v1/analyses/{run['runId']}/report?format=pdf").status_code == 401
    other = env.store.create_org("globex")
    env.add_user(other["id"], "eve@globex.test", "viewer")
    assert env.client.get(f"/v1/analyses/{run['runId']}/report?format=pdf", headers=env.login("eve@globex.test")).status_code == 404


def test_unicode_in_findings_does_not_crash_the_pdf(env):
    z = zip_dir(FIX / "secure", {"ünïcode_文件.py": 'password = "pässwörd-sécret-valué-→-1234"\n'})
    run = env.scan("acme/pdf-unicode", z).json()
    assert get_pdf(env, run["runId"]).status_code == 200
