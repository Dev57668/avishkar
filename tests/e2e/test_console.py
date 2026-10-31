import re

import pytest

from e2e_helpers import ADMIN, guest

pytestmark = pytest.mark.e2e


def test_landing_page_loads_cleanly_with_the_product_name(page):
    assert page.title().startswith("Second Read")
    assert page.locator("h1").first.inner_text().startswith("Second Read")
    assert page.locator(".nav-links a").count() >= 4
    assert page.locator("#fig3-body tr").count() == 3          # filled from the recorded real scans
    assert page.problems == []


def test_login_screen_offers_guest_and_rejects_bad_credentials(page):
    assert page.get_by_role("button", name="Continue as guest").is_visible()
    page.fill("#em", "nobody@example.test")
    page.fill("#pw", "wrong-password-123")
    page.get_by_role("button", name="Sign in").click()
    err = page.locator(".loginform .errstate")
    err.wait_for(state="visible")
    assert "Invalid email or password" in err.inner_text()
    assert page.locator("#console .logincard").is_visible()


def test_guest_sees_overview_and_cannot_see_upload_or_admin(page):
    guest(page)
    assert page.locator(".kpi").count() == 4
    assert page.get_by_role("link", name="Admin").count() == 0
    assert page.locator("text=Scan a repository snapshot").count() == 0     # read-only account
    assert "your role cannot upload" in page.locator("#console").inner_text().lower()
    page.get_by_role("button", name="Sign out").click()
    page.locator("dialog button", has_text="Sign out").click()          # confirmation dialog
    page.wait_for_selector("#console .logincard")


def test_demo_lab_scan_fix_and_rescan_use_real_results(page):
    guest(page)
    page.get_by_role("link", name="Demo lab").click()
    page.wait_for_selector("text=Choose a sample")
    assert page.locator("button.sample").count() >= 14
    page.get_by_role("radio", name="Vulnerable Python app").click()
    page.get_by_role("button", name="Scan sample").click()
    page.wait_for_selector("text=finding(s) in this scan")
    first = page.locator("text=finding(s) in this scan").first.inner_text()
    assert int(re.match(r"(\d+)", first).group(1)) == 24
    page.get_by_role("button", name="Select all").click()
    page.get_by_role("button", name="Apply fixes & rescan").click()
    page.wait_for_selector("text=0 finding(s) in this scan")
    page.wait_for_selector("text=Before / after")
    assert "Fixed (24)" in page.locator(".demo-result").inner_text()
    assert page.problems == []


def test_unsupported_language_is_incomplete_never_clean(page):
    guest(page)
    page.get_by_role("link", name="Demo lab").click()
    page.get_by_role("radio", name="Rust web service").click()
    page.get_by_role("button", name="Scan sample").click()
    page.wait_for_selector("text=Scan incomplete")
    text = page.locator(".demo-result").inner_text()
    assert "no score is shown" in text and "not a pass" in text
    assert page.locator(".gauge").count() == 0


def test_repository_dashboard_explorer_and_score_arithmetic(page):
    guest(page)
    page.locator("tr.clickrow", has_text="demo/vulnerable-python").click()
    page.wait_for_selector("text=Most vulnerable files")
    page.get_by_role("button", name="Show the arithmetic").click()
    page.wait_for_selector("text=reproducible")
    sel = page.locator("#sec-find select").filter(has=page.locator("option", has_text="Fixed")).first
    sel.select_option(label="Fixed")
    page.wait_for_selector("#sec-find [aria-expanded]")
    page.locator("#sec-find [aria-expanded]").first.click()
    page.wait_for_selector("#sec-find >> text=Secure example")
    detail = page.locator("#sec-find").inner_text()
    assert "Secure example" in detail and "CWE-" in detail
    page.get_by_role("button", name="Ask AI about this").click()
    page.wait_for_selector("dialog.drawer")
    # the demo viewer is read-only, and the AI is off on this server: either way the drawer must say so, never answer
    page.wait_for_selector("dialog.drawer .empty-t")
    assert page.locator("dialog.drawer .empty-t").inner_text() in ("AI assistant unavailable", "Your role cannot use the assistant")


def test_export_menu_offers_pdf_sarif_json_and_html(page):
    guest(page)
    page.locator("tr.clickrow", has_text="demo/vulnerable-python").click()
    page.wait_for_selector("text=Most vulnerable files")
    page.get_by_role("button", name="Export").click()
    labels = page.locator(".menu-item").all_inner_texts()
    assert any("PDF" in l for l in labels) and any("SARIF" in l for l in labels) and any("JSON" in l for l in labels) and any("HTML" in l for l in labels)
    with page.expect_download() as dl:
        page.get_by_role("menuitem", name="PDF report").click()
    assert dl.value.suggested_filename.endswith("-report.pdf")
    path = dl.value.path()
    assert open(path, "rb").read(5) == b"%PDF-"


def test_admin_sees_upload_form_and_admin_tabs(page):
    page.fill("#em", ADMIN[0])
    page.fill("#pw", ADMIN[1])
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_selector("text=Repositories")
    assert page.locator("text=Scan a repository snapshot").count() == 1
    page.get_by_role("link", name="Admin").click()
    page.wait_for_selector("role=tab[name='API keys']")
    assert page.locator("[role=tab]").count() == 5


def test_upload_form_normalizes_the_repository_name(page, tmp_path):
    import zipfile
    z = tmp_path / "tiny.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("app.py", "import hashlib\nh = hashlib.md5(b'x').hexdigest()\n")
    page.fill("#em", ADMIN[0])
    page.fill("#pw", ADMIN[1])
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_selector("text=Scan a repository snapshot")
    page.fill("#up-repo", "my demo  project!")
    page.set_input_files("#up-file", str(z))
    page.get_by_role("button", name="Analyze").click()
    page.wait_for_selector("text=Most vulnerable files")
    assert "my-demo-project" in page.locator(".repo-name").inner_text()


@pytest.mark.parametrize("width", [320, 375, 414])
def test_no_horizontal_scroll_on_phones(browser, server, width):
    ctx = browser.new_context(viewport={"width": width, "height": 800})
    pg = ctx.new_page()
    pg.set_default_timeout(60000)
    pg.goto(server + "/", wait_until="domcontentloaded")
    pg.wait_for_selector("#console .logincard")
    assert pg.evaluate("document.documentElement.scrollWidth") <= width
    pg.get_by_role("button", name="Continue as guest").click()
    pg.wait_for_selector("text=Repositories")
    assert pg.evaluate("document.documentElement.scrollWidth") <= width
    pg.get_by_role("button", name="Menu", exact=True).click()
    assert pg.locator("#cnav.open").count() == 1                    # the responsive menu opens
    ctx.close()


def test_keyboard_reaches_the_main_controls(page):
    page.keyboard.press("Tab")
    focused = page.evaluate("document.activeElement && document.activeElement.tagName")
    assert focused in ("A", "BUTTON", "INPUT")
    page.focus("#console button:has-text('Continue as guest')")
    page.keyboard.press("Enter")
    page.wait_for_selector("text=Repositories")

