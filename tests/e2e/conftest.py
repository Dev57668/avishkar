"""Browser tests of the web console. They start a real server (demo mode, own temp database) and drive it with Playwright.

Skipped automatically when Playwright or a browser is not installed:
    pip install playwright && python -m playwright install chromium
Set E2E_CHANNEL=msedge (or chrome) to use an installed browser instead of the downloaded Chromium.
"""
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
from e2e_helpers import ADMIN, DEMO_PW  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    if sync_playwright is None:
        pytest.skip("playwright is not installed")
    port, db = _free_port(), tmp_path_factory.mktemp("e2e") / "e2e.db"
    env = {**os.environ, "AVISHKAR_DEMO_MODE": "1", "AVISHKAR_PUBLISH_DEMO_LOGIN": "1", "AVISHKAR_DEMO_PASSWORD": DEMO_PW,
           "AVISHKAR_UPLOADS": "limited", "AVISHKAR_ADMIN_EMAIL": ADMIN[0], "AVISHKAR_ADMIN_PASSWORD": ADMIN[1],
           "AVISHKAR_SECRET_KEY": "e2e-secret-key-" + "x" * 30, "AVISHKAR_VULN_FEED": "", "PYTHONUNBUFFERED": "1"}
    log = (tmp_path_factory.getbasetemp() / "e2e-server.log").open("w")
    p = subprocess.Popen([sys.executable, "-m", "avishkar", "serve", "--port", str(port), "--db", str(db)], cwd=ROOT, env=env,
                         stdout=log, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(120):
            try:
                if urllib.request.urlopen(url + "/healthz", timeout=2).status == 200:
                    break
            except OSError:
                time.sleep(0.5)
        else:
            pytest.fail("server did not start; see " + log.name)
        # wait until the bundled demo samples are seeded (done before the worker starts serving, but be patient)
        for _ in range(120):
            try:
                if b"vulnerable-python" in urllib.request.urlopen(url + "/static/demo_results.json", timeout=2).read():
                    break
            except OSError:
                pass
            time.sleep(0.5)
        yield url
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
        log.close()


@pytest.fixture(scope="session")
def browser():
    if sync_playwright is None:
        pytest.skip("playwright is not installed")
    with sync_playwright() as pw:
        try:
            b = pw.chromium.launch(channel=os.environ.get("E2E_CHANNEL") or None)
        except Exception as e:  # no browser installed
            pytest.skip(f"no browser available: {str(e)[:120]}")
        yield b
        b.close()


@pytest.fixture()
def page(browser, server):
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    pg = ctx.new_page()
    pg.set_default_timeout(60000)
    pg.problems = []
    # headless Chromium software-renders WebGL and logs "GL Driver Message" performance warnings; those are not page faults
    pg.on("console", lambda m: pg.problems.append(f"console {m.type}: {m.text}")
          if m.type in ("error", "warning") and "GL Driver Message" not in m.text else None)
    pg.on("pageerror", lambda e: pg.problems.append(f"pageerror: {e}"))
    pg.on("response", lambda r: pg.problems.append(f"HTTP {r.status}: {r.url}") if r.status >= 400 and "/v1/auth/me" not in r.url else None)
    pg.goto(server + "/", wait_until="domcontentloaded")
    pg.wait_for_selector("#console .logincard")
    yield pg
    ctx.close()


