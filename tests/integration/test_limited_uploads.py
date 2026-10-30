import io
import zipfile

import httpx

from avishkar.adapters.mailer import Mailer
from avishkar.demo import DemoSettings

from .conftest import FIX, Env, zip_dir
from .test_email import Outbox

PW = "long-enough-pw"


def env(tmp_path):
    box = Outbox()
    m = Mailer("re_test", "Avishkar <no-reply@example.test>", "https://site.example", transport=httpx.MockTransport(box))
    e = Env(tmp_path, demo=DemoSettings(enabled=True, uploads="limited", signup=True, password="demo-viewer-123"), mailer=m)
    return e, box


def signup(e, box, email):
    assert e.client.post("/v1/auth/register", json={"email": email, "password": PW}).status_code == 202
    assert e.client.post("/v1/auth/verify", json={"token": box.token()}).status_code == 200
    return e.login(email, PW)


def up(e, h, data, repo="mine"):
    return e.client.post("/v1/analyses", headers=h, data={"repository": repo}, files={"archive": ("a.zip", data)})


def small_zip():
    return zip_dir(FIX / "secure")


def test_signup_gets_private_org_and_can_upload_small_zip(tmp_path):
    e, box = env(tmp_path)
    h = signup(e, box, "a@x.co")
    assert e.client.get("/v1/auth/me", headers=h).json()["role"] == "analyst"
    r = up(e, h, small_zip())
    assert r.status_code == 202
    e.runner.drain()
    assert [x["name"] for x in e.client.get("/v1/repositories", headers=h).json()["items"]] == ["mine"]


def test_results_are_private_to_each_account_and_hidden_from_admin_org(tmp_path):
    e, box = env(tmp_path)
    ha, hb = signup(e, box, "a@x.co"), signup(e, box, "b@x.co")
    r = up(e, ha, zip_dir(FIX / "insecure")).json()
    e.runner.drain()
    assert e.client.get("/v1/repositories", headers=hb).json()["items"] == []
    assert e.client.get(f"/v1/repositories/{r['repositoryId']}/findings", headers=hb).status_code == 404
    assert e.client.get(f"/v1/analyses/{r['runId']}/sarif", headers=hb).status_code == 404
    assert e.client.get("/v1/repositories", headers=e.h).json()["items"] == []  # the operator org does not see it either


def test_caps_size_files_and_rate(tmp_path):
    e, box = env(tmp_path)
    h = signup(e, box, "a@x.co")
    assert up(e, h, b"PK" + b"0" * 2_100_000).status_code == 413
    many = io.BytesIO()
    with zipfile.ZipFile(many, "w") as z:
        for i in range(301):
            z.writestr(f"f{i}.py", "x=1\n")
    assert up(e, h, many.getvalue()).status_code == 413
    assert up(e, h, b"PKnot-a-zip").status_code == 422
    codes = [up(e, h, small_zip(), repo=f"r{i}").status_code for i in range(4)]
    assert codes == [202, 202, 202, 429]


def test_admin_is_not_capped_and_demo_viewer_cannot_upload(tmp_path):
    e, box = env(tmp_path)
    for i in range(5):
        assert up(e, e.h, small_zip(), repo=f"r{i}").status_code == 202
    e.add_user(e.org["id"], "demo@avishkar.dev", "viewer")
    g = {"Authorization": "Bearer " + e.client.post("/v1/auth/guest").json()["token"]}
    assert up(e, g, small_zip()).status_code == 403
