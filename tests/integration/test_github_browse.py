"""GitHub repository/branch browsing and manual branch scans, against a mocked GitHub transport.

These tests prove the request/response handling and the security properties of OUR code (tenant ownership, the commit
SHA comes from GitHub and never from the client, honest 'not configured'). They do not prove behaviour against the live
GitHub API, which needs a real App installation.
"""
import httpx

from avishkar.adapters import github as gh

from .conftest import PW, Env
from .test_github import SHA, FakeGitHub, keypair, link, make_env  # noqa: F401  (keypair is a fixture)


class BrowseGitHub(FakeGitHub):
    def __call__(self, req: httpx.Request):
        path = req.url.path
        if req.method == "GET" and not path.endswith("/access_tokens"):
            self.calls.append((req.method, path))
            if path == "/installation/repositories":
                return httpx.Response(200, json={"repositories": [
                    {"full_name": "acme/app", "default_branch": "main", "private": True},
                    {"full_name": "bad name/with spaces", "default_branch": "main"}]})
            if path == "/repos/acme/app/branches":
                return httpx.Response(200, json=[{"name": "main", "commit": {"sha": SHA}}, {"name": "dev", "commit": {"sha": "c" * 40}},
                                                 {"name": "weird", "commit": {"sha": "not-a-sha"}}])
        return super().__call__(req)


def env(tmp_path, keypair, **kw):
    priv, pub = keypair
    fake = BrowseGitHub(pub, **kw)
    client = gh.GitHubClient("123", priv, "https://api.github.test", transport=httpx.MockTransport(fake))
    return Env(tmp_path, github=client, webhook_secret="whsec_test"), fake


def test_not_configured_is_reported_honestly_and_never_fabricated(tmp_path, monkeypatch):
    for k in ("GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_PRIVATE_KEY_PATH"):
        monkeypatch.delenv(k, raising=False)
    e = Env(tmp_path)
    for r in (e.client.get("/v1/github/repositories?installation=777", headers=e.h),
              e.client.get("/v1/github/branches?installation=777&repo=acme/app", headers=e.h),
              e.client.post("/v1/github/scan", headers=e.h, json={"installation": "777", "repo": "acme/app", "branch": "main"})):
        assert r.status_code == 503 and r.json()["error"]["code"] == "not_configured"


def test_lists_repositories_and_branches_dropping_malformed_entries(tmp_path, keypair):
    e, fake = env(tmp_path, keypair)
    link(e)
    repos = e.client.get("/v1/github/repositories?installation=777", headers=e.h).json()["items"]
    assert repos == [{"name": "acme/app", "defaultBranch": "main", "private": True}]
    br = e.client.get("/v1/github/branches?installation=777&repo=acme/app", headers=e.h).json()["items"]
    assert [b["name"] for b in br] == ["main", "dev"]


def test_scan_resolves_the_commit_from_github_and_publishes_a_check_run(tmp_path, keypair):
    e, fake = env(tmp_path, keypair)
    link(e)
    r = e.client.post("/v1/github/scan", headers=e.h, json={"installation": "777", "repo": "acme/app", "branch": "main"})
    assert r.status_code == 202 and r.json()["commitSha"] == SHA
    e.runner.drain()
    (c,) = fake.checks.values()
    assert c["create"]["head_sha"] == SHA and c["final"]["status"] == "completed"
    again = e.client.post("/v1/github/scan", headers=e.h, json={"installation": "777", "repo": "acme/app", "branch": "main"})
    assert again.json()["deduplicated"] is True  # same commit is not rescanned twice


def test_client_cannot_supply_a_commit_sha(tmp_path, keypair):
    e, _ = env(tmp_path, keypair)
    link(e)
    r = e.client.post("/v1/github/scan", headers=e.h, json={"installation": "777", "repo": "acme/app", "branch": "main", "sha": "d" * 40})
    assert r.status_code == 422


def test_unknown_branch_bad_repo_and_foreign_installation(tmp_path, keypair):
    e, _ = env(tmp_path, keypair)
    link(e)
    assert e.client.post("/v1/github/scan", headers=e.h, json={"installation": "777", "repo": "acme/app", "branch": "nope"}).status_code == 404
    assert e.client.post("/v1/github/scan", headers=e.h, json={"installation": "777", "repo": "../etc", "branch": "main"}).status_code == 422
    # an installation that was never linked to this organization looks the same as one that does not exist
    assert e.client.get("/v1/github/repositories?installation=999", headers=e.h).status_code == 404


def test_viewers_cannot_browse_or_scan(tmp_path, keypair):
    e, _ = env(tmp_path, keypair)
    link(e)
    e.add_user(e.org["id"], "v@acme.test", "viewer")
    vh = e.login("v@acme.test")
    assert e.client.get("/v1/github/repositories?installation=777", headers=vh).status_code == 403
    assert e.client.post("/v1/github/scan", headers=vh, json={"installation": "777", "repo": "acme/app", "branch": "main"}).status_code == 403
