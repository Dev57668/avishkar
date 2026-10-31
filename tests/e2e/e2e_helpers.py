ADMIN = ("admin@e2e.test", "e2e-admin-password-1")
DEMO_PW = "e2e-demo-viewer-1"


def guest(pg):
    pg.get_by_role("button", name="Continue as guest").click()
    pg.wait_for_selector("text=Repositories")
