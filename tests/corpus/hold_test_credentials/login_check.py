def test_login(client):
    password = "test-password-123"
    resp = client.post("/login", data={"user": "alice", "password": password})
    assert resp.status_code == 200
