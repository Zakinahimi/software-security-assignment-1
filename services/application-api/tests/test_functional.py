from conftest import login_header


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_login_success(client):
    resp = client.post("/auth/login", json={"username": "alice", "password": "Alice#Pass1"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["role"] == "user"
    assert "access_token" in body


def test_login_wrong_password(client):
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/auth/login", json={"username": "mallory", "password": "x"})
    assert resp.status_code == 401


def test_list_datasets_mints_read_scoped_downstream_token(client, downstream):
    headers = login_header(client, "alice", "Alice#Pass1")
    resp = client.get("/datasets", headers=headers)
    assert resp.status_code == 200
    assert len(downstream) == 1
    call = downstream[0]
    assert call["url"].endswith("/datasets")
    sent_auth = call["headers"]["Authorization"]
    assert sent_auth.startswith("Bearer ")


def test_export_mints_processing_service_token_bound_to_the_requested_dataset(client, downstream):
    headers = login_header(client, "alice", "Alice#Pass1")
    resp = client.post("/datasets/7/export", json={"format": "csv"}, headers=headers)
    assert resp.status_code == 200
    call = downstream[0]
    assert call["url"].endswith("/jobs/export")
    assert call["json"]["dataset_id"] == 7


def test_delete_requires_admin_role(client, downstream):
    headers = login_header(client, "alice", "Alice#Pass1")
    resp = client.delete("/datasets/1", headers=headers)
    assert resp.status_code == 403
    assert downstream == []  # never even reached the Resource Service


def test_admin_can_delete(client, downstream):
    headers = login_header(client, "admin", "Admin#Pass1")
    resp = client.delete("/datasets/1", headers=headers)
    assert resp.status_code == 200
    assert len(downstream) == 1
