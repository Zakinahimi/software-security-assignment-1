"""F1/F2 functional tests for the Resource Service, independent of the vulnerability tests."""

from conftest import auth_header, make_token


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_create_and_list_own_datasets(client):
    token = make_token("alice", role="user")
    resp = client.post(
        "/datasets",
        json={"name": "new-dataset", "payload": {"x": 1}},
        headers=auth_header(token),
    )
    assert resp.status_code == 201
    created = resp.get_json()
    assert created["owner"] == "alice"

    resp = client.get("/datasets", headers=auth_header(token))
    assert resp.status_code == 200
    names = [d["name"] for d in resp.get_json()]
    assert "new-dataset" in names
    # alice must not see bob's seeded datasets in her own listing
    assert all(d["owner"] == "alice" for d in resp.get_json())


def test_create_dataset_owner_is_forced_from_token_not_body(client):
    token = make_token("alice", role="user")
    resp = client.post(
        "/datasets",
        json={"name": "spoof-attempt", "payload": {}, "owner": "bob"},
        headers=auth_header(token),
    )
    assert resp.status_code == 201
    assert resp.get_json()["owner"] == "alice"  # body's "owner" field is ignored


def test_missing_token_rejected(client):
    resp = client.get("/datasets")
    assert resp.status_code == 401


def test_admin_can_list_all_with_admin_scope(client):
    token = make_token("admin", role="admin", scope=["dataset:read", "dataset:admin"])
    resp = client.get("/datasets?all=true", headers=auth_header(token))
    assert resp.status_code == 200
    owners = {d["owner"] for d in resp.get_json()}
    assert "alice" in owners and "bob" in owners


def test_admin_delete_requires_admin_scope(client):
    user_token = make_token("alice", role="user", scope=["dataset:read", "dataset:write"])
    resp = client.delete("/datasets/1", headers=auth_header(user_token))
    assert resp.status_code == 403

    admin_token = make_token("admin", role="admin", scope=["dataset:admin"])
    resp = client.delete("/datasets/1", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_token_bound_to_one_dataset_cannot_read_another(client):
    """Authority is bound to ONE resource: alice owns datasets 1 and 2, but a token whose
    `resource` claim is 1 must not authorize reading dataset 2."""
    token = make_token("alice", role="user", scope=["dataset:read"], resource=1)
    assert client.get("/datasets/1", headers=auth_header(token)).status_code == 200
    assert client.get("/datasets/2", headers=auth_header(token)).status_code == 403


def test_token_bound_to_one_dataset_cannot_delete_another(client):
    token = make_token("admin", role="admin", scope=["dataset:admin"], resource=1)
    assert client.delete("/datasets/2", headers=auth_header(token)).status_code == 403
    assert client.delete("/datasets/1", headers=auth_header(token)).status_code == 200


def test_token_bound_to_one_dataset_cannot_save_an_export_for_another(client):
    token = make_token("alice", role="user", scope=["dataset:export"], resource=1)
    body = {"dataset_id": 2, "format": "csv", "content": "x"}
    assert client.post("/exports", json=body, headers=auth_header(token)).status_code == 403
    body["dataset_id"] = 1
    assert client.post("/exports", json=body, headers=auth_header(token)).status_code == 201
