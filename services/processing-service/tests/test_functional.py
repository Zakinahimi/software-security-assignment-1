from conftest import auth_header, make_job_token


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["exportkit_version"]


def test_export_job_runs_and_returns_formatted_content(client, resource_service):
    token = make_job_token("alice", resource=10)
    resp = client.post(
        "/jobs/export",
        json={"dataset_id": 10, "format": "csv"},
        headers=auth_header(token),
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["dataset_id"] == 10
    assert "alice-lab-results" in body["content"]
    assert len(resource_service) == 1  # one export was saved to the Resource Service


def test_missing_token_rejected(client):
    resp = client.post("/jobs/export", json={"dataset_id": 10, "format": "csv"})
    assert resp.status_code == 401


def test_unsupported_format_rejected(client):
    token = make_job_token("alice", resource=10)
    resp = client.post(
        "/jobs/export",
        json={"dataset_id": 10, "format": "xml"},
        headers=auth_header(token),
    )
    assert resp.status_code == 400
