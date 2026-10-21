"""End-to-end functional tests (F1-F4) against the three real, running services."""

import requests
from conftest import APPLICATION_API_URL, auth_header


def test_f1_upload_dataset():
    resp = requests.post(
        f"{APPLICATION_API_URL}/datasets",
        json={"name": "e2e-upload", "payload": {"k": "v"}},
        headers=auth_header("alice"),
    )
    assert resp.status_code == 201
    assert resp.json()["owner"] == "alice"


def test_f2_list_own_datasets_only():
    requests.post(
        f"{APPLICATION_API_URL}/datasets",
        json={"name": "alice-only-e2e", "payload": {}},
        headers=auth_header("alice"),
    )
    resp = requests.get(f"{APPLICATION_API_URL}/datasets", headers=auth_header("bob"))
    assert resp.status_code == 200
    names = {d["name"] for d in resp.json()}
    assert "alice-only-e2e" not in names


def test_f3_export_spans_all_three_components():
    create = requests.post(
        f"{APPLICATION_API_URL}/datasets",
        json={"name": "export-me-e2e", "payload": {"a": 1}},
        headers=auth_header("alice"),
    )
    dataset_id = create.json()["id"]

    export = requests.post(
        f"{APPLICATION_API_URL}/datasets/{dataset_id}/export",
        json={"format": "json"},
        headers=auth_header("alice"),
    )
    assert export.status_code == 201
    body = export.json()
    assert body["dataset_id"] == dataset_id
    assert "export-me-e2e" in body["content"]

    # retrievable afterwards via the Application API -> Resource Service path too
    fetched = requests.get(f"{APPLICATION_API_URL}/exports/{body['export_id']}", headers=auth_header("alice"))
    assert fetched.status_code == 200


def test_f4_admin_sees_and_can_delete_any_dataset():
    create = requests.post(
        f"{APPLICATION_API_URL}/datasets",
        json={"name": "admin-target-e2e", "payload": {}},
        headers=auth_header("bob"),
    )
    dataset_id = create.json()["id"]

    admin_list = requests.get(
        f"{APPLICATION_API_URL}/datasets", params={"all": "true"}, headers=auth_header("admin")
    )
    assert any(d["id"] == dataset_id for d in admin_list.json())

    delete = requests.delete(f"{APPLICATION_API_URL}/datasets/{dataset_id}", headers=auth_header("admin"))
    assert delete.status_code == 200
