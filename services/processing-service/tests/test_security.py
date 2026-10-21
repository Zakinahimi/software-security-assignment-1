"""Security regression test for the Processing Service's V4 composition vulnerability (CWE-441).

This scenario previously demonstrated a successful confused-deputy export (see the version of
this file at commit 9a3fc5b, where the vulnerability was planted:
`git show 9a3fc5b:services/processing-service/tests/test_security.py`). It is now fixed in
app.py and the assertions below are inverted to assert the exploit is rejected, turning this into
a permanent regression guard.
"""

from conftest import auth_header, make_job_token


def test_V4_confused_deputy_export_is_now_rejected(client, resource_service):
    """alice holds a legitimate, correctly-signed job:export token for her OWN dataset
    (resource=10). Asking this service to export bob's dataset (20) instead must now fail."""
    alice_token_for_her_own_dataset = make_job_token("alice", resource=10)

    resp = client.post(
        "/jobs/export",
        json={"dataset_id": 20, "format": "csv"},
        headers=auth_header(alice_token_for_her_own_dataset),
    )

    assert resp.status_code == 403
    assert resource_service == [], "the Resource Service must never even be called for an unauthorized dataset"


def test_V4_matching_dataset_id_still_works(client, resource_service):
    """Regression guard: the fix must not have broken the legitimate case — a token whose
    resource claim matches the job's dataset_id must still succeed."""
    alice_token_for_her_own_dataset = make_job_token("alice", resource=10)

    resp = client.post(
        "/jobs/export",
        json={"dataset_id": 10, "format": "csv"},
        headers=auth_header(alice_token_for_her_own_dataset),
    )

    assert resp.status_code == 201
    assert len(resource_service) == 1


def test_V4_token_without_a_resource_claim_is_rejected(client, resource_service):
    """Fail-safe default: a token minted without a resource claim at all must not be treated as
    authorizing every dataset."""
    token_missing_resource_claim = make_job_token("alice", resource=None)

    resp = client.post(
        "/jobs/export",
        json={"dataset_id": 10, "format": "csv"},
        headers=auth_header(token_missing_resource_claim),
    )

    assert resp.status_code == 403
    assert resource_service == []
