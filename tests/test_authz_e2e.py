"""End-to-end authorization regression tests (V1-V4, fixed) against the three real, running
services — the same scenarios documented in docs/THREAT_MODEL.md, exercised over the actual
network boundaries rather than through Flask's test client, and in one case (V4) deliberately
bypassing the Application API entirely to hit the Processing Service directly, the way the
original exploit did.
"""

import requests
from conftest import (
    APPLICATION_API_URL,
    PROCESSING_SERVICE_URL,
    RESOURCE_SERVICE_URL,
    auth_header,
    login,
    mint_raw_token,
)


def test_v1_idor_fixed_cannot_read_another_users_dataset():
    create = requests.post(
        f"{APPLICATION_API_URL}/datasets",
        json={"name": "alice-private-e2e", "payload": {}},
        headers=auth_header("alice"),
    )
    dataset_id = create.json()["id"]

    resp = requests.get(f"{APPLICATION_API_URL}/datasets/{dataset_id}", headers=auth_header("bob"))
    assert resp.status_code == 403


def test_v2_forged_admin_token_rejected_by_application_api():
    import jwt as pyjwt
    import time

    now = int(time.time())
    forged = pyjwt.encode(
        {"sub": "mallory", "role": "admin", "aud": ["application-api"], "scope": ["session"], "iat": now, "exp": now + 1800},
        "attacker-does-not-know-the-real-secret",
        algorithm="HS256",
    )
    resp = requests.get(
        f"{APPLICATION_API_URL}/datasets", params={"all": "true"}, headers={"Authorization": f"Bearer {forged}"}
    )
    assert resp.status_code == 401


def test_v3_sql_injection_no_longer_bypasses_owner_filter_on_resource_service():
    # Talk to the Resource Service directly with a correctly-signed token for bob, the way the
    # Application API would mint one — exercising the fix at the layer where it actually lives.
    token = mint_raw_token("bob", "user", ["resource-service"], ["dataset:read"])
    resp = requests.get(
        f"{RESOURCE_SERVICE_URL}/datasets/search",
        params={"q": "' OR '1'='1' -- "},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert all(row["owner"] == "bob" for row in resp.json())


def test_v4_confused_deputy_fixed_direct_processing_service_call_rejected():
    """alice creates her own dataset (gets a legitimate, Application-API-issued export token
    scoped to it), then calls the Processing Service DIRECTLY — not through the Application API —
    asking it to export someone else's dataset instead. This is exactly the exploit path
    documented for V4; it must now be rejected."""
    create = requests.post(
        f"{APPLICATION_API_URL}/datasets",
        json={"name": "alice-for-v4-e2e", "payload": {}},
        headers=auth_header("alice"),
    )
    alices_dataset_id = create.json()["id"]

    other = requests.post(
        f"{APPLICATION_API_URL}/datasets",
        json={"name": "bob-for-v4-e2e", "payload": {}},
        headers=auth_header("bob"),
    )
    bobs_dataset_id = other.json()["id"]

    # A token the Application API would genuinely mint for alice's own export job.
    alice_job_token = mint_raw_token(
        "alice", "user", ["processing-service"], ["job:export"], resource=alices_dataset_id
    )

    resp = requests.post(
        f"{PROCESSING_SERVICE_URL}/jobs/export",
        json={"dataset_id": bobs_dataset_id, "format": "csv"},  # tampered: not her dataset
        headers={"Authorization": f"Bearer {alice_job_token}"},
    )
    assert resp.status_code == 403
