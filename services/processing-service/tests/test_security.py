"""Security test for the planted V4 composition vulnerability (CWE-441 Confused Deputy).

At THIS commit the test asserts the exploit SUCCEEDS. This vulnerability cannot exist in a
single-process version of this application: it requires (a) a service that holds broader
authority than the end user it is acting for, to do its legitimate job, and (b) a second service
(the Application API) whose authorization decision is encoded in a token the first service is
supposed to, but does not, actually check against the job's own parameters. See
docs/THREAT_MODEL.md for the full write-up. A later commit adds the missing check in app.py and
this test is rewritten to assert the exploit now fails.
"""

from conftest import auth_header, make_job_token


def test_V4_confused_deputy_exports_a_dataset_the_token_did_not_authorize(client, resource_service):
    """alice holds a perfectly legitimate, correctly-signed job:export token for HER OWN
    dataset (resource=10). She calls the Processing Service directly (not through the Application
    API) and simply puts bob's dataset id (20) in the request body instead."""
    alice_token_for_her_own_dataset = make_job_token("alice", resource=10)

    resp = client.post(
        "/jobs/export",
        json={"dataset_id": 20, "format": "csv"},  # bob's dataset, not the one the token authorized
        headers=auth_header(alice_token_for_her_own_dataset),
    )

    assert resp.status_code == 201, "expected the confused-deputy export to currently succeed (planted vulnerability)"
    body = resp.get_json()
    assert body["dataset_id"] == 20
    assert "bob-survey-data" in body["content"], "alice received bob's data despite her token only authorizing dataset 10"
