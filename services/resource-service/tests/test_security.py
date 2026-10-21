"""Security tests for the Resource Service's planted vulnerabilities (V1, V3).

At THIS commit these tests assert that the exploits SUCCEED — this is the "investigation" record
the SSDLC plan calls for: automated proof that the planted bug is real and reachable over the
service's actual HTTP API with a validly-signed, correctly-scoped token (i.e. the bug is an
authorization flaw, not an authentication flaw). See docs/THREAT_MODEL.md for the write-up.

A later commit fixes both bugs in db.py/app.py and rewrites the assertions in this same file to
prove the fix (regression tests). Compare this file across the two commits (or `git show`) as
before/after evidence.
"""

from conftest import auth_header, make_token


def test_V1_idor_any_authenticated_user_can_read_another_users_dataset(client):
    """CWE-639. bob holds a perfectly legitimate, correctly-signed, correctly-scoped token for
    HIMSELF, yet can read alice's dataset (id=1, seeded as alice's) just by requesting it by id."""
    bob_token = make_token("bob", role="user", scope=["dataset:read"])

    resp = client.get("/datasets/1", headers=auth_header(bob_token))

    assert resp.status_code == 200, "expected the IDOR to currently succeed (planted vulnerability)"
    body = resp.get_json()
    assert body["owner"] == "alice", "bob was able to read a dataset he does not own"


def test_V3_sql_injection_bypasses_owner_filter_in_search(client):
    """CWE-89. bob searches with a crafted `q` that turns the WHERE clause's owner restriction
    into a tautology, returning alice's and bob's datasets through an endpoint that is only
    supposed to return the caller's own."""
    bob_token = make_token("bob", role="user", scope=["dataset:read"])
    payload = "' OR '1'='1' -- "

    resp = client.get("/datasets/search", query_string={"q": payload}, headers=auth_header(bob_token))

    assert resp.status_code == 200
    owners = {row["owner"] for row in resp.get_json()}
    assert "alice" in owners, "expected the injection to currently leak alice's rows to bob (planted vulnerability)"


def test_V3_sql_injection_without_payload_only_returns_own_rows(client):
    """Sanity check: a normal, non-malicious query is still owner-scoped — the bug is specific to
    injection payloads, not a blanket lack of filtering."""
    bob_token = make_token("bob", role="user", scope=["dataset:read"])

    resp = client.get("/datasets/search?q=survey", headers=auth_header(bob_token))

    assert resp.status_code == 200
    owners = {row["owner"] for row in resp.get_json()}
    assert owners == {"bob"}
