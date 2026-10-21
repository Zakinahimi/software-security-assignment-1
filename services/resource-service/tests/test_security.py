"""Security regression tests for the Resource Service's V1 and V3 vulnerabilities.

These scenarios previously demonstrated successful exploits (see the version of this file at
commit d8e9e2a, where the vulnerabilities were planted: `git show d8e9e2a:services/resource-service/tests/test_security.py`).
Both bugs are now fixed in app.py/db.py and the assertions below are inverted to assert the
secure behaviour, turning these into permanent regression guards.
"""

from conftest import auth_header, make_token


def test_V1_idor_is_fixed_cross_owner_read_is_rejected(client):
    """CWE-639, fixed. bob holds a perfectly legitimate, correctly-signed, correctly-scoped token
    for HIMSELF; he must not be able to read alice's dataset (id=1, seeded as alice's) by id."""
    bob_token = make_token("bob", role="user", scope=["dataset:read"])

    resp = client.get("/datasets/1", headers=auth_header(bob_token))

    assert resp.status_code == 403


def test_V1_owner_can_still_read_their_own_dataset(client):
    """Regression guard: the fix must not have broken the legitimate case."""
    alice_token = make_token("alice", role="user", scope=["dataset:read"])

    resp = client.get("/datasets/1", headers=auth_header(alice_token))

    assert resp.status_code == 200
    assert resp.get_json()["owner"] == "alice"


def test_V1_admin_can_still_read_any_dataset(client):
    admin_token = make_token("admin", role="admin", scope=["dataset:read"])

    resp = client.get("/datasets/1", headers=auth_header(admin_token))

    assert resp.status_code == 200


def test_V3_sql_injection_no_longer_bypasses_owner_filter(client):
    """CWE-89, fixed. The same payload that previously turned the owner restriction into a
    tautology must no longer return any other user's rows."""
    bob_token = make_token("bob", role="user", scope=["dataset:read"])
    payload = "' OR '1'='1' -- "

    resp = client.get("/datasets/search", query_string={"q": payload}, headers=auth_header(bob_token))

    assert resp.status_code == 200
    owners = {row["owner"] for row in resp.get_json()}
    assert owners <= {"bob"}, "the injection payload must not leak alice's rows to bob anymore"


def test_V3_sql_injection_payload_is_treated_as_literal_text(client):
    """The fixed query doesn't error out on quote characters either — they're just literal text
    to match against, as they should be."""
    bob_token = make_token("bob", role="user", scope=["dataset:read"])
    payload = "' OR '1'='1' -- "

    resp = client.get("/datasets/search", query_string={"q": payload}, headers=auth_header(bob_token))

    assert resp.status_code == 200
    assert resp.get_json() == []  # no dataset name literally contains that payload text


def test_search_without_payload_still_returns_only_own_rows(client):
    bob_token = make_token("bob", role="user", scope=["dataset:read"])

    resp = client.get("/datasets/search", query_string={"q": "survey"}, headers=auth_header(bob_token))

    assert resp.status_code == 200
    owners = {row["owner"] for row in resp.get_json()}
    assert owners == {"bob"}
