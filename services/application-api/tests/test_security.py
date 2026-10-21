"""Security regression test for the Application API's V2 vulnerability (CWE-347).

This scenario previously demonstrated a successful privilege-escalation forgery (see the version
of this file at commit 64bab5e, where the vulnerability was planted:
`git show 64bab5e:services/application-api/tests/test_security.py`). It is now fixed in
security.py and the assertions below are inverted to assert the forgery is rejected, turning this
into a permanent regression guard.
"""

from conftest import forge_unsigned_session_token


def test_V2_forged_admin_session_token_is_rejected(client, downstream):
    forged = forge_unsigned_session_token(sub="mallory", role="admin")

    resp = client.get("/datasets?all=true", headers={"Authorization": f"Bearer {forged}"})

    assert resp.status_code == 401
    assert downstream == [], "the Application API must reject the forged token before calling any downstream service"


def test_V2_forged_token_no_longer_escalates_to_a_downstream_admin_token(client, downstream):
    forged = forge_unsigned_session_token(sub="mallory", role="admin")

    resp = client.delete("/datasets/1", headers={"Authorization": f"Bearer {forged}"})

    assert resp.status_code == 401
    assert downstream == []


def test_a_genuinely_issued_admin_token_still_works(client, downstream):
    """Regression guard: the fix must not have broken the legitimate case — a session token the
    Application API itself issued at login must still be accepted."""
    login_resp = client.post("/auth/login", json={"username": "admin", "password": "Admin#Pass1"})
    real_token = login_resp.get_json()["access_token"]

    resp = client.delete("/datasets/1", headers={"Authorization": f"Bearer {real_token}"})

    assert resp.status_code == 200
    assert len(downstream) == 1
