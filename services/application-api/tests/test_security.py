"""Security test for the planted V2 vulnerability (CWE-347) in the Application API.

At THIS commit the test asserts the forgery SUCCEEDS: an attacker who knows nothing about
RESEARCH_WORKSPACE_JWT_SECRET can still get the Application API to treat them as `admin`, and —
critically — the Application API then mints a genuinely, correctly-signed downstream service
token carrying that forged authority, which a properly-verifying Resource Service would accept.
A later commit fixes security.decode_session_token_UNSAFE() and this test is rewritten to assert
the forgery is rejected.
"""

import jwt
import security
from conftest import forge_unsigned_session_token


def test_V2_forged_admin_session_token_is_accepted(client, downstream):
    forged = forge_unsigned_session_token(sub="mallory", role="admin")

    resp = client.get("/datasets?all=true", headers={"Authorization": f"Bearer {forged}"})

    assert resp.status_code != 401, "expected the forged token to currently be accepted (planted vulnerability)"


def test_V2_forged_token_escalates_to_a_genuinely_signed_downstream_admin_token(client, downstream):
    forged = forge_unsigned_session_token(sub="mallory", role="admin")

    resp = client.delete("/datasets/1", headers={"Authorization": f"Bearer {forged}"})

    assert resp.status_code == 200, "forged 'admin' claim currently passes require_admin (planted vulnerability)"
    assert len(downstream) == 1
    sent_token = downstream[0]["headers"]["Authorization"].removeprefix("Bearer ")
    # The token the Application API sent to the Resource Service is REAL — signed with the real
    # shared secret — even though the identity behind it was never actually authenticated. A
    # Resource Service that verifies signatures correctly (as ours does) would still accept this.
    claims = jwt.decode(sent_token, security.JWT_SECRET, algorithms=["HS256"], audience="resource-service")
    assert claims["sub"] == "mallory"
    assert "dataset:admin" in claims["scope"]
