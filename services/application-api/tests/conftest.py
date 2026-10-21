import os
import sys
import time

import jwt
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as api_app  # noqa: E402
import security  # noqa: E402
import users  # noqa: E402


class FakeResponse:
    """Stand-in for requests.Response, used to isolate Application API tests from the two
    downstream services (those are tested against their own real HTTP APIs in their own test
    suites and in tests/ at the repo root)."""

    def __init__(self, json_body, status_code=200):
        self._json_body = json_body
        self.status_code = status_code

    def json(self):
        return self._json_body


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("APPLICATION_API_DB_PATH", str(tmp_path / "users_test.db"))
    users.DB_PATH = str(tmp_path / "users_test.db")
    users.seed(reset=True)
    api_app.app.config["TESTING"] = True
    with api_app.app.test_client() as c:
        yield c


@pytest.fixture()
def downstream(monkeypatch):
    """Capture + stub out every outbound call the Application API makes, recording the
    Authorization header and JSON body it sent so tests can assert on the *authority* the
    Application API minted, not just the final response."""
    calls = []

    def _record(method):
        def _fn(url, headers=None, json=None, params=None, timeout=None):
            calls.append({"method": method, "url": url, "headers": headers or {}, "json": json, "params": params})
            return FakeResponse({"ok": True, "echo": json}, 200)

        return _fn

    monkeypatch.setattr(api_app.requests, "get", _record("GET"))
    monkeypatch.setattr(api_app.requests, "post", _record("POST"))
    monkeypatch.setattr(api_app.requests, "delete", _record("DELETE"))
    return calls


def login_header(client, username: str, password: str) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    token = resp.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def forge_unsigned_session_token(sub: str, role: str) -> str:
    """Builds a session-token-shaped JWT and signs it with a key the server does NOT know,
    simulating an attacker with no knowledge of RESEARCH_WORKSPACE_JWT_SECRET."""
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": role,
        "aud": ["application-api"],
        "scope": ["session"],
        "iat": now,
        "exp": now + 1800,
    }
    return jwt.encode(claims, "attacker-does-not-know-the-real-secret", algorithm="HS256")
