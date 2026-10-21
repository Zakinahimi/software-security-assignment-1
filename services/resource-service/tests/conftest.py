import os
import sys
import time

import jwt
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as resource_app  # noqa: E402
import db  # noqa: E402
import security  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("RESOURCE_DB_PATH", str(tmp_path / "resource_test.db"))
    db.DB_PATH = str(tmp_path / "resource_test.db")
    db.seed(reset=True)
    resource_app.app.config["TESTING"] = True
    with resource_app.app.test_client() as c:
        yield c


def make_token(sub: str, role: str = "user", scope=None, aud=None, resource=None, ttl=60, secret=None):
    scope = scope if scope is not None else ["dataset:read", "dataset:write", "dataset:export"]
    aud = aud if aud is not None else ["resource-service"]
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": role,
        "aud": aud,
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
    }
    if resource is not None:
        claims["resource"] = resource
    return jwt.encode(claims, secret or security.JWT_SECRET, algorithm="HS256")


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
