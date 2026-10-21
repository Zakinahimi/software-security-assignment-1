import os
import sys
import time

import jwt
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as proc_app  # noqa: E402
import security  # noqa: E402

RESOURCE_DATASETS = {
    10: {"id": 10, "owner": "alice", "name": "alice-lab-results", "payload": "{}"},
    20: {"id": 20, "owner": "bob", "name": "bob-survey-data", "payload": "{}"},
}


class FakeResponse:
    def __init__(self, json_body, status_code=200):
        self._json_body = json_body
        self.status_code = status_code

    def json(self):
        return self._json_body


@pytest.fixture()
def client():
    proc_app.app.config["TESTING"] = True
    with proc_app.app.test_client() as c:
        yield c


@pytest.fixture()
def resource_service(monkeypatch):
    """Stub the Resource Service: GET returns the dataset if its id exists (no ownership check
    simulated here — Resource Service's own tests cover that independently); POST /exports
    records what was saved."""
    saved_exports = []

    def fake_get(url, headers=None, timeout=None):
        dataset_id = int(url.rsplit("/", 1)[-1])
        record = RESOURCE_DATASETS.get(dataset_id)
        if record is None:
            return FakeResponse({"error": "not found"}, 404)
        return FakeResponse(record, 200)

    def fake_post(url, json=None, headers=None, timeout=None):
        if url.endswith("/exports"):
            export_record = {"id": len(saved_exports) + 1, **json}
            saved_exports.append(export_record)
            return FakeResponse(export_record, 201)
        return FakeResponse({"error": "unexpected call"}, 500)

    monkeypatch.setattr(proc_app.requests, "get", fake_get)
    monkeypatch.setattr(proc_app.requests, "post", fake_post)
    return saved_exports


def make_job_token(sub: str, role: str = "user", resource=None, scope=None, ttl=60):
    scope = scope if scope is not None else ["job:export"]
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": role,
        "aud": ["processing-service"],
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
    }
    if resource is not None:
        claims["resource"] = resource
    return jwt.encode(claims, security.JWT_SECRET, algorithm="HS256")


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
