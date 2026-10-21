"""Cross-service integration tests — run against three REAL, networked instances of the three
components (either `scripts/run_dev.sh` locally, or the docker-compose stack Jenkins/`docker
compose up` brings up). Unlike the per-service unit tests under services/*/tests, nothing here is
mocked.
"""

from __future__ import annotations

import os
import time

import jwt
import pytest
import requests

APPLICATION_API_URL = os.environ.get("APPLICATION_API_URL", "http://localhost:5001")
RESOURCE_SERVICE_URL = os.environ.get("RESOURCE_SERVICE_URL", "http://localhost:5002")
PROCESSING_SERVICE_URL = os.environ.get("PROCESSING_SERVICE_URL", "http://localhost:5003")
JWT_SECRET = os.environ.get("RESEARCH_WORKSPACE_JWT_SECRET", "dev-only-shared-secret-change-me-32bytes!!")

SEED_PASSWORDS = {"alice": "Alice#Pass1", "bob": "Bob#Pass1", "admin": "Admin#Pass1"}


def _wait_until_healthy(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            resp = requests.get(f"{url}/health", timeout=2)
            if resp.status_code == 200:
                return
        except requests.RequestException as exc:  # noqa: PERF203
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError(f"{url}/health never became healthy (last error: {last_error})")


@pytest.fixture(scope="session", autouse=True)
def services_are_up():
    for url in (APPLICATION_API_URL, RESOURCE_SERVICE_URL, PROCESSING_SERVICE_URL):
        _wait_until_healthy(url)


def login(username: str, password: str | None = None) -> str:
    password = password or SEED_PASSWORDS[username]
    resp = requests.post(f"{APPLICATION_API_URL}/auth/login", json={"username": username, "password": password})
    resp.raise_for_status()
    return resp.json()["access_token"]


def auth_header(username: str) -> dict:
    return {"Authorization": f"Bearer {login(username)}"}


def mint_raw_token(sub: str, role: str, aud: list[str], scope: list[str], resource=None, ttl=60) -> str:
    """For tests that talk to the Resource Service / Processing Service directly, bypassing the
    Application API — used by the authorization tests that specifically check what each service
    enforces on its own, not just what the Application API's routing happens to prevent."""
    now = int(time.time())
    claims = {"sub": sub, "role": role, "aud": aud, "scope": scope, "iat": now, "exp": now + ttl}
    if resource is not None:
        claims["resource"] = resource
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")
