"""Application API — authenticates users and coordinates requests across the other two
components. Owns no protected data itself; every dataset/export lives in the Resource Service.
"""

from __future__ import annotations

import os

import requests
import security
import users
from flask import Flask, g, jsonify, request

app = Flask(__name__)

RESOURCE_SERVICE_URL = os.environ.get("RESOURCE_SERVICE_URL", "http://localhost:5002")
PROCESSING_SERVICE_URL = os.environ.get("PROCESSING_SERVICE_URL", "http://localhost:5003")
HTTP_TIMEOUT = 10


def _forward(resp: requests.Response):
    """Relay a downstream JSON response + status code unchanged."""
    try:
        body = resp.json()
    except ValueError:
        body = {"error": "downstream service returned a non-JSON response"}
    return jsonify(body), resp.status_code


@app.get("/health")
def health():
    return jsonify(status="ok", service="application-api")


@app.post("/auth/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return jsonify(error="username and password are required"), 400

    role = users.verify_password(username, password)
    if role is None:
        # Fail-safe default: unknown user and wrong password look identical to the caller.
        return jsonify(error="invalid credentials"), 401

    token = security.mint_session_token(sub=username, role=role)
    return jsonify(access_token=token, token_type="Bearer", role=role, expires_in=security.SESSION_TTL_SECONDS)


@app.get("/datasets")
@security.require_session_auth
def list_datasets():
    want_all = request.args.get("all") == "true" and g.user["role"] == "admin"
    scope = ["dataset:read", "dataset:admin"] if want_all else ["dataset:read"]
    token = security.mint_service_token(g.user["sub"], g.user["role"], "resource-service", scope)
    resp = requests.get(
        f"{RESOURCE_SERVICE_URL}/datasets",
        params={"all": "true"} if want_all else {},
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    return _forward(resp)


@app.post("/datasets")
@security.require_session_auth
def upload_dataset():
    body = request.get_json(force=True, silent=True) or {}
    token = security.mint_service_token(g.user["sub"], g.user["role"], "resource-service", ["dataset:write"])
    resp = requests.post(
        f"{RESOURCE_SERVICE_URL}/datasets",
        json={"name": body.get("name"), "payload": body.get("payload")},
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    return _forward(resp)


@app.get("/datasets/<int:dataset_id>")
@security.require_session_auth
def get_dataset(dataset_id: int):
    token = security.mint_service_token(
        g.user["sub"], g.user["role"], "resource-service", ["dataset:read"], resource=dataset_id
    )
    resp = requests.get(
        f"{RESOURCE_SERVICE_URL}/datasets/{dataset_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    return _forward(resp)


@app.delete("/datasets/<int:dataset_id>")
@security.require_session_auth
@security.require_admin
def delete_dataset(dataset_id: int):
    token = security.mint_service_token(
        g.user["sub"], g.user["role"], "resource-service", ["dataset:admin"], resource=dataset_id
    )
    resp = requests.delete(
        f"{RESOURCE_SERVICE_URL}/datasets/{dataset_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    return _forward(resp)


@app.post("/datasets/<int:dataset_id>/export")
@security.require_session_auth
def export_dataset(dataset_id: int):
    """F3 — the functionality that touches all three components. The dataset id in the URL (part
    of the request the Application API itself authenticated) is what gets bound into the token's
    `resource` claim; the Processing Service is supposed to treat that claim, not any job
    parameter in the request body, as the authoritative answer to "which dataset am I allowed to
    touch for this call"."""
    body = request.get_json(force=True, silent=True) or {}
    fmt = body.get("format", "csv")

    token = security.mint_service_token(
        g.user["sub"], g.user["role"], "processing-service", ["job:export"], resource=dataset_id
    )
    resp = requests.post(
        f"{PROCESSING_SERVICE_URL}/jobs/export",
        json={"dataset_id": dataset_id, "format": fmt},
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    return _forward(resp)


@app.get("/exports/<int:export_id>")
@security.require_session_auth
def get_export(export_id: int):
    token = security.mint_service_token(g.user["sub"], g.user["role"], "resource-service", ["dataset:read"])
    resp = requests.get(
        f"{RESOURCE_SERVICE_URL}/exports/{export_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    return _forward(resp)


if __name__ == "__main__":
    users.seed(reset=True)
    app.run(host="0.0.0.0", port=5001)
