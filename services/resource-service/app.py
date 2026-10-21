"""Resource Service — owns dataset records and export results.

Security responsibility (per the brief's architecture table): enforce permissions for each
resource and action, including requests arriving from other trusted services (Processing
Service), not just requests arriving straight from a user via the Application API.
"""

from __future__ import annotations

import db
import security
from flask import Flask, g, jsonify, request

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok", service="resource-service")


@app.post("/datasets")
@security.require_scope("dataset:write")
def create_dataset():
    body = request.get_json(force=True, silent=True) or {}
    name = body.get("name")
    payload = body.get("payload")
    if not name or payload is None:
        return jsonify(error="name and payload are required"), 400
    # Fail-safe default / least privilege: the owner is ALWAYS the authenticated caller's
    # identity from the verified token, never a client-supplied field — a client cannot create a
    # dataset "as" someone else no matter what the request body says.
    record = db.create_dataset(owner=g.user["sub"], name=name, payload=str(payload))
    return jsonify(record), 201


@app.get("/datasets")
@security.require_scope("dataset:read", "dataset:admin")
def list_datasets():
    is_admin_listing = "dataset:admin" in (g.user.get("scope") or []) and request.args.get("all") == "true"
    if is_admin_listing:
        records = db.list_datasets(owner=None)
    else:
        records = db.list_datasets(owner=g.user["sub"])
    return jsonify(records)


@app.get("/datasets/search")
@security.require_scope("dataset:read")
def search_datasets():
    query = request.args.get("q", "")
    # V3 (SQL injection) lives in db.search_datasets — see that function's docstring.
    records = db.search_datasets(owner=g.user["sub"], query=query)
    return jsonify(records)


@app.get("/datasets/<int:dataset_id>")
@security.require_scope("dataset:read")
def get_dataset(dataset_id: int):
    record = db.get_dataset(dataset_id)
    if record is None:
        return jsonify(error="not found"), 404
    # V1 FIX (was CWE-639 IDOR, planted in d8e9e2a): scope alone ("dataset:read") says the caller
    # may read *some* dataset; it says nothing about *which* one. Complete mediation requires this
    # endpoint to independently check ownership on every call, the same way list_datasets() and
    # save_export()/get_export() already do, rather than trusting that holding the right scope is
    # sufficient. Fail-safe default: deny unless owner matches or the caller is an admin.
    if record["owner"] != g.user["sub"] and g.user.get("role") != "admin":
        return jsonify(error="forbidden: dataset does not belong to this token's identity"), 403
    return jsonify(record)


@app.delete("/datasets/<int:dataset_id>")
@security.require_scope("dataset:admin")
def delete_dataset(dataset_id: int):
    # Privileged action (F4): only a token carrying the "dataset:admin" scope reaches this point
    # at all (enforced by the decorator) — ordinary users are rejected before any DB access,
    # which is fail-safe defaults in action.
    deleted = db.delete_dataset(dataset_id)
    if not deleted:
        return jsonify(error="not found"), 404
    return jsonify(status="deleted", id=dataset_id)


@app.post("/exports")
@security.require_scope("dataset:export")
def save_export():
    """Called by the Processing Service once a job has produced export content. The dataset_id
    supplied must belong to the identity the token is bound to (complete mediation: the Resource
    Service re-checks ownership here too, instead of trusting that whoever called it already
    checked)."""
    body = request.get_json(force=True, silent=True) or {}
    dataset_id = body.get("dataset_id")
    fmt = body.get("format")
    content = body.get("content")
    if dataset_id is None or not fmt or content is None:
        return jsonify(error="dataset_id, format and content are required"), 400

    record = db.get_dataset(dataset_id)
    if record is None:
        return jsonify(error="not found"), 404
    if record["owner"] != g.user["sub"] and g.user.get("role") != "admin":
        return jsonify(error="forbidden: dataset does not belong to this token's identity"), 403

    export_record = db.save_export(dataset_id=dataset_id, owner=record["owner"], fmt=fmt, content=content)
    return jsonify(export_record), 201


@app.get("/exports/<int:export_id>")
@security.require_scope("dataset:read")
def get_export(export_id: int):
    record = db.get_export(export_id)
    if record is None:
        return jsonify(error="not found"), 404
    if record["owner"] != g.user["sub"] and g.user.get("role") != "admin":
        return jsonify(error="forbidden"), 403
    return jsonify(record)


if __name__ == "__main__":
    db.seed(reset=True)
    app.run(host="0.0.0.0", port=5002)
