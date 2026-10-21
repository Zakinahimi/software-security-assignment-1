"""Processing Service — runs export jobs using the external `exportkit` package.

Security responsibility (per the brief's architecture table): operate only on the data requested
for a specific job. This is the component where the composition vulnerability (V4) lives: it is
given broad read access to the Resource Service in order to do its work, and the thing that is
supposed to keep that power scoped to "this specific job" is this service's own check that the
job it was asked to run is the job it was actually authorized for.
"""

from __future__ import annotations

import os

import requests
import security
from exportkit import VERSION as EXPORTKIT_VERSION
from exportkit import to_csv, to_json
from flask import Flask, g, jsonify, request

app = Flask(__name__)

RESOURCE_SERVICE_URL = os.environ.get("RESOURCE_SERVICE_URL", "http://localhost:5002")
HTTP_TIMEOUT = 10

FORMATTERS = {"csv": to_csv, "json": to_json}


@app.get("/health")
def health():
    return jsonify(status="ok", service="processing-service", exportkit_version=EXPORTKIT_VERSION)


@app.post("/jobs/export")
@security.require_scope("job:export")
def run_export_job():
    body = request.get_json(force=True, silent=True) or {}
    dataset_id = body.get("dataset_id")
    fmt = body.get("format", "csv")

    if dataset_id is None:
        return jsonify(error="dataset_id is required"), 400
    if fmt not in FORMATTERS:
        return jsonify(error=f"unsupported format '{fmt}'"), 400

    # --- V4 (planted on purpose, see docs/THREAT_MODEL.md): the job's target dataset is taken
    # straight from the request BODY instead of from `g.user["resource"]` — the dataset id the
    # Application API actually bound into this specific, signed token when it authorized this
    # job. This service was given a broad "worker" credential (see security.py) to fetch whatever
    # data a job needs; the only thing standing between that broad power and a confused-deputy
    # attack is checking that the job's parameters match what was actually authorized, and that
    # check is missing here. A caller holding ANY valid job:export token for THEIR OWN dataset can
    # call this endpoint directly (it does not have to go through the Application API) with a
    # different dataset_id in the body and have this service fetch and export someone else's
    # data using its own elevated worker credentials. CWE-441 Unintended Proxy/Confused Deputy.
    fetch_token = security.mint_resource_service_worker_token(scope=["dataset:read"], resource=dataset_id)
    resp = requests.get(
        f"{RESOURCE_SERVICE_URL}/datasets/{dataset_id}",
        headers={"Authorization": f"Bearer {fetch_token}"},
        timeout=HTTP_TIMEOUT,
    )
    if resp.status_code != 200:
        return jsonify(error="could not read the requested dataset"), resp.status_code

    record = resp.json()
    # exportkit only ever sees the single record it was explicitly handed — "operate only on the
    # data requested for a specific job" (architecture table), regardless of whether the job
    # parameters above were themselves correctly scoped.
    content = FORMATTERS[fmt]([record])

    save_token = security.mint_resource_service_worker_token(scope=["dataset:export"], resource=dataset_id)
    save_resp = requests.post(
        f"{RESOURCE_SERVICE_URL}/exports",
        json={"dataset_id": dataset_id, "format": fmt, "content": content},
        headers={"Authorization": f"Bearer {save_token}"},
        timeout=HTTP_TIMEOUT,
    )
    if save_resp.status_code not in (200, 201):
        return jsonify(error="could not store the export result"), save_resp.status_code

    export_record = save_resp.json()
    return jsonify(
        export_id=export_record["id"],
        dataset_id=dataset_id,
        format=fmt,
        content=content,
        requested_by=g.user["sub"],
    ), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
