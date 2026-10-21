"""Processing Service — runs export jobs using the external `exportkit` package.

Security responsibility (per the brief's architecture table): operate only on the data requested
for a specific job. This is the component where the composition vulnerability (V4) lives: it is
given broad read access to the Resource Service in order to do its work, and the thing that is
supposed to keep that power scoped to "this specific job" is this service's own check that the
job it was asked to run is the job it was actually authorized for.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os

import requests
import security
from exportkit import VERSION as EXPORTKIT_VERSION
from exportkit import to_csv, to_json
from flask import Flask, g, jsonify, request

app = Flask(__name__)
logger = logging.getLogger("processing-service")

RESOURCE_SERVICE_URL = os.environ.get("RESOURCE_SERVICE_URL", "http://localhost:5002")
HTTP_TIMEOUT = 10

FORMATTERS = {"csv": to_csv, "json": to_json}


def _fields_produced_by(content: str, fmt: str) -> set[str]:
    """Reads back the top-level field names the formatter actually emitted."""
    if fmt == "json":
        parsed = json.loads(content) if content else []
        fields: set[str] = set()
        for row in parsed:
            fields.update(row.keys())
        return fields
    if fmt == "csv":
        if not content:
            return set()
        reader = csv.reader(io.StringIO(content))
        header = next(reader, [])
        return set(header)
    raise ValueError(f"unknown format: {fmt}")


def validate_export_output(content: str, fmt: str, expected_record: dict) -> None:
    """Output-validation mitigation for the supply-chain scenario (Experiment B): regardless of
    what the installed `exportkit` build actually does internally, its OUTPUT must only ever
    contain fields that were present on the single record this job was authorized to touch.
    Checking the package's filename/version is not a runtime defence (the brief is explicit about
    this) — this checks the one thing that actually matters: what the dependency produced.
    Raises ValueError (caught by the caller, which fails the job closed) if the output contains
    anything else, e.g. a field smuggled in from the process environment or another record.
    """
    produced = _fields_produced_by(content, fmt)
    allowed = set(expected_record.keys())
    unexpected = produced - allowed
    if unexpected:
        logger.warning(
            "exportkit output for dataset %s contained unexpected field(s) %s — rejecting the job",
            expected_record.get("id"),
            sorted(unexpected),
        )
        raise ValueError(f"export output contained unexpected field(s): {sorted(unexpected)}")


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

    # V4 FIX (was CWE-441 Confused Deputy, planted in 9a3fc5b): this service holds a broad
    # "worker" credential (see security.py) so it can fetch whatever data a job legitimately
    # needs — but that power must only ever be used for the exact job the Application API actually
    # authorized. `g.user["resource"]` is the dataset id bound into THIS specific, signed token;
    # the request body is just job parameters supplied by whoever is calling this endpoint, which
    # is not necessarily the Application API (nothing stops a client from calling this service
    # directly). Fail-safe default: reject unless the token carries a resource claim and it
    # matches the dataset_id actually being requested — never let the body silently override what
    # was authorized.
    authorized_dataset_id = g.user.get("resource")
    if authorized_dataset_id is None or int(authorized_dataset_id) != int(dataset_id):
        return jsonify(error="forbidden: this token does not authorize a job on this dataset"), 403

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

    # Defense in depth against a compromised/malicious exportkit build (controlled supply-chain
    # experiment, see docs/THREAT_MODEL.md "Controlled supply chain attack" and
    # packages/exportkit-malicious/). We do not trust the dependency just because its name/version
    # matched an approval manifest at install time (manifest/approved_packages.json,
    # scripts/verify_manifest.py handles that, separately) — we also check what it actually
    # produced, every time, at runtime.
    try:
        validate_export_output(content, fmt, record)
    except ValueError as exc:
        return jsonify(error=f"export rejected by output validation: {exc}"), 422

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
