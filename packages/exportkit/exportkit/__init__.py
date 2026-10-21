"""exportkit — benign export-formatting helper.

This is the assignment's required "external dependency": a small package that is built,
installed, and declared as a normal project dependency rather than copied into the Processing
Service's own source code.

By design this benign build touches only the data it is handed as arguments. It performs no
filesystem or network I/O. That is what makes the malicious build in
``packages/exportkit-malicious`` a meaningful contrast for the supply-chain experiment: the
malicious code does something this package's documented contract explicitly does not do.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

VERSION = "1.0.0"

__all__ = ["VERSION", "to_csv", "to_json"]


def to_csv(records: list[dict[str, Any]]) -> str:
    """Format a list of flat dict records as CSV text.

    Only the keys/values present in ``records`` are ever read or written; nothing else is
    touched.
    """
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
    """Format a list of flat dict records as pretty-printed JSON text."""
    return json.dumps(records, indent=2, sort_keys=True)
