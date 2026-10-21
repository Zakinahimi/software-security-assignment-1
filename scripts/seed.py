#!/usr/bin/env python3
"""Re-seed both services' SQLite stores without restarting them.

Each service already seeds itself (reset=True) when started directly via `python app.py` (see
scripts/run_dev.sh), so you normally don't need this. It's useful to reset state between manual
testing sessions without killing the running processes, or to seed a path explicitly (e.g. before
first boot in a container that mounts a persistent volume).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "services" / "application-api"))
sys.path.insert(0, str(REPO_ROOT / "services" / "resource-service"))

import db as resource_db  # noqa: E402
import users as application_users  # noqa: E402


def main() -> None:
    application_users.seed(reset=True)
    print(f"seeded {application_users.DB_PATH}: {[u for u, _, _ in application_users.SEED_ACCOUNTS]}")

    resource_db.seed(reset=True)
    print(f"seeded {resource_db.DB_PATH} with synthetic datasets for alice/bob")


if __name__ == "__main__":
    main()
