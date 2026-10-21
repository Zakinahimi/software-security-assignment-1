#!/usr/bin/env python3
"""Command-line client for the Research Workspace Application API.

Per the brief: "A command-line client or API test collection is sufficient as the user
interface." This is that client. It logs in fresh on every invocation using the seeded account's
known password — fine for this teaching sandbox (all seeded accounts/passwords are already public
in services/application-api/users.py), not something to do with real credentials.

Usage:
    python scripts/client.py login <username> [password]
    python scripts/client.py upload <username> <name> <payload-json>
    python scripts/client.py list <username> [--all]
    python scripts/client.py get <username> <dataset_id>
    python scripts/client.py search <username> <query>
    python scripts/client.py export <username> <dataset_id> [csv|json]
    python scripts/client.py get-export <username> <export_id>
    python scripts/client.py admin-list <username>
    python scripts/client.py admin-delete <username> <dataset_id>
"""

from __future__ import annotations

import json
import os
import sys

import requests

APPLICATION_API_URL = os.environ.get("APPLICATION_API_URL", "http://localhost:5001")

# Convenience only — see module docstring. Not used for anything beyond this local dev CLI.
SEED_PASSWORDS = {
    "alice": "Alice#Pass1",
    "bob": "Bob#Pass1",
    "admin": "Admin#Pass1",
}


def login(username: str, password: str | None) -> str:
    password = password or SEED_PASSWORDS.get(username)
    if password is None:
        sys.exit(f"no known password for '{username}'; pass one explicitly")
    resp = requests.post(f"{APPLICATION_API_URL}/auth/login", json={"username": username, "password": password})
    if resp.status_code != 200:
        sys.exit(f"login failed ({resp.status_code}): {resp.text}")
    return resp.json()["access_token"]


def auth_headers(username: str, password: str | None = None) -> dict:
    return {"Authorization": f"Bearer {login(username, password)}"}


def pretty(resp: requests.Response) -> None:
    print(f"HTTP {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print(resp.text)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd, args = sys.argv[1], sys.argv[2:]

    if cmd == "login":
        username = args[0]
        password = args[1] if len(args) > 1 else None
        print(login(username, password))

    elif cmd == "upload":
        username, name, payload_json = args[0], args[1], args[2]
        resp = requests.post(
            f"{APPLICATION_API_URL}/datasets",
            json={"name": name, "payload": json.loads(payload_json)},
            headers=auth_headers(username),
        )
        pretty(resp)

    elif cmd == "list":
        username = args[0]
        want_all = "--all" in args
        resp = requests.get(
            f"{APPLICATION_API_URL}/datasets",
            params={"all": "true"} if want_all else {},
            headers=auth_headers(username),
        )
        pretty(resp)

    elif cmd == "get":
        username, dataset_id = args[0], args[1]
        resp = requests.get(f"{APPLICATION_API_URL}/datasets/{dataset_id}", headers=auth_headers(username))
        pretty(resp)

    elif cmd == "search":
        username, query = args[0], args[1]
        resp = requests.get(
            f"{APPLICATION_API_URL}/datasets/search", params={"q": query}, headers=auth_headers(username)
        )
        pretty(resp)

    elif cmd == "export":
        username, dataset_id = args[0], args[1]
        fmt = args[2] if len(args) > 2 else "csv"
        resp = requests.post(
            f"{APPLICATION_API_URL}/datasets/{dataset_id}/export",
            json={"format": fmt},
            headers=auth_headers(username),
        )
        pretty(resp)

    elif cmd == "get-export":
        username, export_id = args[0], args[1]
        resp = requests.get(f"{APPLICATION_API_URL}/exports/{export_id}", headers=auth_headers(username))
        pretty(resp)

    elif cmd == "admin-list":
        username = args[0]
        resp = requests.get(
            f"{APPLICATION_API_URL}/datasets", params={"all": "true"}, headers=auth_headers(username)
        )
        pretty(resp)

    elif cmd == "admin-delete":
        username, dataset_id = args[0], args[1]
        resp = requests.delete(f"{APPLICATION_API_URL}/datasets/{dataset_id}", headers=auth_headers(username))
        pretty(resp)

    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
