"""SQLite storage owned exclusively by the Resource Service.

No other component ever opens this database file directly — all access goes through this
service's HTTP API, so this is the single place ownership/authorization rules must hold.
"""

from __future__ import annotations

import os
import sqlite3
import time
from typing import Any

DB_PATH = os.environ.get("RESOURCE_DB_PATH", os.path.join(os.path.dirname(__file__), "resource.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner       TEXT NOT NULL,
    name        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS exports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id  INTEGER NOT NULL,
    owner       TEXT NOT NULL,
    format      TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  REAL NOT NULL
);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(reset: bool = False) -> None:
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def seed(reset: bool = True) -> None:
    """Seed synthetic datasets for the two ordinary users. Idempotent when reset=True."""
    init_db(reset=reset)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS n FROM datasets")
    if cur.fetchone()["n"] == 0:
        now = time.time()
        seeded = [
            ("alice", "alice-lab-results", '{"ph": 7.1, "temp_c": 36.6, "sample": "A-001"}'),
            ("alice", "alice-field-notes", '{"site": "fjord-3", "species_count": 12}'),
            ("bob", "bob-survey-data", '{"respondents": 48, "topic": "sleep-habits"}'),
        ]
        for owner, name, payload in seeded:
            cur.execute(
                "INSERT INTO datasets (owner, name, payload, created_at) VALUES (?, ?, ?, ?)",
                (owner, name, payload, now),
            )
        conn.commit()
    conn.close()


def create_dataset(owner: str, name: str, payload: str) -> dict[str, Any]:
    conn = get_conn()
    cur = conn.cursor()
    now = time.time()
    cur.execute(
        "INSERT INTO datasets (owner, name, payload, created_at) VALUES (?, ?, ?, ?)",
        (owner, name, payload, now),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return {"id": row_id, "owner": owner, "name": name, "payload": payload, "created_at": now}


def get_dataset(dataset_id: int) -> dict[str, Any] | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_datasets(owner: str | None) -> list[dict[str, Any]]:
    """owner=None means 'all owners' (admin use only — enforced by the caller in app.py)."""
    conn = get_conn()
    if owner is None:
        rows = conn.execute("SELECT * FROM datasets ORDER BY id").fetchall()
    else:
        rows = conn.execute("SELECT * FROM datasets WHERE owner = ? ORDER BY id", (owner,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_dataset(dataset_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


def save_export(dataset_id: int, owner: str, fmt: str, content: str) -> dict[str, Any]:
    conn = get_conn()
    cur = conn.cursor()
    now = time.time()
    cur.execute(
        "INSERT INTO exports (dataset_id, owner, format, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (dataset_id, owner, fmt, content, now),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return {"id": row_id, "dataset_id": dataset_id, "owner": owner, "format": fmt, "created_at": now}


def get_export(export_id: int) -> dict[str, Any] | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM exports WHERE id = ?", (export_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def search_datasets(owner: str, query: str) -> list[dict[str, Any]]:
    """Search the caller's own datasets by (substring of) name — the ``owner`` restriction is
    what is supposed to enforce that a non-admin caller only ever sees their own rows.

    NOTE (V3, planted on purpose — see docs/THREAT_MODEL.md): ``owner`` is bound as a parameter
    correctly, but ``query`` is concatenated directly into the SQL string. CWE-89 SQL Injection: a
    crafted ``query`` such as ``' OR '1'='1' -- `` changes the WHERE clause's structure so that the
    ``owner = ?`` restriction is effectively OR'd away, letting any authenticated user read every
    other user's dataset names/payloads through this endpoint — a SQL-injection-driven
    authorization bypass, not just a generic data leak.
    """
    conn = get_conn()
    sql = "SELECT * FROM datasets WHERE owner = ? AND name LIKE '%" + query + "%'"
    rows = conn.execute(sql, (owner,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
