"""Seeded account store owned by the Application API — the only component that ever sees
passwords. Resource/Processing services only ever see a verified identity (JWT `sub`/`role`),
never a password.
"""

from __future__ import annotations

import os
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.environ.get("APPLICATION_API_DB_PATH", os.path.join(os.path.dirname(__file__), "users.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username       TEXT PRIMARY KEY,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL
);
"""

# Synthetic, seeded accounts only (per the brief: no real registration flow).
SEED_ACCOUNTS = [
    ("alice", "Alice#Pass1", "user"),
    ("bob", "Bob#Pass1", "user"),
    ("admin", "Admin#Pass1", "admin"),
]


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def seed(reset: bool = True) -> None:
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = get_conn()
    conn.executescript(SCHEMA)
    for username, password, role in SEED_ACCOUNTS:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
    conn.commit()
    conn.close()


def verify_password(username: str, password: str) -> str | None:
    """Returns the user's role if the password is correct, else None. Fail-safe default: any
    lookup/compare failure returns None (deny), never an exception that could be mishandled."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row is None:
        return None
    if not check_password_hash(row["password_hash"], password):
        return None
    return row["role"]
