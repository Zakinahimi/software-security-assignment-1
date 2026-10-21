"""Token issuance and verification for the Application API.

The Application API is the only component that ever authenticates a human user (via
username/password). Every other authority in the system is derived from that one decision:

1. At login, it mints a "session token" the client holds (aud=["application-api"]).
2. On every subsequent request, it is supposed to *properly re-verify* the caller's session
   token before trusting `sub`/`role` from it, and then mints a fresh, narrowly-scoped,
   short-lived "service token" bound to the specific downstream service + action + resource +
   validity period, which it attaches when calling the Resource Service / Processing Service.

Because step 2 is where every downstream authority originates, a bug in how the Application API
verifies a session token is a bug in the authorization of the *entire system*, even though the
Resource/Processing services each correctly verify the signature of whatever token they receive.
"""

from __future__ import annotations

import os
import time
import uuid
from functools import wraps
from typing import Any

import jwt
from flask import g, jsonify, request

JWT_SECRET = os.environ.get(
    "RESEARCH_WORKSPACE_JWT_SECRET",
    "dev-only-shared-secret-change-me-32bytes!!",
)
SERVICE_NAME = "application-api"
SESSION_TTL_SECONDS = 30 * 60
SERVICE_TOKEN_TTL_SECONDS = 60


def mint_session_token(sub: str, role: str) -> str:
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": role,
        "aud": [SERVICE_NAME],
        "scope": ["session"],
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def mint_service_token(sub: str, role: str, audience: str, scope: list[str], resource: Any = None, ttl: int = SERVICE_TOKEN_TTL_SECONDS) -> str:
    """Mint a narrowly-scoped, short-lived token authorizing exactly one downstream
    service + action (+ optionally one specific resource id), for exactly `sub`/`role`.
    This is where authority is bound to service, resource, action and validity period."""
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": role,
        "aud": [audience],
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }
    if resource is not None:
        claims["resource"] = resource
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def decode_session_token_UNSAFE(token: str) -> dict[str, Any]:
    """V2 (planted on purpose — see docs/THREAT_MODEL.md): decodes the session token WITHOUT
    verifying its signature (`verify_signature: False`). CWE-347 Improper Verification of
    Cryptographic Signature. Any client can craft an arbitrary, unsigned-but-well-formed JWT
    claiming `role: "admin"` / any `sub`, and every endpoint below that relies on this function —
    i.e. every protected endpoint in the Application API — will treat it as authentic. Because the
    Application API then uses that (forged) identity to *mint a genuinely, correctly signed*
    downstream service token via mint_service_token(), the forgery propagates as real authority
    into the Resource Service and Processing Service, even though those services verify
    signatures correctly themselves."""
    return jwt.decode(token, options={"verify_signature": False})


def require_session_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="missing bearer token"), 401
        token = header[len("Bearer ") :]
        try:
            claims = decode_session_token_UNSAFE(token)
        except Exception as exc:  # noqa: BLE001 - malformed token, not a trust decision
            return jsonify(error=f"malformed token: {exc}"), 401

        if claims.get("exp", 0) < time.time():
            return jsonify(error="token expired"), 401
        if "sub" not in claims or "role" not in claims:
            return jsonify(error="malformed token"), 401

        g.user = claims
        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user.get("role") != "admin":
            return jsonify(error="forbidden: admin role required"), 403
        return fn(*args, **kwargs)

    return wrapper
