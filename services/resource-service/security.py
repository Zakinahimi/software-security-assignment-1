"""JWT verification for the Resource Service.

The Resource Service never issues tokens itself — only the Application API does, at login — but
it MUST independently verify every token it is handed, including tokens forwarded by the
Processing Service. This is "complete mediation": the Resource Service never assumes a request is
legitimate just because it arrived from another trusted-sounding component.

Token claims used (see docs/ARCHITECTURE.md for the full scheme):
  sub      - the end-user's username this authority was issued for
  role     - "user" or "admin"
  aud      - list of services allowed to accept this token; must contain "resource-service"
  scope    - list of actions this token authorizes, e.g. ["dataset:read"]
  resource - (optional) a specific dataset id this token is additionally restricted to
  exp/iat  - validity window
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Any

import jwt
from flask import g, jsonify, request

JWT_SECRET = os.environ.get(
    "RESEARCH_WORKSPACE_JWT_SECRET",
    "dev-only-shared-secret-change-me-32bytes!!",
)
SERVICE_NAME = "resource-service"


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def verify_token(token: str) -> dict[str, Any]:
    """Properly verify signature, expiry and audience. Raises AuthError on any failure."""
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],  # pinned explicitly — never accept "none" or let the caller pick
            audience=SERVICE_NAME,
            options={"require": ["exp", "iat", "sub", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthError(401, "token expired")
    except jwt.InvalidAudienceError:
        # Signature and expiry were fine, but this token was never issued for this service —
        # explicit 403 rather than folding it into the generic 401, since it is an authorization
        # (wrong audience) failure, not an authentication (bad/expired credential) failure.
        raise AuthError(403, f"token not valid for {SERVICE_NAME}")
    except jwt.InvalidTokenError as exc:
        raise AuthError(401, f"invalid token: {exc}")

    return claims


def require_scope(*required_scopes: str):
    """Decorator: require a valid token, bound to this service, with at least one of the given
    scopes. Fail-safe default: any missing/invalid/expired/wrong-audience/wrong-scope token is
    rejected; nothing is granted implicitly."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="missing bearer token"), 401
            token = header[len("Bearer ") :]
            try:
                claims = verify_token(token)
            except AuthError as exc:
                return jsonify(error=exc.message), exc.status

            token_scopes = set(claims.get("scope") or [])
            if required_scopes and not (token_scopes & set(required_scopes)):
                return jsonify(error="insufficient scope"), 403

            g.user = claims
            return fn(*args, **kwargs)

        return wrapper

    return decorator
