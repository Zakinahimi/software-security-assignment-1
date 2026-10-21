"""JWT verification for the Processing Service, plus minting of the service's own outbound
"worker" credential used to call the Resource Service.
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
SERVICE_NAME = "processing-service"

# The Processing Service needs to read whatever dataset a job legitimately concerns, which is a
# deliberate trust relationship with the Resource Service (see docs/ARCHITECTURE.md, "trust
# boundaries"), separate from the question of WHICH dataset a given job is authorized to touch —
# that question must still be answered correctly in app.py. See docs/THREAT_MODEL.md V4 for the
# discussion of why "admin" here is a least-privilege trade-off worth revisiting in production.
WORKER_IDENTITY = "processing-service-worker"
WORKER_ROLE = "admin"


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def verify_token(token: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=SERVICE_NAME,
            options={"require": ["exp", "iat", "sub", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthError(401, "token expired")
    except jwt.InvalidAudienceError:
        raise AuthError(403, f"token not valid for {SERVICE_NAME}")
    except jwt.InvalidTokenError as exc:
        raise AuthError(401, f"invalid token: {exc}")
    return claims


def require_scope(*required_scopes: str):
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


def mint_resource_service_worker_token(scope: list[str], resource: Any = None, ttl: int = 60) -> str:
    """The Processing Service's own outbound credential for talking to the Resource Service while
    carrying out a job. NOT the end user's identity — this is the Processing Service acting with
    its own, broader, authority to do its job."""
    now = int(time.time())
    claims = {
        "sub": WORKER_IDENTITY,
        "role": WORKER_ROLE,
        "aud": ["resource-service"],
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }
    if resource is not None:
        claims["resource"] = resource
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")
