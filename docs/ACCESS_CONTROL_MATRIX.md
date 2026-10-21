# Access Control Matrix

Enforced independently by each service that owns the corresponding endpoint (complete mediation —
see `docs/ARCHITECTURE.md`). "Scope required" is the JWT `scope` claim value(s) the receiving
service checks for; "resource rule" is the additional per-record check applied on top of scope.

## Application API (`services/application-api/app.py`)

| Endpoint | Ordinary user | Admin | Unauthenticated |
|---|---|---|---|
| `POST /auth/login` | ✅ (own credentials only) | ✅ | ✅ (that's the point) |
| `GET /datasets` | ✅ own datasets only | ✅ own, or all with `?all=true` | ❌ 401 |
| `POST /datasets` | ✅ creates as self (owner forced server-side) | ✅ | ❌ 401 |
| `GET /datasets/<id>` | ✅ only if owner | ✅ any | ❌ 401 |
| `POST /datasets/<id>/export` | ✅ only if owner (enforced downstream, see below) | ✅ | ❌ 401 |
| `DELETE /datasets/<id>` | ❌ 403 (`require_admin`) | ✅ | ❌ 401 |
| `GET /exports/<id>` | ✅ only if owner | ✅ any | ❌ 401 |

## Resource Service (`services/resource-service/app.py`) — the authoritative enforcement point

| Endpoint | Scope required | Resource rule |
|---|---|---|
| `POST /datasets` | `dataset:write` | owner forced to `token.sub`, never trusts a client-supplied owner |
| `GET /datasets` | `dataset:read` or `dataset:admin` | `dataset:admin` + `?all=true` → all owners; otherwise forced to `token.sub` |
| `GET /datasets/<id>` | `dataset:read` | **`record.owner == token.sub` OR `token.role == admin`** (V1 fix) |
| `GET /datasets/search` | `dataset:read` | SQL `WHERE owner = <token.sub>` bound as a parameter (V3 fix) |
| `DELETE /datasets/<id>` | `dataset:admin` | admin-only by scope; no ordinary-user path at all |
| `POST /exports` | `dataset:export` | `record.owner == token.sub` OR `token.role == admin`, re-checked here even though the Processing Service already checked once upstream |
| `GET /exports/<id>` | `dataset:read` | `record.owner == token.sub` OR `token.role == admin` |

## Processing Service (`services/processing-service/app.py`)

| Endpoint | Scope required | Resource rule |
|---|---|---|
| `POST /jobs/export` | `job:export` | **`token.resource == body.dataset_id`** (V4 fix) — the job may only ever touch the dataset the Application API actually bound into this specific token |

## Cross-cutting rules (apply everywhere a token is checked)

- Missing/malformed/expired/wrong-signature token → `401`.
- Correctly-signed token but wrong audience (not meant for this service) → `403`.
- Correctly-signed, right-audience token but missing/insufficient scope → `403`.
- Correctly-signed, right-audience, right-scope token but wrong resource owner → `403`.
- Unknown resource id → `404` (checked *after* authentication but the ownership check still runs
  first where both could apply, so a 403 is never used to leak whether a resource exists for
  someone who isn't allowed to know).

## Seeded test identities (used throughout the test suites to prove the matrix above)

| Username | Role | Owns (seeded) |
|---|---|---|
| alice | user | dataset 1 (`alice-lab-results`), dataset 2 (`alice-field-notes`) |
| bob | user | dataset 3 (`bob-survey-data`) |
| admin | admin | nothing — exercises the privileged role, not ownership |
