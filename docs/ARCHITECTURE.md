# Architecture

## Components

Three independently-runnable Flask processes, each its own SQLite store (except the Processing
Service, which is stateless), communicating only over HTTP/JSON:

```
                       Export results / View results
   User (CLI/curl) ───────────────────────────────────▶ Application API (:5001)
                                                               │        │
                                        Start export job       │        │ Retrieve authorized
                                                 │              ▼        │ result
                                                 ▼         (mints a     │
                                      Processing Service    per-call    │
                                         (:5003)             token)     │
                                           │     ▲                      │
                               Read allowed│     │Save export           │
                               records     │     │result                ▼
                                           ▼     │                Resource Service (:5002)
                                      Resource Service ◀──────────────────┘
                                         (:5002)
                                           ▲
                               Install/update package
                                           │
                                   exportkit (external package,
                                   packages/exportkit)
```

(This mirrors Figure 1 of the assignment brief, instantiated for the Research Workspace domain.)

| Component | Example responsibility | Security responsibility |
|---|---|---|
| **Application API** | Authenticate users (login), route F1–F4 to the right downstream service | Establish user identity and mint narrowly-scoped, short-lived authority for each downstream call |
| **Resource Service** | Own dataset rows + export results (SQLite) | Enforce ownership/role/scope on every request it serves, including ones from the Processing Service |
| **Processing Service** | Run export jobs using `exportkit` | Operate only on the data a specific, verified job was authorized for |

## Identity, authority and how it is bound (session/token mechanism)

A single mechanism — JWTs, HS256, PyJWT — is used throughout, with one secret
(`RESEARCH_WORKSPACE_JWT_SECRET`) shared only among the three trusted services (never with a
client). Two kinds of token exist:

1. **Session token** — issued once by the Application API at `/auth/login`, held by the user's
   client for the rest of the session (`aud=["application-api"]`, `scope=["session"]`, 30 min
   TTL). It carries `sub` (username) and `role` (`"user"`/`"admin"`), established by checking a
   password hash (`werkzeug.security`) against a seeded account — this is the one point in the
   whole system where a human is authenticated.

2. **Service token** — minted fresh by the Application API (or by the Processing Service, for its
   own calls to the Resource Service) for every single downstream call, never reused across calls:
   - **service** → `aud`: which service may accept it (`resource-service` / `processing-service`)
   - **action** → `scope`: a list like `["dataset:read"]`, `["dataset:write"]`,
     `["dataset:admin"]`, `["dataset:export"]`, `["job:export"]` — the receiving service checks
     the token carries a scope it requires before doing anything
   - **resource** → an optional `resource` claim binding the token to one specific dataset id
     (used for `GET /datasets/<id>`, delete, and every export job). It is enforced in two places:
     the Resource Service rejects (403) a token whose `resource` claim differs from the dataset id
     being read/deleted/exported (`services/resource-service/security.py::resource_claim_allows`),
     and the Processing Service rejects an export job whose body `dataset_id` differs from the
     claim — the check that is V4's fix (`docs/THREAT_MODEL.md`)
   - **validity period** → `exp`/`iat`, 60 seconds for service tokens — short enough that replaying
     a captured token after the fact is not useful, long enough to complete one request

Every service (not just the Application API) independently verifies signature, pinned algorithm
(`HS256` only — never `none`), audience, and required scope on every request via its own
`security.py` (`services/*/security.py`), using `PyJWT`'s `algorithms=` and `audience=`
parameters so nothing is trusted that wasn't actually re-checked. This is **complete mediation**
in practice, and it is also exactly the property V2's planted bug violated (see
`docs/THREAT_MODEL.md`).

## Trust boundaries

- **User ↔ Application API** — untrusted network input; the only place a password ever appears.
- **Application API ↔ Resource/Processing Service** — same deployment/trust domain (all three
  share the JWT secret), but each service still independently authenticates and authorizes every
  request rather than assuming "it came from a trusted peer, so it's fine" — a deliberate
  zero-trust-within-the-cluster stance, not weakened just because the caller is "one of ours".
- **Processing Service ↔ exportkit** — a supply-chain boundary. `exportkit` is treated as
  externally supplied code: installed from a separately built wheel (not copied into
  `services/processing-service/`), gated at install time by a digest manifest
  (`manifest/approved_packages.json`, checked by `scripts/verify_manifest.py` in the Docker build
  and in the Jenkins "Build & install" stage *before* `pip install`), and not trusted at runtime either — its output is
  validated before being saved/returned (`services/processing-service/app.py::validate_export_output`).
  The Processing Service container runs as a non-root user (`worker`) because it executes this code.

## Roles and seeded accounts

| Username | Password | Role |
|---|---|---|
| alice | `Alice#Pass1` | user (ordinary) |
| bob | `Bob#Pass1` | user (ordinary) |
| admin | `Admin#Pass1` | admin (privileged) |

Two ordinary users exist specifically so tests can show one cannot access another's resources
(`alice` vs `bob`); one admin exists to exercise the privileged role (F4: list-all, delete-any).

## Functionalities (F1–F4)

| | Endpoint (Application API) | Components involved |
|---|---|---|
| F1 Upload | `POST /datasets` | Application API → Resource Service |
| F2 List own | `GET /datasets` | Application API → Resource Service |
| F3 **Export** | `POST /datasets/<id>/export` | Application API → **Processing Service → Resource Service → exportkit** (all three) |
| F4 Admin list/delete | `GET /datasets?all=true`, `DELETE /datasets/<id>` | Application API → Resource Service (privileged) |

## External dependency

`packages/exportkit` — a standalone, pip-installable package (own `pyproject.toml`, its own
`dist/*.whl`) providing `to_csv`/`to_json`. It is declared and installed as a normal dependency of
the Processing Service, never copied into `services/processing-service/`. See
`packages/exportkit/README.md` and the supply-chain section of `docs/THREAT_MODEL.md` for the
malicious-build fixture and the integrity/output-validation gates around it.

## What would need to change for a production release

(See also the report's discussion of this.) Briefly: real secrets management instead of an env
var with a documented dev fallback; per-service asymmetric keys (so a compromised service can't
mint tokens for the others) instead of one shared HMAC secret; TLS between services; a token
revocation/replay story (the short TTLs mitigate but don't eliminate this); structured audit
logging of authorization decisions; rate limiting on `/auth/login`; a real package registry +
signing instead of a local manifest; and the Processing Service's "worker" role narrowed from
`admin`-equivalent to a purpose-built scope (see V4 discussion).
