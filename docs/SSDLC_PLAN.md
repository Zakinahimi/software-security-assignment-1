# Secure SDLC Plan — Research Workspace

This plan is committed **before** any feature code, per the assignment's SSDLC and CI/CD
requirement. It reuses the four-phase structure and the chain
`asset → threat → requirement/control → lifecycle activity → test/evidence → gate decision`
from the course's threat-modelling / DevSecOps exercise.

## 1. Application summary

**Domain:** Research Workspace — researchers upload private datasets and request exports of
them. This is the assignment's own worked example (see Figure 1 of the brief), chosen because it
maps cleanly onto the required three-component architecture without inventing scope that isn't
needed to demonstrate the security requirements.

**Components (separate OS processes, each its own Flask app + own SQLite store, communicating
only over HTTP):**

| Component | Responsibility | Security responsibility |
|---|---|---|
| **Application API** (`services/application-api`) | Authenticates users, issues JWTs, routes requests | Establishes user identity and the authority (role + scopes) of the request |
| **Resource Service** (`services/resource-service`) | Owns dataset records and export results (SQLite) | Enforces per-resource ownership/role checks on every access, including calls arriving from Processing Service |
| **Processing Service** (`services/processing-service`) | Runs export jobs using the external `exportkit` package | Re-verifies the caller's authority itself and operates only on the records it was authorized to fetch |

**External dependency:** `exportkit` — a small, separately packaged/installed library (not
copied into any service's source tree) that formats dataset records into CSV/JSON. Used by the
Processing Service. A benign and a deliberately malicious build exist (`packages/exportkit*`) for
the controlled supply-chain exercise.

**Users/roles:** two ordinary users (`alice`, `bob`) and one admin (`admin`), seeded at startup.

## 2. Functional and non-functional requirements (scope)

- F1 — A user can upload a dataset they own (Application API → Resource Service).
- F2 — A user can list/view **their own** datasets (Application API → Resource Service).
- F3 — A user can request an **export** of one of their datasets. This is the functionality that
  involves all three components (Application API → Processing Service → Resource Service →
  `exportkit`), matching Figure 1 in the brief.
- F4 — An **admin** can list all datasets across all users and delete any dataset (privileged
  action, Application API → Resource Service).
- NF1 — No component trusts another component's claims about user identity without independently
  verifying a signed token (complete mediation).
- NF2 — Synthetic data only; no real accounts, no payments, no public hosting (out of scope per
  the brief).
- NF3 — A command-line client (`scripts/client.py`) plus curl examples/Postman collection serve
  as the user interface; no GUI is built.

## 3. Identity, authority and trust boundaries (summary — full detail in `docs/ARCHITECTURE.md`
   and `docs/THREAT_MODEL.md`)

- Identity is established once, at the Application API, via username/password checked against
  seeded accounts (passwords hashed with `werkzeug.security`).
- Authority is expressed as a **JWT** (HS256, shared signing secret between the three trusted
  services only) carrying `sub` (user id), `role`, `aud` (which services may accept it), `scope`
  (which actions it authorizes), `exp`/`iat` (validity window) and `jti`.
- Every service — not just the Application API — independently verifies this token's signature,
  audience, expiry and scope on every call it receives, including calls that originate from
  another trusted service (complete mediation; see design-principle section of the report).
- Trust boundaries: User ↔ Application API (network, untrusted input), Application API ↔
  Resource/Processing Service (same trust domain, but each service still re-authenticates —
  zero-trust style), Processing Service ↔ `exportkit` (supply-chain boundary — treated as
  external/untrusted code).

## 4. Planned vulnerabilities (to be planted, then found and fixed with test evidence)

Three from the course's vulnerability catalog, plus one from composing the components, as
required. Each is first **implemented as a real, exploitable bug** (own commit), then an
**automated test that demonstrates the exploit** is added (own commit, initially failing/red
because the exploit succeeds), then the bug is **fixed** with the test turned into a regression
guard (own commit, green). Full write-up with evidence links is in the report and in
`docs/THREAT_MODEL.md`.

| # | Vulnerability | Class / CWE | Component | Why planted here |
|---|---|---|---|---|
| V1 | IDOR — reading another user's dataset by guessing its id | CWE-639 Broken Access Control | Resource Service | Classic ownership-check omission on a resource-owning service |
| V2 | JWT `alg=none` / unverified-signature acceptance | CWE-347 Improper Verification of Cryptographic Signature | Application API | Classic broken-authentication bug in the identity-issuing component |
| V3 | SQL injection in dataset search | CWE-89 SQL Injection | Resource Service | Classic injection bug in the component that talks to the database |
| V4 | Confused deputy — Processing Service trusts a `user_id` field in the request body instead of re-verifying the caller's JWT, letting a forged/compromised body trigger an export of another user's data | CWE-441 Unintended Proxy/Confused Deputy | Processing Service ↔ Resource Service (composition) | Arises only because components are composed over a network boundary — a single-process version of this app could not exhibit it |

## 5. Design principles to apply (≥3 required)

1. **Least privilege** — service-to-service JWTs carry narrow `scope`s; the Processing Service's
   DB file permissions and the `exportkit` sandbox directory are restricted to what the export job
   needs.
2. **Complete mediation** — every request, at every service, re-checks the token and the
   resource-ownership rule; nothing is checked once and cached/trusted downstream (this is the
   fix for V4).
3. **Fail-safe defaults** — missing/invalid/expired token ⇒ 401; valid token but insufficient
   scope/role/ownership ⇒ 403; unknown route/method ⇒ deny; the export job starts from an empty
   allow-list of records and only adds records the Resource Service explicitly returns.

## 6. Phase table

| Phase | Required deliverable | Gate |
|---|---|---|
| **Requirements** | This document; `docs/ARCHITECTURE.md`; `docs/ACCESS_CONTROL_MATRIX.md`; `docs/THREAT_MODEL.md` (STRIDE) | Reviewed against the brief's scope before any service code is written: trust boundaries drawn, authorities defined, V1–V4 mapped to STRIDE categories with a planned control each |
| **Implementation & build** | Three working services, `exportkit` built as an installable wheel and declared as a dependency (not vendored), reproducible builds via `requirements.txt`/`pyproject.toml` | CI step rejects the build if `exportkit` is not installed from the declared package (i.e., no copy-pasted helper code) or if dependency/static-analysis findings are present |
| **Testing** | `pytest` functional tests (F1–F4) and authorization/security tests for V1–V4 and the design principles; exploit-demonstrating tests added at plant time, fixed at patch time | CI fails the build if any functional or security test fails; CI fails if a malformed/unapproved `exportkit` artifact is used (manifest check, see `docs/supply-chain` section) |
| **Release, deploy & operation** | Discussed in the report: what a production release would still need (secrets management, TLS between services, structured audit logging, token revocation, rate limiting, real RBAC admin UI) | — |

## 7. CI/CD gate (Jenkinsfile, committed alongside this plan)

On every push/PR the pipeline must: (1) build/validate each component, run static analysis
(`ruff`) and dependency analysis (`pip-audit`); (2) spin up a fresh environment (docker-compose)
and run the functional + authorization/security test suite against it; (3) archive test reports,
static-analysis reports and dependency-audit reports as Jenkins artifacts. The build is configured
to **fail** on: any failing test, any `pip-audit` finding of severity ≥ medium on the direct
dependency set, and any integrity-manifest mismatch for `exportkit` (supply-chain gate).

## 8. Out of scope (per the brief)

Account self-registration UI, graphical interface, real payment/email delivery, public hosting,
high availability, large-scale performance.
