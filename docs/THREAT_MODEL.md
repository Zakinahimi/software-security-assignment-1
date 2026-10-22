# Threat Model

## STRIDE analysis

| Asset | Threat (STRIDE) | Requirement / control | Lifecycle activity | Test / evidence | Gate decision |
|---|---|---|---|---|---|
| User credentials (Application API) | **S**poofing | Passwords hashed (`werkzeug.security`), generic "invalid credentials" response | Implementation | `services/application-api/tests/test_functional.py::test_login_wrong_password`, `test_login_unknown_user` | Pass required |
| Session/service JWTs | **S**poofing / **T**ampering | HS256 signature verified everywhere, algorithm pinned, never `none` | Implementation → fixed after being planted (V2) | `services/application-api/tests/test_security.py` | Pass required (regression-tested) |
| Dataset records (Resource Service) | **T**ampering / **I**nformation disclosure / **E**levation of privilege | Per-record ownership check on every read/write, parameterized SQL | Implementation → fixed after being planted (V1, V3) | `services/resource-service/tests/test_security.py` | Pass required |
| Export jobs (Processing Service) | **E**levation of privilege via a confused deputy | Job's dataset bound to the token's verified `resource` claim, not request body | Implementation → fixed after being planted (V4) | `services/processing-service/tests/test_security.py` | Pass required |
| Audit trail of who did what | **R**epudiation | `sub` on every token, `requested_by` on export results | Implementation (partial — see "what would need to change for production") | export response includes `requested_by` | — |
| Resource Service availability | **D**enial of service | Out of scope per the brief (no large-scale performance/availability requirement) | — | — | — |
| `exportkit` dependency | Supply-chain **T**ampering / **I**nformation disclosure | Install-time digest manifest + runtime output validation | Implementation (optional section) | `scripts/verify_manifest.py`, `services/processing-service/tests/test_supply_chain.py` | Pass required once attempted |

## The four planted vulnerabilities

Each was implemented as real, exploitable code, proven exploitable by an automated test that
passed against that exact commit, then fixed with the same test file rewritten to assert the
secure behaviour. `git show <hash>:<path>` reproduces the "before" state for any of these at any
time; nothing below is hypothetical.

### V1 — IDOR on `GET /datasets/<id>` (CWE-639)

- **Component:** Resource Service.
- **Planted:** `1dfd1d8` — the endpoint checked the caller held the
  `dataset:read` scope, but never checked `record.owner == token.sub`. Any authenticated user
  could read any other user's dataset by id.
- **Exploit evidence:** `test_V1_idor_any_authenticated_user_can_read_another_users_dataset`
  (same commit) — bob, holding a legitimate token for himself, successfully reads alice's
  dataset.
- **Fixed:** `cde57d6` — added
  `if record["owner"] != g.user["sub"] and g.user.get("role") != "admin": return 403`.
- **Regression test:** `test_V1_idor_is_fixed_cross_owner_read_is_rejected` (+
  `test_V1_owner_can_still_read_their_own_dataset`, `test_V1_admin_can_still_read_any_dataset`
  so the fix is proven not to have broken the legitimate cases). Also re-verified end-to-end in
  `tests/test_authz_e2e.py::test_v1_idor_fixed_cannot_read_another_users_dataset`.
- **Why it's realistic:** this is the single most common authorization bug in web APIs — a scope
  check ("can this caller read *a* dataset") is mistaken for a resource check ("can this caller
  read *this* dataset").

### V2 — JWT signature not verified (CWE-347)

- **Component:** Application API.
- **Planted:** `1ccefc1` —
  `decode_session_token_UNSAFE()` called `jwt.decode(token, options={"verify_signature": False})`.
  Because every downstream service token is minted *from* the identity this decode produces, a
  forged session token claiming `role: "admin"` resulted in the Application API minting a
  genuinely, correctly-signed `dataset:admin` token for the Resource Service — the forgery
  propagated as real authority past services that verify signatures correctly themselves.
- **Exploit evidence:** `test_V2_forged_admin_session_token_is_accepted` and
  `test_V2_forged_token_escalates_to_a_genuinely_signed_downstream_admin_token` (same commit) —
  the second test decodes the token the Application API actually sent to the Resource Service,
  with the *real* secret, and shows it is validly signed and carries `sub: "mallory"`,
  `dataset:admin`.
- **Fixed:** `5cdc098` — `decode_session_token()` now verifies signature
  (`algorithms=["HS256"]`, real secret), audience, and requires `exp/iat/sub/aud`.
- **Regression test:** `test_V2_forged_admin_session_token_is_rejected` +
  `test_V2_forged_token_no_longer_escalates_to_a_downstream_admin_token` +
  `test_a_genuinely_issued_admin_token_still_works`. Re-verified end-to-end in
  `tests/test_authz_e2e.py::test_v2_forged_admin_token_rejected_by_application_api`.
- **Why it's realistic:** `verify_signature=False` (or forgetting to pin `algorithms=`) is a
  well-documented, recurring real-world JWT library misuse pattern, not a contrived bug.

### V3 — SQL injection in dataset search (CWE-89)

- **Component:** Resource Service.
- **Planted:** `1dfd1d8` —
  `db.search_datasets()` bound `owner` as a parameter but concatenated the free-text `query`
  directly into the SQL string: `"... WHERE owner = ? AND name LIKE '%" + query + "%'"`.
- **Exploit evidence:** `test_V3_sql_injection_bypasses_owner_filter_in_search` (same commit) —
  payload `' OR '1'='1' -- ` turns the WHERE clause into a tautology, returning alice's rows to
  bob through an endpoint that is only supposed to return the caller's own. This is a
  SQL-injection-driven **authorization bypass**, not just a generic data leak, because the owner
  filter is exactly what the injection defeats.
- **Fixed:** `cde57d6` — both `owner` and the LIKE pattern are now bound
  as parameters.
- **Regression test:** `test_V3_sql_injection_no_longer_bypasses_owner_filter` +
  `test_V3_sql_injection_payload_is_treated_as_literal_text`. Re-verified end-to-end in
  `tests/test_authz_e2e.py::test_v3_sql_injection_no_longer_bypasses_owner_filter_on_resource_service`.

### V4 — Confused deputy across Processing Service ↔ Resource Service (CWE-441) — the composition vulnerability

This is the vulnerability required to stem specifically from composing the three components; it
cannot exist in a single-process version of this application.

- **Component:** Processing Service (acting on the Resource Service with its own elevated
  credentials).
- **Why the Processing Service has elevated credentials at all:** per the brief's architecture
  table, it must "operate only on the data requested for a specific job" — which still requires
  it to be *able* to read arbitrary users' data on the Resource Service's say-so, because the data
  it needs for any given job varies by job. It mints its own `role: "admin"`-equivalent "worker"
  token for calls to the Resource Service (`security.mint_resource_service_worker_token`), rather
  than reusing the end user's own (much narrower) identity. That is itself a least-privilege
  trade-off, discussed below and in the report — the real bug is what happens next.
- **Planted:** `d0303b2` — `POST /jobs/export` read `dataset_id` straight
  from the request body to decide which dataset to fetch with that elevated credential, instead
  of from `g.user["resource"]` — the dataset id the Application API actually bound into *this
  specific, signed* job token.
- **Exploit evidence:** `test_V4_confused_deputy_exports_a_dataset_the_token_did_not_authorize`
  (same commit) — alice, holding a perfectly legitimate `job:export` token scoped to her own
  dataset (`resource=10`), calls the Processing Service **directly** (not through the Application
  API — nothing in the architecture stops a client from reaching it on the network) with
  `dataset_id: 20` (bob's) in the body, and receives bob's data.
- **Why Resource Service's own fixes don't save you here:** even after V1 is fixed, the Resource
  Service correctly grants the Processing Service's elevated worker token (`role: admin`) access
  to any dataset — that's the *intended* trust relationship, not a bug. The authorization decision
  that matters for V4 has to live in the Processing Service itself, because it's the only
  component that knows both "what this specific token actually authorizes" and "what job
  parameters it's about to act on."
- **Fixed:** `0fca8b3` — requires `g.user["resource"]` to be present and
  equal to `body["dataset_id"]`, rejecting with 403 otherwise, *before* minting/using the elevated
  worker credential.
- **Regression test:** `test_V4_confused_deputy_export_is_now_rejected` +
  `test_V4_matching_dataset_id_still_works` + `test_V4_token_without_a_resource_claim_is_rejected`.
  Re-verified end-to-end — deliberately calling the Processing Service directly, the same way the
  original exploit did — in
  `tests/test_authz_e2e.py::test_v4_confused_deputy_fixed_direct_processing_service_call_rejected`.

## Secure design principles applied (≥3 required)

### 1. Least privilege

- **Design decision:** service tokens are minted per-call, per-action, per-resource, with a 60s
  TTL (`services/application-api/security.py::mint_service_token`), never a long-lived broad
  credential; dataset creation always forces `owner = token.sub` server-side rather than trusting
  a client-supplied value.
- **Implementation:** `scope` claims are the narrowest action that satisfies the call
  (`dataset:read` vs `dataset:write` vs `dataset:admin` vs `dataset:export`), and the Resource
  Service rejects any call whose token doesn't carry the specific scope it needs — see
  `docs/ACCESS_CONTROL_MATRIX.md`. The one deliberate exception (the Processing Service's `admin`-
  equivalent worker credential) is called out explicitly in V4's write-up above and in
  `docs/ARCHITECTURE.md`'s "what would need to change for production" as something a real
  deployment should narrow further (e.g. a dedicated `service` role scoped to "read whatever
  `resource` claim is on the job token that's currently being processed", enforced at the Resource
  Service, instead of a blanket `admin`).
- **Test/evidence:** `test_create_dataset_owner_is_forced_from_token_not_body`
  (`services/resource-service/tests/test_functional.py`) — a client cannot create a dataset
  "as" someone else no matter what the request body says.

### 2. Complete mediation

- **Design decision:** every service — not only the Application API — independently verifies
  signature, audience, scope and resource ownership on every request, including requests arriving
  from another trusted service, rather than checking once at the perimeter and trusting it
  downstream.
- **Implementation:** `services/resource-service/app.py::save_export` re-checks
  `record["owner"] != g.user["sub"]` even though the Processing Service already decided which
  dataset to fetch — this is deliberately redundant with the Processing Service's own V4 check, so
  that a bug in either place alone would not be sufficient for a breach (defense in depth). V2's
  fix is itself the clearest demonstration of what happens when this principle is *violated* at
  just one layer: a single component trusting an identity claim without re-verifying it
  compromised the whole chain, even though the other two services verified signatures correctly.
- **Test/evidence:** `services/resource-service/tests/test_functional.py::test_missing_token_rejected`;
  every `require_scope`/`require_session_auth` path has a corresponding 401/403 test; V1–V4's
  regression tests collectively prove this holds at each service independently.

### 3. Fail-safe defaults

- **Design decision:** every authorization decision in the system defaults to deny — missing
  token → 401, wrong audience → 403, insufficient scope → 403, resource id present but not owned
  → 403, unknown resource → 404 (never silently return partial/empty success); V4's fix
  specifically treats a *missing* `resource` claim as authorizing nothing, not everything.
- **Implementation:** `services/application-api/users.py::verify_password` returns `None` (not an
  exception, not a partial match) on any lookup/compare failure, and the login endpoint returns
  the same generic "invalid credentials" for both an unknown user and a wrong password, so neither
  path leaks which one occurred; `services/processing-service/app.py::run_export_job` rejects
  unsupported formats and missing `dataset_id` before any downstream call is made at all.
- **Test/evidence:** `test_login_wrong_password`/`test_login_unknown_user`
  (`services/application-api/tests/test_functional.py`, both expect the same 401);
  `test_V4_token_without_a_resource_claim_is_rejected`
  (`services/processing-service/tests/test_security.py`); `test_missing_token_rejected`
  (resource-service and processing-service test suites).

## Controlled supply chain attack (optional, attempted)

See `packages/exportkit-malicious/README.md` and the "External dependency" / "Trust boundaries"
sections of `docs/ARCHITECTURE.md` for the full design. Summary:

- **Where the malicious code enters:** entirely through `packages/exportkit-malicious`'s own
  `to_csv`/`to_json` functions, i.e. through the package installation path — nothing in
  `services/processing-service/app.py` was edited to accommodate it. In Experiment B the wheel is
  installed by the normal Dockerfile after the consumer explicitly approves its identity and digest.
- **Experiment B (implemented and run: `python scripts/experiment_b.py`, evidence in
  `artifacts/experiment-b/`).** An isolated docker-compose project (own network, host ports
  6001-6003) models a compromised supplier release that the consumer then accepts:
  1. *Explicit approval.* The real manifest rejects the malicious wheel; the separate
     `manifest/experiment_b/approved_packages.json` approves its name, version and sha256, so the
     install-time gate admits it in this run only (`step1-approval.txt`).
  2. *Normal workflow, before the boundary* (`before-boundary.json`). The Processing Service as it
     was before output validation existed (commit `0fca8b3`) plus the approved malicious wheel:
     alice's ordinary export through the Application API returns HTTP 201 and its content contains
     an extra `_leaked_secret` column holding `RESEARCH_WORKSPACE_JWT_SECRET`; the same secret is
     also stored in the Resource Service. The unauthorized access **succeeded**; this file is the
     preserved evidence.
  3. *Boundary corrected, run repeated* (`after-boundary.json`). The current Processing Service,
     whose `validate_export_output` re-parses what `exportkit` actually produced and rejects any
     field beyond the authorized record's keys, with the same approved malicious wheel: the export is
     refused (HTTP 422), the secret is not in the response and nothing is stored.
  4. *Legitimate job still completes* (`benign-control.json`): current code plus the real benign
     wheel returns HTTP 201 with no extra field.
  The check is on the dependency's **output**, not its filename or version (the brief is explicit
  that the latter "is not a sufficient runtime defence" — the malicious wheel's name and version
  are identical to the real one). Unit-level versions of the same checks are in
  `services/processing-service/tests/test_supply_chain.py`.
- **What the compromised component can access** (measured by a read-only probe run inside the
  Processing Service container in each phase, `what_the_processing_service_container_can_reach` in
  the JSON files): it runs as the non-root user `worker` (uid 999, set in the Dockerfile after this
  experiment first showed uid 0); its environment holds `RESEARCH_WORKSPACE_JWT_SECRET` and
  `RESOURCE_SERVICE_URL`; no Resource Service database file is visible; the only non-pseudo mounts
  are Docker's `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf` (no volumes); it can reach the
  Resource Service and Application API over HTTP (the Resource Service answers 401 to an
  unauthenticated `/datasets`); and it can open outbound TCP connections to the internet.
- **Residual risk (be explicit about what is *not* contained):** the output validation blocks one
  exfiltration channel — smuggling the secret out through the export content. It does not stop
  malicious code that already runs inside the Processing Service process from using the shared
  secret directly (it is in the process environment and the Resource Service is reachable) or from
  sending it out over the network (outbound internet access is open). With a single shared HS256
  secret that risk is inherent; the production fix is per-service asymmetric keys, a narrowed
  Processing-Service credential and egress filtering (see "What would need to change for a
  production release" in `docs/ARCHITECTURE.md`).
- **Experiment A (install-time integrity gate, implemented):**
  `manifest/approved_packages.json` + `scripts/verify_manifest.py` pin the benign wheel's exact
  sha256, controlled by the consumer (this project), not the supplier. The gate is part of the
  installation path itself: the Processing Service `Dockerfile` and the Jenkins "Build & install"
  stage run `verify_manifest.py` on the wheel and only then `pip install` it, so a mismatch fails
  the build (`artifacts/docker-build-malicious-wheel-rejected.txt` is the saved evidence of a
  Docker build being refused with the malicious wheel in place;
  `services/processing-service/tests/test_supply_chain.py` also rewrites the approved wheel's
  bytes while keeping its name and version and shows the digest check rejects it). The malicious wheel
  declares the identical name+version but a different digest and is rejected
  (`python scripts/verify_manifest.py packages/exportkit-malicious/dist/*.whl` exits 1 — see
  README.md for the exact command and `packages/*/dist/` for the two committed wheels used).
