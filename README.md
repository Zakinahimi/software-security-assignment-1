# Research Workspace — Software Security Assignment I

A small multi-tier application: researchers upload private datasets and request exports of them.
Built to satisfy AU's Software Security Assignment I (see
`Assignemnt1/Software_Security_Assignment_I.pdf`): three independently-running components talking
over HTTP, JWT-based authentication/authorization across component boundaries, a real external
helper package, four intentionally planted-then-fixed vulnerabilities, a controlled supply-chain
attack experiment, and a Jenkins CI/CD gate.

Step-by-step test guide: `docs/TESTING_GUIDE.md`. Full write-up: `docs/report/Assignment_I_Report.docx`. Architecture: `docs/ARCHITECTURE.md`.
Threat model: `docs/THREAT_MODEL.md`. Access control matrix: `docs/ACCESS_CONTROL_MATRIX.md`.
SSDLC plan (committed first, before feature code): `docs/SSDLC_PLAN.md`. AI usage declaration:
`docs/AI_USE_DECLARATION.md`.

## Architecture

```
User (CLI / curl) ──▶ Application API (:5001) ──▶ Resource Service (:5002)  [SQLite: users, datasets]
                              │                           ▲
                              ▼                           │ read allowed records / save export
                      Processing Service (:5003) ─────────┘
                              │
                              ▼
                      exportkit (installed package) ──▶ External package registry (local dir)
```

- **Application API** — authenticates users (username/password → JWT), routes requests.
- **Resource Service** — owns dataset rows and export results in SQLite; enforces per-user
  ownership and role checks on every request it serves, including requests forwarded by the
  Processing Service.
- **Processing Service** — runs export jobs using the `exportkit` external package; independently
  re-verifies the caller's JWT rather than trusting fields in the request body.
- **exportkit** — a standalone, pip-installable helper package (`packages/exportkit`) that formats
  dataset records as CSV/JSON. A deliberately malicious build (`packages/exportkit-malicious`)
  exists for the supply-chain experiment.

## Components & ports

| Component | Port | Source |
|---|---|---|
| Application API | 5001 | `services/application-api` |
| Resource Service | 5002 | `services/resource-service` |
| Processing Service | 5003 | `services/processing-service` |

## Quickstart

### 1. Set up a virtualenv and install everything

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt          # shared dev/test tooling (pytest, ruff, pip-audit, requests)
python scripts/verify_manifest.py packages/exportkit/dist/*.whl   # integrity gate: must print APPROVED
pip install --no-deps packages/exportkit/dist/*.whl               # install the external dependency (benign wheel)
for svc in application-api resource-service processing-service; do
  pip install -r services/$svc/requirements.txt
done
```

### 2. Seed and run the three services (each in its own terminal, or see `scripts/run_dev.sh`)

```bash
python scripts/seed.py        # (re)creates both SQLite stores with the seeded accounts/datasets
./scripts/run_dev.sh          # starts all three; each service also re-seeds its own store on start
```

This seeds three accounts: `alice` / `Alice#Pass1` (user), `bob` / `Bob#Pass1` (user),
`admin` / `Admin#Pass1` (admin), plus synthetic datasets for alice (ids 1, 2) and bob (id 3).

### 3. Use the command-line client

```bash
python scripts/client.py login alice Alice#Pass1
python scripts/client.py upload alice "lab-results" '{"ph": 7.1, "temp_c": 36.6}'
python scripts/client.py list alice
python scripts/client.py export alice <dataset_id>
python scripts/client.py list bob                 # bob cannot see alice's datasets
python scripts/client.py admin-list admin          # admin sees everyone's datasets
```

A ready-to-import Postman/Insomnia-style collection is at `scripts/api-collection.json`. Plain
curl equivalent of the same flow:

```bash
TOKEN=$(curl -s -X POST localhost:5001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice#Pass1"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s -X POST localhost:5001/datasets -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"curl-demo","payload":{"k":"v"}}'

curl -s localhost:5001/datasets -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:5001/datasets/1/export -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"format":"csv"}'
```

### 4. Run the tests

Each service's unit/security tests must be run from within that service's own directory (their
`conftest.py` imports each service's `app.py` as the top-level module `app`, so running them all
from one `pytest` invocation at the repo root would make the second and third `import app`s reuse
the first service's cached module instead of their own):

```bash
for svc in resource-service application-api processing-service; do
  (cd services/$svc && python -m pytest -q)         # 16 / 11 / 13 tests respectively
done
```

The root-level `tests/` suite is cross-service integration + the V1–V4 authorization regression
tests, run against three **real, running** instances of the services (either from step 2/5, or the
docker-compose stack):

```bash
pytest -q tests/                                    # 8 end-to-end tests
```

### 5. Run everything in Docker (fresh environment — what Jenkins does)

```bash
mkdir -p reports
docker compose up --build -d resource-service processing-service application-api
docker compose --profile test build test-runner
docker compose --profile test run --name e2e-runner test-runner     # runs tests/ against the real containers
docker cp e2e-runner:/reports/e2e-results.xml reports/e2e-results.xml   # saves the JUnit XML
docker rm e2e-runner
docker compose down -v
```

### 6. Verify the supply-chain integrity gate and run the attack experiment

The two wheels used below (`packages/exportkit/dist/*.whl`, `packages/exportkit-malicious/dist/*.whl`)
are committed to the repo so their digests are stable and reviewable, exactly matching
`manifest/approved_packages.json`:

```bash
python scripts/verify_manifest.py packages/exportkit/dist/*.whl            # APPROVED
python scripts/verify_manifest.py packages/exportkit-malicious/dist/*.whl  # REJECTED: digest mismatch
(cd services/processing-service && python -m pytest -q -v tests/test_supply_chain.py)
```

**Experiment B — an explicitly approved compromised update (needs Docker).** In an isolated
docker-compose project (`docker-compose.experiment-b.yml`, host ports 6001-6003, own network) the
script approves the malicious wheel's name, version and digest in a separate manifest
(`manifest/experiment_b/approved_packages.json`, used by nothing else), builds the Processing Service
with that wheel, runs the normal workflow (login → upload → export through the Application API)
and records what happens in three phases, plus what the compromised container can reach:

```bash
python scripts/experiment_b.py       # ~3-5 minutes; writes artifacts/experiment-b/*.json
```

| Phase | Processing Service | Wheel | Expected |
|---|---|---|---|
| `before-boundary` | source of commit `0fca8b3` (before output validation existed) | malicious, approved | leak **succeeds**: the JWT secret is in the export and stored in the Resource Service (evidence preserved) |
| `after-boundary` | current code (output validation) | malicious, approved | export refused with HTTP 422, nothing stored |
| `benign-control` | current code | real benign wheel | export completes (HTTP 201), no secret |

The script prints `PASS`/`FAIL` for each and exits non-zero if any phase behaves differently.

(`scripts/build_packages.sh` can regenerate fresh wheels if you want to re-run the attack with new
bytes, but — as it documents — a fresh rebuild will *not* reproduce the same digest as the
committed wheels, so you would need to re-approve the new benign digest in the manifest
afterwards; it's not needed just to see the gate work.)

### 7. Static analysis and dependency audit (what the Jenkins pipeline's gate runs)

```bash
ruff check services packages scripts tests                              # clean
for svc in resource-service application-api processing-service; do
  pip-audit -r services/$svc/requirements.txt                           # "No known vulnerabilities found"
done
```

## CI/CD

`Jenkinsfile` runs on every push/PR: build & install → static analysis (`ruff`) → dependency
analysis (`pip-audit`) → supply-chain integrity gate (`scripts/verify_manifest.py`) → per-service
unit tests → a fresh docker-compose environment running the functional/authorization test suite.
The Processing Service container (which runs third-party code) runs as a non-root user.
It fails the build on any failing test, any ruff finding, any pip-audit finding (pip-audit has no
severity threshold, so every finding blocks), a broken dependency set (`pip check`), or an
unexpected integrity-gate result, and archives all reports under `reports/` as Jenkins artifacts.
The wheel is verified against the manifest *before* it is installed (both in the Jenkins
"Build & install" stage and in the Processing Service `Dockerfile`).

Note: the `Jenkinsfile` has not been completed on a Jenkins server from this repository. Every
command it runs was executed by hand (also in a fresh virtualenv) with the results saved in
`artifacts/` (see below). Set it up as a Multibranch Pipeline job (branch + pull-request
discovery and a webhook) so that it runs on every push and pull request; the job needs python3 and
a docker CLI with the compose plugin on the agent, and the Timestamper and JUnit plugins.

## Saved test and analysis results (`artifacts/`)

Results of the last full run (the same commands the pipeline runs): per-service JUnit XML
(`unit-*.xml`), the end-to-end JUnit XML from the docker-compose stack (`e2e-results-docker.xml`),
`ruff.txt`, `pip-audit-*.json`, `integrity-gate.txt` (benign wheel APPROVED, malicious wheel
REJECTED) and `docker-build-malicious-wheel-rejected.txt` (the Processing Service image build
refusing the malicious wheel), and `experiment-b/` (the three phases of Experiment B and the access
probe of the compromised container). `reports/` is where a fresh run writes its output and is git-ignored.

## Repository contents checklist (per the assignment's Submission section)

- [x] README with purpose and exact build/seed/run/test commands (this file)
- [x] Initial lifecycle plan committed before feature code, full git history kept (`docs/SSDLC_PLAN.md`, first commit)
- [x] Architecture description, threat model, access-control matrix (`docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/ACCESS_CONTROL_MATRIX.md`)
- [x] Jenkins pipeline definition (`Jenkinsfile`)
- [x] Helper package + malicious version + approval manifest (`packages/exportkit*`, `manifest/approved_packages.json`, Experiment B in `manifest/experiment_b/` and `scripts/experiment_b.py`)
- [x] Written report (`docs/report/Assignment_I_Report.docx`)
- [x] AI usage declaration (`docs/AI_USE_DECLARATION.md`, following the AU GAI declaration form)
- [x] Saved test and analysis results (`artifacts/`)
