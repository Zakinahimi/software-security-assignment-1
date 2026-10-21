# Research Workspace — Software Security Assignment I

A small multi-tier application: researchers upload private datasets and request exports of them.
Built to satisfy AU's Software Security Assignment I (see
`Assignemnt1/Software_Security_Assignment_I.pdf`): three independently-running components talking
over HTTP, JWT-based authentication/authorization across component boundaries, a real external
helper package, four intentionally planted-then-fixed vulnerabilities, a controlled supply-chain
attack experiment, and a Jenkins CI/CD gate.

Full write-up: `docs/report/Assignment_I_Report.docx`. Architecture: `docs/ARCHITECTURE.md`.
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
pip install -r requirements-dev.txt          # shared dev/test tooling
pip install -e packages/exportkit            # install the external dependency (benign build)
for svc in application-api resource-service processing-service; do
  pip install -r services/$svc/requirements.txt
done
```

### 2. Run the three services (each in its own terminal, or see `scripts/run_dev.sh`)

```bash
./scripts/run_dev.sh          # starts all three with seeded SQLite data, foreground logs interleaved
```

This seeds three accounts: `alice` / `Alice#Pass1` (user), `bob` / `Bob#Pass1` (user),
`admin` / `Admin#Pass1` (admin), each from `scripts/seed.py` (also run automatically on first
start of each service).

### 3. Use the command-line client

```bash
python scripts/client.py login alice Alice#Pass1
python scripts/client.py upload alice "lab-results" '{"ph": 7.1, "temp_c": 36.6}'
python scripts/client.py list alice
python scripts/client.py export alice <dataset_id>
python scripts/client.py list bob                 # bob cannot see alice's datasets
python scripts/client.py admin-list admin          # admin sees everyone's datasets
```

A ready-to-import Postman/Insomnia-style collection is at `scripts/api-collection.json`, and plain
curl examples are in `docs/ARCHITECTURE.md`.

### 4. Run the tests

```bash
pytest -q                      # unit + functional tests per service
pytest -q tests/               # cross-service integration + the V1–V4 security tests
```

### 5. Run everything in Docker (fresh environment, matches what Jenkins does)

```bash
docker compose up --build -d
docker compose run --rm test-runner pytest -q
docker compose down -v
```

### 6. Build and verify the external packages, and run the supply-chain experiment

```bash
./scripts/build_packages.sh                 # builds benign + malicious exportkit wheels
python scripts/verify_manifest.py packages/exportkit/dist/*.whl      # passes (approved digest)
python scripts/verify_manifest.py packages/exportkit-malicious/dist/*.whl  # fails: digest mismatch
pytest -q tests/test_supply_chain.py -v
```

## Repository contents checklist (per the assignment's Submission section)

- [x] README with purpose and exact build/seed/run/test commands (this file)
- [x] Initial lifecycle plan committed before feature code, full git history kept (`docs/SSDLC_PLAN.md`, first commit)
- [x] Architecture description, threat model, access-control matrix (`docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/ACCESS_CONTROL_MATRIX.md`)
- [x] Jenkins pipeline definition (`Jenkinsfile`)
- [x] Helper package + malicious version + approval manifest (`packages/exportkit*`, `manifest/approved_packages.json`)
- [x] Written report (`docs/report/Assignment_I_Report.docx`)
- [x] AI usage declaration (`docs/AI_USE_DECLARATION.md`)
