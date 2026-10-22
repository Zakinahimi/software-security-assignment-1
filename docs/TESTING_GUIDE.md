# Testing guide — step by step

Everything below is run from the repository root. Needed: Python 3.12, Docker Desktop (running) and
git. The expected output after each command is what a correct run prints. Run the steps in order;
steps 4-8 are independent of each other once step 1 is done.

## 1. One-time setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/verify_manifest.py packages/exportkit/dist/*.whl      # must print: APPROVED: exportkit==1.0.0 ...
pip install --no-deps packages/exportkit/dist/*.whl
for svc in resource-service application-api processing-service; do pip install -r services/$svc/requirements.txt; done
pip check                                                            # No broken requirements found.
```

## 2. Unit and security tests (one service at a time)

```bash
for svc in resource-service application-api processing-service; do
  (cd services/$svc && python -m pytest -q)
done
```
Expected: `16 passed`, `11 passed`, `13 passed`. The `test_V1…`, `test_V2…`, `test_V3…` and `test_V4…`
tests are the regression tests for the four planted vulnerabilities after their fixes;
`test_supply_chain.py` holds the supply-chain tests (malicious fixture, output validation, and the
integrity gate rejecting a wheel whose bytes were changed).

## 3. Run the real system and try it by hand

Terminal 1:
```bash
source .venv/bin/activate
python scripts/seed.py          # seeds alice/bob/admin and their datasets (ids 1, 2 = alice, 3 = bob)
./scripts/run_dev.sh            # starts the 3 services on 5001 / 5002 / 5003 (leave it running)
```
Terminal 2 (repo root, venv active):

```bash
# normal use
python scripts/client.py list alice                  # HTTP 200, alice's datasets 1 and 2 only
python scripts/client.py upload alice "my-data" '{"x": 1}'   # HTTP 201, owner is alice
python scripts/client.py export alice 1 json         # HTTP 201 — the flow through all 3 components
python scripts/client.py get-export alice 1          # HTTP 200, the stored export
python scripts/client.py admin-list admin            # HTTP 200, every user's datasets
pytest -q tests/                                     # 8 end-to-end tests against the running services

# authorization (each of these must be refused)
python scripts/client.py get bob 1                   # V1: HTTP 403 (bob reading alice's dataset)
python scripts/client.py get-export bob 1            # HTTP 403 (bob reading alice's export)
python scripts/client.py admin-delete bob 3          # HTTP 403 (ordinary user cannot use the admin action)
python scripts/client.py admin-delete admin 3        # HTTP 200 (admin can)
```

The four planted vulnerabilities, each attacked by hand against the fixed code (all must fail):

```bash
# V2 — forged session token claiming role=admin, signed with a wrong secret  -> 401
FORGED=$(python -W ignore - <<'EOF'
import jwt, time
now = int(time.time())
print(jwt.encode({"sub": "mallory", "role": "admin", "aud": ["application-api"], "scope": ["session"], "iat": now, "exp": now + 1800}, "wrong-secret", algorithm="HS256"))
EOF
)
curl -s -o /dev/null -w "%{http_code}\n" "localhost:5001/datasets?all=true" -H "Authorization: Bearer $FORGED"

# V3 — SQL injection in the search, sent straight to the Resource Service as bob -> only bob's rows (here: none match)
BOB=$(python -W ignore - <<'EOF'
import jwt, time
now = int(time.time())
print(jwt.encode({"sub": "bob", "role": "user", "aud": ["resource-service"], "scope": ["dataset:read"], "iat": now, "exp": now + 60}, "dev-only-shared-secret-change-me-32bytes!!", algorithm="HS256"))
EOF
)
curl -s -G "localhost:5002/datasets/search" --data-urlencode "q=' OR '1'='1' -- " -H "Authorization: Bearer $BOB"
# prints []  (before the fix this returned alice's rows too)

# V4 — alice's job token is bound to dataset 1; she calls the Processing Service directly asking for bob's dataset 3 -> 403
ALICE_JOB=$(python -W ignore - <<'EOF'
import jwt, time
now = int(time.time())
print(jwt.encode({"sub": "alice", "role": "user", "aud": ["processing-service"], "scope": ["job:export"], "resource": 1, "iat": now, "exp": now + 60}, "dev-only-shared-secret-change-me-32bytes!!", algorithm="HS256"))
EOF
)
curl -s -w "  HTTP %{http_code}\n" -X POST localhost:5003/jobs/export -H "Authorization: Bearer $ALICE_JOB" -H 'Content-Type: application/json' -d '{"dataset_id": 3, "format": "csv"}'
```
V1 is the `get bob 1` line above. To see each exploit *working*, check out the planting commit in a
scratch copy (`git show <hash>:<path>`); the commit hashes are in `docs/THREAT_MODEL.md`.

Stop terminal 1 with Ctrl-C when done.

## 4. The same tests in a fresh Docker environment (what the pipeline does)

```bash
mkdir -p reports
docker compose up --build -d resource-service processing-service application-api
docker compose --profile test build test-runner
docker compose --profile test run --name e2e-runner test-runner     # expect: 8 passed
docker cp e2e-runner:/reports/e2e-results.xml reports/e2e-results.xml
docker rm e2e-runner
docker compose down -v
```

## 5. Static analysis and dependency audit

```bash
ruff check services packages scripts tests                    # All checks passed!
for svc in resource-service application-api processing-service; do
  pip-audit -r services/$svc/requirements.txt                 # No known vulnerabilities found
done
```
(`pip-audit` needs internet access.)

## 6. Supply chain, Experiment A — the install-time integrity gate

```bash
python scripts/verify_manifest.py packages/exportkit/dist/*.whl            # APPROVED, exit code 0
python scripts/verify_manifest.py packages/exportkit-malicious/dist/*.whl  # REJECTED: digest mismatch, exit code 1
(cd services/processing-service && python -m pytest -q -v tests/test_supply_chain.py)   # 6 passed
```
The Docker build itself refuses the malicious wheel (it must fail with `REJECTED: digest mismatch`):

```bash
tmp=$(mktemp -d)
mkdir -p $tmp/services $tmp/packages/exportkit/dist $tmp/manifest $tmp/scripts
cp -R services/processing-service $tmp/services/
cp manifest/approved_packages.json $tmp/manifest/
cp scripts/verify_manifest.py $tmp/scripts/
cp packages/exportkit-malicious/dist/*.whl $tmp/packages/exportkit/dist/    # the swapped-in artifact
docker build -f $tmp/services/processing-service/Dockerfile $tmp            # fails: exit code 1
rm -rf $tmp
```

## 7. Supply chain, Experiment B — approved compromised update, isolated run

```bash
python scripts/experiment_b.py       # about 3-5 minutes; needs Docker
```
Expected at the end:
```
[PASS] before-boundary: the attempted leak succeeded (evidence preserved)
[PASS] after-boundary: the leak is blocked (HTTP 422, secret not in response)
[PASS] benign-control: the legitimate job still completes (HTTP 201, no secret)
```
What to look at afterwards (all in `artifacts/experiment-b/`):
- `step1-approval.txt` — the real manifest rejects the malicious wheel, the experiment manifest approves it.
- `before-boundary.json` — `_leaked_secret` column in the export and `secret_in_stored_export_(resource_service): true`.
- `after-boundary.json` — HTTP 422, nothing stored.
- `benign-control.json` — HTTP 201, no extra column.
- `what_the_processing_service_container_can_reach` inside each JSON — user id, environment variable names, visible database files, mounts, and which services/the internet it can reach.

The script starts and removes its own containers (project `experiment-b`, ports 6001-6003); the
normal stack on 5001-5003 does not need to be stopped.

## 8. The CI pipeline

`Jenkinsfile` runs, in order: build and install (wheel checked against the manifest first, then
`pip check`), `ruff`, `pip-audit`, the integrity-gate control case (the malicious wheel must be
rejected), the per-service unit tests, and the fresh docker-compose environment with the
end-to-end tests; it archives `reports/**`. To run it on a Jenkins server create a Multibranch
Pipeline job for this repository (branch and pull-request discovery, webhook trigger). The agent
needs python3, a docker CLI with the compose plugin and access to a Docker daemon, and the Pipeline,
Git, JUnit and Timestamper plugins. Every command in the pipeline is also listed in steps 1, 2, 4,
5 and 6 above, so the same results can be produced by hand; they are saved in `artifacts/`.
