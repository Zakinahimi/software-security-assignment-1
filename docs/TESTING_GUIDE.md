# Testing guide — step by step

Everything below is run from the repository root. Needed: Python 3.12, Docker Desktop (running) and
git. The expected result is written under each block. Run steps 1-2 first; steps 3-7 can then be
run in any order.

**Copying commands (macOS / zsh):** the code blocks contain no `#` comments on purpose. Interactive
zsh does not treat `#` as a comment, so a pasted `# note` line gives `command not found: #`, and a
`#` after a command (for example `pytest -q tests/ # 8 passed`) is passed to the command as
arguments. Copy only the commands, or run `setopt interactivecomments` once in the terminal.

## 1. One-time setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/verify_manifest.py packages/exportkit/dist/*.whl
pip install --no-deps packages/exportkit/dist/*.whl
for svc in resource-service application-api processing-service; do pip install -r services/$svc/requirements.txt; done
pip check
```
Expected: `APPROVED: exportkit==1.0.0 matches the manifest ...` from the manifest check, and
`No broken requirements found.` from `pip check`. The pip installs can take a minute or two; if
packages are already installed they just print "Requirement already satisfied".

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

You need two terminals.

**Terminal 1 — the servers.** Run:

```bash
source .venv/bin/activate
python scripts/seed.py
./scripts/run_dev.sh
```
After `seed.py` prints the seeded accounts, `run_dev.sh` starts the three services and then **the
terminal stands still. That is correct:** the services are running in the foreground and print their
request logs here. Leave it open. Port 5001-5003 must be free (`docker compose down -v` first if the
Docker stack is up).

**Terminal 2 — the client.** Open a new terminal in the repository root and run:

```bash
source .venv/bin/activate
python scripts/client.py list alice
python scripts/client.py upload alice "my-data" '{"x": 1}'
python scripts/client.py export alice 1 json
python scripts/client.py get-export alice 1
python scripts/client.py admin-list admin
pytest -q tests/
```
Expected: `list alice` gives HTTP 200 with datasets 1 and 2; `upload` gives HTTP 201 with owner alice;
`export` gives HTTP 201 (this request goes through all three components); `get-export` gives HTTP
200; `admin-list` gives HTTP 200 with everybody's datasets; `pytest` prints `8 passed`.

Requests that must be **refused**:

```bash
python scripts/client.py get bob 1
python scripts/client.py get-export bob 1
python scripts/client.py admin-delete bob 3
```
Expected: HTTP 403 each time (bob cannot read alice's dataset — this is V1 — or her export, and an
ordinary user cannot use the admin action). Then the admin may do it:

```bash
python scripts/client.py admin-delete admin 3
```
Expected: HTTP 200.

**V2 — forged admin session token, signed with a wrong secret.**

```bash
FORGED=$(python -W ignore - <<'EOF'
import jwt, time
now = int(time.time())
print(jwt.encode({"sub": "mallory", "role": "admin", "aud": ["application-api"], "scope": ["session"], "iat": now, "exp": now + 1800}, "wrong-secret", algorithm="HS256"))
EOF
)
curl -s -o /dev/null -w "%{http_code}\n" "localhost:5001/datasets?all=true" -H "Authorization: Bearer $FORGED"
```
Expected: `401`.

**V3 — SQL injection in the search, sent straight to the Resource Service as bob.**

```bash
BOB=$(python -W ignore - <<'EOF'
import jwt, time
now = int(time.time())
print(jwt.encode({"sub": "bob", "role": "user", "aud": ["resource-service"], "scope": ["dataset:read"], "iat": now, "exp": now + 60}, "dev-only-shared-secret-change-me-32bytes!!", algorithm="HS256"))
EOF
)
curl -s -G "localhost:5002/datasets/search" --data-urlencode "q=' OR '1'='1' -- " -H "Authorization: Bearer $BOB"
```
Expected: `[]` (before the fix this returned alice's rows too).

**V4 — confused deputy.** Alice's job token is bound to dataset 1; she calls the Processing Service
directly and asks for bob's dataset 3.

```bash
ALICE_JOB=$(python -W ignore - <<'EOF'
import jwt, time
now = int(time.time())
print(jwt.encode({"sub": "alice", "role": "user", "aud": ["processing-service"], "scope": ["job:export"], "resource": 1, "iat": now, "exp": now + 60}, "dev-only-shared-secret-change-me-32bytes!!", algorithm="HS256"))
EOF
)
curl -s -w "  HTTP %{http_code}\n" -X POST localhost:5003/jobs/export -H "Authorization: Bearer $ALICE_JOB" -H 'Content-Type: application/json' -d '{"dataset_id": 3, "format": "csv"}'
```
Expected: `{"error":"forbidden: this token does not authorize a job on this dataset"}` and `HTTP 403`.

To see each exploit *working*, look at the planting commits (`git show <hash>:<path>`); the commit
hashes are in `docs/THREAT_MODEL.md`.

When done, stop terminal 1 with Ctrl-C.

## 4. The same tests in a fresh Docker environment (what the pipeline does)

```bash
mkdir -p reports
docker compose up --build -d resource-service processing-service application-api
docker compose --profile test build test-runner
docker compose --profile test run --name e2e-runner test-runner
docker cp e2e-runner:/reports/e2e-results.xml reports/e2e-results.xml
docker rm e2e-runner
docker compose down -v
```
Expected: `8 passed` from the test runner, and `reports/e2e-results.xml` exists afterwards.

## 5. Static analysis and dependency audit

```bash
ruff check services packages scripts tests
for svc in resource-service application-api processing-service; do
  pip-audit -r services/$svc/requirements.txt
done
pip-audit -r requirements-dev.txt
```
Expected: `All checks passed!` and `No known vulnerabilities found` four times. (`pip-audit` needs
internet access.)

## 6. Supply chain, Experiment A — the install-time integrity gate

```bash
python scripts/verify_manifest.py packages/exportkit/dist/*.whl
python scripts/verify_manifest.py packages/exportkit-malicious/dist/*.whl
(cd services/processing-service && python -m pytest -q -v tests/test_supply_chain.py)
```
Expected: the first prints `APPROVED`; the second prints `REJECTED: digest mismatch for
exportkit==1.0.0` (same name and version, different bytes); the tests print `6 passed`.

The Docker build itself must refuse the malicious wheel:

```bash
tmp=$(mktemp -d)
mkdir -p $tmp/services $tmp/packages/exportkit/dist $tmp/manifest $tmp/scripts
cp -R services/processing-service $tmp/services/
cp manifest/approved_packages.json $tmp/manifest/
cp scripts/verify_manifest.py $tmp/scripts/
cp packages/exportkit-malicious/dist/*.whl $tmp/packages/exportkit/dist/
docker build -f $tmp/services/processing-service/Dockerfile $tmp
rm -rf $tmp
```
Expected: the build **fails** with `REJECTED: digest mismatch for exportkit==1.0.0`.

## 7. Supply chain, Experiment B — approved compromised update, isolated run

```bash
python scripts/experiment_b.py
```
Takes about 3-5 minutes and needs Docker. Expected at the end:

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
- `what_the_processing_service_container_can_reach` inside each JSON — user id, environment variable names, visible database files, mounts, and which services and the internet it can reach.

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
