#!/usr/bin/env bash
# Starts all three services in the background (foreground logs interleaved, Ctrl-C stops all),
# each self-seeding its own SQLite store on startup. Run from the repo root after installing
# dependencies per README.md.
set -euo pipefail
cd "$(dirname "$0")/.."

export RESEARCH_WORKSPACE_JWT_SECRET="${RESEARCH_WORKSPACE_JWT_SECRET:-dev-only-shared-secret-change-me-32bytes!!}"
export RESOURCE_SERVICE_URL="http://localhost:5002"
export PROCESSING_SERVICE_URL="http://localhost:5003"

pids=()
cleanup() {
  echo
  echo "stopping services..."
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

echo "starting resource-service on :5002"
(cd services/resource-service && python app.py) &
pids+=($!)

sleep 1

echo "starting processing-service on :5003"
(cd services/processing-service && python app.py) &
pids+=($!)

echo "starting application-api on :5001"
(cd services/application-api && python app.py) &
pids+=($!)

echo
echo "seeded accounts: alice/Alice#Pass1 (user), bob/Bob#Pass1 (user), admin/Admin#Pass1 (admin)"
echo "try: python scripts/client.py list alice"
echo "press Ctrl-C to stop all three services"
wait
