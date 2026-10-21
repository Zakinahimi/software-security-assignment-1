#!/usr/bin/env bash
# Rebuilds the exportkit wheels (benign + malicious fixture) and prints their digests.
#
# NOTE: wheel builds are not byte-for-byte reproducible by default (per-file timestamps embedded
# in the zip), so a freshly rebuilt wheel's sha256 will generally NOT match the one pinned in
# manifest/approved_packages.json or the one committed at packages/exportkit/dist/. That mismatch
# is expected and is not itself a sign of tampering — it's just how `pip wheel` works without
# SOURCE_DATE_EPOCH pinning. The committed wheels under packages/*/dist/ are the actual artifacts
# the manifest and the test suite reference; this script exists for documentation/convenience and
# for anyone who wants to re-run the attack-and-detect loop end to end with fresh bytes (in which
# case, re-approve the new digest in the manifest for the benign build afterwards).
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf packages/exportkit/dist packages/exportkit-malicious/dist
python -m pip wheel --no-deps -w packages/exportkit/dist packages/exportkit
python -m pip wheel --no-deps -w packages/exportkit-malicious/dist packages/exportkit-malicious

echo
echo "Benign wheel:"
shasum -a 256 packages/exportkit/dist/*.whl
echo "Malicious fixture wheel:"
shasum -a 256 packages/exportkit-malicious/dist/*.whl
