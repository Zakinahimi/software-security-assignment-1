#!/usr/bin/env python3
"""Experiment B - a compromised supplier update that the consumer explicitly approves.

Runs in an isolated environment (its own docker-compose project "experiment-b", its own network and
its own host ports 6001-6003); the normal stack, manifest and tests are never touched.

What it does, per the assignment text:

1. Explicit approval. The real manifest (manifest/approved_packages.json) rejects the malicious
   fixture wheel (Experiment A). manifest/experiment_b/approved_packages.json approves the
   malicious wheel's identity AND digest as if it were a new authentic version, so the install-time
   gate lets it through in this isolated run.
2. Normal workflow. Three phases drive the normal workflow (login -> upload -> export through the
   Application API) against a freshly built stack:
     before-boundary  Processing Service as it was before output validation was added (commit
                      0fca8b3) + approved malicious wheel   -> the attempted leak is expected to
                                                              succeed; evidence is preserved
     after-boundary   current Processing Service (output validation) + approved malicious wheel
                                                           -> the leak must be blocked
     benign-control   current Processing Service + real, benign wheel
                                                           -> the legitimate job must complete
3. What the compromised component can reach. In each phase a read-only probe runs inside the
   Processing Service container and records its credentials (env var names), visible files and
   volumes, and network reachability.

Evidence is written to artifacts/experiment-b/. Requires a running Docker daemon.

    python scripts/experiment_b.py
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "artifacts" / "experiment-b"
COMPOSE = ["docker", "compose", "-p", "experiment-b", "-f", str(REPO / "docker-compose.experiment-b.yml")]
APP_URL = "http://localhost:6001"
RESOURCE_URL = "http://localhost:6002"
PROCESSING_URL = "http://localhost:6003"
SECRET = "dev-only-shared-secret-change-me-32bytes!!"  # the dev secret from docker-compose.yml

REAL_MANIFEST = "manifest/approved_packages.json"
EXPERIMENT_MANIFEST = "manifest/experiment_b/approved_packages.json"
BENIGN_WHEEL_DIR = "packages/exportkit/dist"
MALICIOUS_WHEEL_DIR = "packages/exportkit-malicious/dist"

PHASES = [
    # (name, git ref of the Processing Service source, wheel dir, manifest)
    ("before-boundary", "0fca8b3", MALICIOUS_WHEEL_DIR, EXPERIMENT_MANIFEST),
    ("after-boundary", "HEAD", MALICIOUS_WHEEL_DIR, EXPERIMENT_MANIFEST),
    ("benign-control", "HEAD", BENIGN_WHEEL_DIR, REAL_MANIFEST),
]

PROBE = r"""
import json, os, socket, urllib.request, urllib.error

def http(url):
    try:
        return urllib.request.urlopen(url, timeout=3).status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception as exc:
        return type(exc).__name__

def can_connect(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return True
    except Exception:
        return False

pseudo = {"proc", "sysfs", "tmpfs", "devpts", "mqueue", "cgroup", "cgroup2", "overlay", "devtmpfs"}
mounts = []
for line in open("/proc/mounts"):
    source, mountpoint, fstype = line.split()[:3]
    if fstype not in pseudo:
        mounts.append(f"{fstype} {mountpoint}")

print(json.dumps({
    "uid": os.getuid(),
    "env_var_names": sorted(k for k in os.environ if k.startswith("RESEARCH_WORKSPACE") or k.endswith("_URL")),
    "jwt_secret_in_process_environment": "RESEARCH_WORKSPACE_JWT_SECRET" in os.environ,
    "resource_service_database_file_visible": [
        p for p in ("/app/data/resource.db", "/app/resource.db", "/data/resource.db") if os.path.exists(p)
    ],
    "non_pseudo_mounts_(volumes_and_bind_mounts)": mounts,
    "resource_service_health_http": http("http://resource-service:5002/health"),
    "resource_service_datasets_without_token_http": http("http://resource-service:5002/datasets"),
    "application_api_health_http": http("http://application-api:5001/health"),
    "outbound_internet_tcp_1.1.1.1:443": can_connect("1.1.1.1", 443),
}, indent=2))
"""


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kwargs)


def build_processing_image(tag: str, app_ref: str, wheel_dir: str, manifest: str) -> None:
    """Builds the Processing Service image from `app_ref`'s service source, with the CURRENT
    Dockerfile (install-time manifest check), the chosen wheel and the chosen manifest."""
    ctx = Path(tempfile.mkdtemp(prefix="experiment-b-"))
    try:
        archive = subprocess.run(
            ["git", "archive", app_ref, "services/processing-service"], cwd=REPO, check=True, capture_output=True
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(ctx)  # noqa: S202 - our own git archive
        shutil.copy(REPO / "services/processing-service/Dockerfile", ctx / "services/processing-service/Dockerfile")
        (ctx / "scripts").mkdir()
        shutil.copy(REPO / "scripts/verify_manifest.py", ctx / "scripts/verify_manifest.py")
        (ctx / manifest).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / manifest, ctx / manifest)
        shutil.copytree(REPO / wheel_dir, ctx / wheel_dir)
        run(
            [
                "docker", "build", "-q", "-f", str(ctx / "services/processing-service/Dockerfile"),
                "--build-arg", f"MANIFEST={manifest}", "--build-arg", f"WHEEL_DIR={wheel_dir}",
                "-t", tag, str(ctx),
            ]
        )
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


def wait_healthy(url: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{url}/health", timeout=2).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError(f"{url} did not become healthy")


def login(username: str, password: str) -> dict:
    token = requests.post(f"{APP_URL}/auth/login", json={"username": username, "password": password}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {token}"}


def run_workflow() -> dict:
    """The normal workflow: alice uploads a dataset and exports it through the Application API."""
    alice = login("alice", "Alice#Pass1")
    dataset = requests.post(
        f"{APP_URL}/datasets", json={"name": "experiment-b-dataset", "payload": {"ph": 7.1}}, headers=alice
    ).json()
    export = requests.post(f"{APP_URL}/datasets/{dataset['id']}/export", json={"format": "csv"}, headers=alice)
    result = {
        "export_http_status": export.status_code,
        "export_response_body": export.json(),
        "secret_in_export_response": SECRET in export.text,
    }
    if export.status_code == 201:
        stored = requests.get(f"{APP_URL}/exports/{export.json()['export_id']}", headers=alice)
        result["stored_export_http_status"] = stored.status_code
        result["secret_in_stored_export_(resource_service)"] = SECRET in stored.text
    else:
        stored_rows = requests.get(f"{APP_URL}/datasets", headers=alice).json()
        result["note"] = "export refused; nothing was stored for this job"
        result["alice_dataset_count"] = len(stored_rows)
    return result


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    summary: dict[str, dict] = {}

    print("== Step 1: explicit approval of the malicious fixture in the isolated manifest ==")
    malicious_wheel = next((REPO / MALICIOUS_WHEEL_DIR).glob("*.whl"))
    lines = []
    for label, manifest in (("real manifest", REAL_MANIFEST), ("Experiment B manifest", EXPERIMENT_MANIFEST)):
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts/verify_manifest.py"), str(malicious_wheel), "--manifest", str(REPO / manifest)],
            capture_output=True, text=True,
        )
        lines.append(f"[{label}] exit={proc.returncode}\n{proc.stdout.strip()}")
    (OUT / "step1-approval.txt").write_text("\n\n".join(lines) + "\n")
    print("\n\n".join(lines))

    for name, app_ref, wheel_dir, manifest in PHASES:
        print(f"\n== Phase: {name} (processing-service source {app_ref}, wheel {wheel_dir}, manifest {manifest}) ==")
        tag = f"experiment-b-processing:{name}"
        build_processing_image(tag, app_ref, wheel_dir, manifest)
        env = {**os.environ, "PROCESSING_IMAGE": tag}
        try:
            run(COMPOSE + ["up", "-d", "--build"], env=env)
            for url in (RESOURCE_URL, PROCESSING_URL, APP_URL):
                wait_healthy(url)
            result = run_workflow()
            probe = run(COMPOSE + ["exec", "-T", "processing-service", "python", "-c", PROBE], env=env)
            result["what_the_processing_service_container_can_reach"] = json.loads(probe.stdout)
        finally:
            subprocess.run(COMPOSE + ["down", "-v"], env=env, capture_output=True)
        summary[name] = result
        (OUT / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({k: v for k, v in result.items() if k != "what_the_processing_service_container_can_reach"}, indent=2))

    before, after, benign = summary["before-boundary"], summary["after-boundary"], summary["benign-control"]
    checks = {
        "before-boundary: the attempted leak succeeded (evidence preserved)": before["secret_in_export_response"]
        and before.get("secret_in_stored_export_(resource_service)", False),
        "after-boundary: the leak is blocked (HTTP 422, secret not in response)": after["export_http_status"] == 422
        and not after["secret_in_export_response"],
        "benign-control: the legitimate job still completes (HTTP 201, no secret)": benign["export_http_status"] == 201
        and not benign["secret_in_export_response"],
    }
    (OUT / "summary.json").write_text(json.dumps(checks, indent=2) + "\n")
    print("\n== Result ==")
    for text, ok in checks.items():
        print(f"[{'PASS' if ok else 'FAIL'}] {text}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
