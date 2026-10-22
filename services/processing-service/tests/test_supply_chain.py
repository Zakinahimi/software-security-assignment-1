"""Controlled supply-chain experiment, runtime-containment half (Experiment B).

Swaps in the malicious exportkit fixture (packages/exportkit-malicious) at the Python-import
level for a single test — simulating "an isolated experimental run where the malicious fixture's
identity/digest has been explicitly approved as a new authentic version" (Experiment B's own
framing: this models what happens if a compromised supplier update gets approved and installed).
Nothing in app.py is edited to accommodate this: the malicious code enters purely through what
`import exportkit` resolves to, exactly as the brief requires.
"""

import importlib
import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest
from conftest import auth_header, make_job_token


@pytest.fixture()
def malicious_exportkit_installed(monkeypatch):
    """Temporarily makes `import exportkit` resolve to the malicious fixture instead of the real
    package, for the duration of one test, then restores the real one."""
    malicious_path = __file__.rsplit("/services/", 1)[0] + "/packages/exportkit-malicious"
    sys.path.insert(0, malicious_path)
    for name in list(sys.modules):
        if name == "exportkit" or name.startswith("exportkit."):
            del sys.modules[name]
    import app as proc_app

    importlib.reload(proc_app)
    yield proc_app
    sys.path.remove(malicious_path)
    for name in list(sys.modules):
        if name == "exportkit" or name.startswith("exportkit."):
            del sys.modules[name]
    importlib.reload(proc_app)


def test_malicious_exportkit_attempts_to_leak_the_shared_secret(monkeypatch, malicious_exportkit_installed):
    """Confirms the malicious fixture really does try the attack described in its own README —
    this is the "preserve the evidence" step the brief asks for before showing it is contained."""
    monkeypatch.setenv("RESEARCH_WORKSPACE_JWT_SECRET", "super-secret-value-should-never-leak")
    import exportkit as malicious

    output = malicious.to_csv([{"id": 1, "owner": "alice", "name": "x", "payload": "{}"}])
    assert "super-secret-value-should-never-leak" in output, (
        "sanity check: the malicious fixture must actually attempt the leak for this experiment "
        "to mean anything"
    )


def test_malicious_exportkit_leak_is_blocked_by_output_validation(
    client, resource_service, monkeypatch, malicious_exportkit_installed
):
    """The actual containment test: even with the malicious dependency installed and actively
    trying to exfiltrate RESEARCH_WORKSPACE_JWT_SECRET through the export content, the Processing
    Service's output-validation check (app.py::validate_export_output) rejects the job before the
    poisoned content is ever saved or returned — an actual runtime defence, not a check of the
    package's filename or version (which, per the brief, "is not a sufficient runtime defence" —
    and indeed this malicious build's filename/version are identical to the real one)."""
    monkeypatch.setenv("RESEARCH_WORKSPACE_JWT_SECRET", "super-secret-value-should-never-leak")
    token = make_job_token("alice", resource=10)

    resp = malicious_exportkit_installed.app.test_client().post(
        "/jobs/export",
        json={"dataset_id": 10, "format": "csv"},
        headers=auth_header(token),
    )

    assert resp.status_code == 422
    assert "super-secret-value-should-never-leak" not in resp.get_data(as_text=True)
    assert resource_service == [], "the poisoned export must never reach the Resource Service"


def test_legitimate_job_still_completes_with_the_benign_dependency(client, resource_service):
    """Required by the brief: confirm the legitimate job still completes normally once the
    malicious fixture is gone and the real, benign exportkit is back in place (this test runs
    with the module-level `client`/`app` fixtures, which use the real exportkit — see
    conftest.py / pyproject install)."""
    token = make_job_token("alice", resource=10)

    resp = client.post("/jobs/export", json={"dataset_id": 10, "format": "csv"}, headers=auth_header(token))

    assert resp.status_code == 201
    assert len(resource_service) == 1


# --- Experiment A: install-time integrity gate (scripts/verify_manifest.py + the manifest) ---

REPO_ROOT = Path(__file__).resolve().parents[3]


def _verify_manifest_module():
    spec = importlib.util.spec_from_file_location("verify_manifest", REPO_ROOT / "scripts" / "verify_manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _benign_wheel() -> Path:
    return next((REPO_ROOT / "packages" / "exportkit" / "dist").glob("*.whl"))


def test_integrity_gate_approves_the_approved_wheel():
    ok, message = _verify_manifest_module().verify(_benign_wheel())
    assert ok, message


def test_integrity_gate_rejects_same_name_and_version_with_different_bytes(tmp_path):
    """Replace the supplier artifact with different bytes while keeping the expected identity
    (name + version in the wheel's METADATA) unchanged: the digest check must block it."""
    benign = _benign_wheel()
    tampered = tmp_path / benign.name
    with zipfile.ZipFile(benign) as src, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "exportkit/__init__.py":
                data += b"\n# injected by a compromised supplier\n"
            dst.writestr(item, data)

    ok, message = _verify_manifest_module().verify(tampered)

    assert not ok
    assert "digest mismatch" in message


def test_integrity_gate_rejects_the_malicious_fixture_wheel():
    malicious = next((REPO_ROOT / "packages" / "exportkit-malicious" / "dist").glob("*.whl"))
    ok, message = _verify_manifest_module().verify(malicious)
    assert not ok
    assert "digest mismatch" in message
