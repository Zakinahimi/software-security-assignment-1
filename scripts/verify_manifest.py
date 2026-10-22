#!/usr/bin/env python3
"""Experiment A — install-time integrity gate for the external `exportkit` dependency.

Usage:
    python scripts/verify_manifest.py <path-to-wheel> [--manifest <path-to-manifest.json>]

Exits 0 and prints "APPROVED" if the wheel's package name, version and sha256 content digest all
match an entry in manifest/approved_packages.json (controlled by the CONSUMER — this project —
not by whoever supplies the package). Exits 1 and prints "REJECTED" with the reason otherwise.

This is deliberately a real content-hash check, not a filename/version check: the brief is
explicit that "checking only the package's filename or version is not a sufficient runtime
defence." A malicious wheel can claim any name/version it likes; it cannot produce the approved
sha256 without being byte-for-byte the approved artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "manifest" / "approved_packages.json"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_wheel_identity(path: Path) -> tuple[str, str]:
    """Returns (name, version) read from the wheel's own METADATA, the same thing a package
    installer would trust — which is exactly why identity/version alone cannot be the gate."""
    with zipfile.ZipFile(path) as zf:
        metadata_names = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
        if not metadata_names:
            raise ValueError("wheel has no .dist-info/METADATA — cannot determine identity")
        metadata = zf.read(metadata_names[0]).decode("utf-8", errors="replace")
    name = version = None
    for line in metadata.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
    if not name or not version:
        raise ValueError("could not read Name/Version from wheel METADATA")
    return name, version


def verify(wheel_path: Path, manifest_path: Path = MANIFEST_PATH) -> tuple[bool, str]:
    if not wheel_path.exists():
        return False, f"REJECTED: no such file: {wheel_path}"

    manifest = json.loads(Path(manifest_path).read_text())["packages"]

    name, version = read_wheel_identity(wheel_path)
    entry = manifest.get(name)
    if entry is None:
        return False, f"REJECTED: package '{name}' is not in the approval manifest at all"
    if entry["version"] != version:
        return False, f"REJECTED: approved version is {entry['version']}, wheel declares {version}"

    actual_digest = sha256_of(wheel_path)
    if actual_digest != entry["sha256"]:
        return False, (
            f"REJECTED: digest mismatch for {name}=={version}\n"
            f"  approved sha256: {entry['sha256']}\n"
            f"  actual   sha256: {actual_digest}\n"
            "  (name and version matched — this looks like a tampered/compromised artifact, not a typo)"
        )

    return True, f"APPROVED: {name}=={version} matches the manifest (sha256={actual_digest})"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a wheel against the consumer-held approval manifest.")
    parser.add_argument("wheel", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=MANIFEST_PATH,
        help="approval manifest to check against (default: manifest/approved_packages.json)",
    )
    args = parser.parse_args()
    ok, message = verify(args.wheel, args.manifest)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
