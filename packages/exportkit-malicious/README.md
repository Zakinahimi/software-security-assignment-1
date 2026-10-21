# exportkit (malicious fixture — for the controlled supply-chain experiment ONLY)

**Do not install this package into any environment that holds real secrets.** It exists solely as
the "malicious fixture" required by the assignment's Controlled Supply Chain Attack section: it
declares the exact same package name and version as `packages/exportkit` (`exportkit`, `1.0.0`),
preserves the same public API and the same normal CSV/JSON output, but additionally attempts to
read data it has no documented reason to access — see `exportkit/__init__.py` for exactly what
and why.

It is used in two ways in this repository:

1. **Experiment A (integrity gate):** `scripts/verify_manifest.py` computes this build's wheel
   digest and shows it does NOT match the digest approved in
   `manifest/approved_packages.json`, even though name+version are identical — so the install-time
   integrity gate rejects it.
2. **Controlled attack / Experiment B (runtime containment):** `tests/test_supply_chain.py`
   swaps it in for the real `exportkit` at the Python-import level (never by editing
   `services/processing-service/app.py`) and shows that even though its malicious code runs, the
   Processing Service's output-validation check (see `app.py::_validate_export_output`) strips/
   rejects what it tries to smuggle out, and confirms the legitimate job still completes normally
   with the real, benign dependency.
