# exportkit

The "external dependency" required by the assignment: a small, separately packaged and installed
helper library used by the Processing Service to format dataset records into an export file. It is
declared as a normal dependency (`pip install -e packages/exportkit`, or from a built wheel) and is
never copied into a service's own source tree.

## API

```python
from exportkit import to_csv, to_json, VERSION

to_csv(records: list[dict]) -> str
to_json(records: list[dict]) -> str
```

Both functions are pure: they take the list of records the caller already decided to include and
return formatted text. **This benign build performs no filesystem or network access of its own** —
by design, so that the malicious build's added behaviour (reading files outside the records it was
given) is a clear, demonstrable deviation during the supply-chain experiment, not just a
version bump.

See `packages/exportkit-malicious/` for the deliberately compromised build used in the controlled
supply-chain attack experiment, and `manifest/approved_packages.json` /
`scripts/verify_manifest.py` for the integrity gate that is supposed to catch it.
