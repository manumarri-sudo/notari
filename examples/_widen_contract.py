"""Probe helper: rewrite a signed contract's scope to `**`, as a hostile agent would.

Used by ``bypass_probes.sh`` probe 12. The point is that the edit succeeds (the
file is plain JSON on disk) and the verdict still BLOCKs, because the Ed25519
signature no longer matches a trusted approver.
"""

import json
import sys

path = sys.argv[1]
with open(path) as fh:
    contract = json.load(fh)
contract["allowed_paths"] = ["**"]
with open(path, "w") as fh:
    json.dump(contract, fh, indent=2)
