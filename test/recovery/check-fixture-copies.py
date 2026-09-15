#!/usr/bin/env python3
"""Compare companion golden fixtures with the canonical repository bytes."""
import hashlib
from pathlib import Path
import sys

canonical = Path(__file__).parent / "fixtures" / "recovery-wire-v1.json"
expected = canonical.read_bytes()
if len(sys.argv) < 2:
    raise SystemExit("usage: check-fixture-copies.py COMPANION_FIXTURE [COMPANION_FIXTURE ...]")
for argument in sys.argv[1:]:
    candidate = Path(argument)
    if candidate.read_bytes() != expected:
        raise SystemExit(f"fixture differs: {candidate}")
print(f"{len(sys.argv) - 1} fixture copies match SHA256 {hashlib.sha256(expected).hexdigest()}")
