#!/usr/bin/env python3
"""Check the opt-in poll trace and retained safety records in a built Pi ELF.

Run on both release images: default, then with --enabled for trace-control-link.
This checks instrumentation selection, not UART throughput or physical safety.
"""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("image", type=Path)
parser.add_argument("--enabled", action="store_true")
args = parser.parse_args()
image = args.image.read_bytes()
assert (b"V04_CHUNK chunk_id=" in image) == args.enabled, "wrong poll trace selection"
for marker in (b"V04_FAILURE reason=", b"V04_LINK_LOSS event_id=", b"V04_ESTOP event_id="):
    assert marker in image, f"safety event removed: {marker!r}"
print(f"PASS: poll trace enabled={args.enabled}; safety records retained")
