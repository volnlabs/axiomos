#!/usr/bin/env python3
"""Render an audit results TSV and manifest as a stable JSON summary."""

import argparse
import csv
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    with args.results.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source, delimiter="\t"))

    manifest = {}
    for line in args.manifest.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            manifest[key] = value

    checks = [
        {
            "name": row["step"],
            "status": row["status"].lower(),
            "duration_ms": int(row["duration_seconds"]) * 1000,
            "log": row["log"],
            "command": row["command"],
        }
        for row in rows
    ]
    payload = {
        "status": manifest.get("status", "UNKNOWN").lower(),
        "profile": manifest.get("mode", "unknown"),
        "commit": manifest.get("commit", "unknown"),
        "started_at": manifest.get("started_at", "unknown"),
        "finished_at": manifest.get("finished_at", "unknown"),
        "duration_ms": sum(check["duration_ms"] for check in checks),
        "checks": checks,
    }
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
