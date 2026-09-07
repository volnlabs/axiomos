#!/usr/bin/env python3
"""Recompute publication invariants from observed Rust campaign state."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

PROTOCOLS = ("attach_first", "detach_first", "atomic_publication", "transactional")
METRICS = ("requests", "unsupported_cases", "snapshots", "single_snapshots", "dual_snapshots", "empty_snapshots",
           "execution_checks", "execution_overlap", "accounting_checks", "accounting_mismatches", "failed_requests", "failed_preserved",
           "expected_requests", "stale_acceptances", "installation_violations", "skipped_dispatches")


def analyze(records):
    result = {}
    seen = set()
    for record in records:
        protocol = record.get("protocol")
        if record.get("schema") != 1 or protocol not in PROTOCOLS:
            raise ValueError("unknown trace schema/protocol")
        identity = (protocol, record["case"], record["request_id"])
        if identity in seen:
            raise ValueError(f"duplicate request: {identity}")
        seen.add(identity)
        row = result.setdefault(protocol, dict.fromkeys(METRICS, 0))
        if record["outcome"] == "Unsupported":
            row["unsupported_cases"] += 1
            continue
        row["requests"] += 1
        before, after = record["before"], record["after"]
        costs = record["costs"]
        for state in [*record["observations"], after]:
            cardinality = len(state["snapshot"])
            row["snapshots"] += 1
            row["single_snapshots"] += cardinality == 1
            row["dual_snapshots"] += cardinality > 1
            row["empty_snapshots"] += cardinality == 0
            versions = {json.dumps(v, sort_keys=True) for v in (state["executing"] or [])}
            row["execution_checks"] += bool(versions)
            row["execution_overlap"] += len(versions) > 1
            if state["committed"] is not None:
                row["accounting_checks"] += 1
                expected_charge = record["ordinary_charge"] + sum(costs[str(p)] for p in state["snapshot"])
                row["accounting_mismatches"] += state["committed"] != expected_charge
        succeeded = record["outcome"] == "Ok"
        if not succeeded:
            row["failed_requests"] += 1
            row["failed_preserved"] += all(before[key] == after[key]
                                            for key in ("snapshot", "installation", "committed"))
        expected = record["expected"]
        if expected is not None:
            row["expected_requests"] += 1
            row["stale_acceptances"] += succeeded and expected != before["installation"]
        if succeeded and protocol == "transactional":
            installed = after["installation"]
            old = before["installation"]
            row["installation_violations"] += not (
                installed is not None and installed[0] == record["candidate"]
                and after["snapshot"] == [record["candidate"]]
                and (old is None or installed[1] > old[1]))
        row["skipped_dispatches"] += record["skipped_dispatches"]
    if not result:
        raise ValueError("empty campaign")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    records = [json.loads(line) for line in args.trace.read_text().splitlines() if line.strip()]
    rows = analyze(records)
    if set(rows) != set(PROTOCOLS):
        raise ValueError("final campaign must contain all four protocols")
    cases = {p: {r["case"] for r in records if r["protocol"] == p and r["outcome"] != "Unsupported"}
             for p in PROTOCOLS}
    shared_manager_cases = cases["attach_first"] & cases["detach_first"] & cases["transactional"]
    if not shared_manager_cases:
        raise ValueError("no shared manager scenarios")
    destination = args.trace.parent
    with (destination / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("protocol", *METRICS))
        writer.writeheader()
        writer.writerows({"protocol": p, **rows[p]} for p in PROTOCOLS)
    manager_protocols = ("attach_first", "detach_first", "transactional")
    table_rows = analyze([r for r in records if r["protocol"] in manager_protocols
                          and r["case"] in shared_manager_cases])
    analysis = {"table_summary": table_rows, "trace_sha256": hashlib.sha256(args.trace.read_bytes()).hexdigest(),
                "cases": {p: sorted(c) for p, c in cases.items()}, "summary": rows,
                "shared_manager_cases": sorted(shared_manager_cases),
                "scope": {p: sorted({r.get("scope", "unspecified") for r in records if r["protocol"] == p})
                          for p in PROTOCOLS},
                "denominator": "emitted intermediate observations plus each request's final observation"}
    (destination / "analysis.json").write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    labels = (("Observed snapshots", "snapshots"), ("Multiple versions", "dual_snapshots"),
              ("Empty snapshots", "empty_snapshots"),
              ("Accounting mismatches", "accounting_mismatches"))
    lines = ["% Generated from shared manager scenarios; do not hand-edit.\n",
             r"\begin{tabular}{lrrr}" + "\n", r"\toprule" + "\n",
             r"Observation & AF & DF & TX \\" + "\n", r"\midrule" + "\n"]
    for label, key in labels:
        lines.append(label + " & " + " & ".join(str(table_rows[p][key]) for p in manager_protocols) + r" \\" + "\n")
    lines.append("Failed requests preserved & " + " & ".join(
        f"{table_rows[p]['failed_preserved']}/{table_rows[p]['failed_requests']}" if table_rows[p]['failed_requests'] else "--"
        for p in manager_protocols) + r" \\" + "\n")
    lines += [r"\bottomrule" + "\n", r"\end{tabular}" + "\n"]
    (destination / "result-table.tex").write_text("".join(lines))
    transactional = rows["transactional"]
    failures = [key for key in ("dual_snapshots", "empty_snapshots", "execution_overlap",
                               "accounting_mismatches", "stale_acceptances", "installation_violations")
                if transactional[key]]
    if transactional["failed_preserved"] != transactional["failed_requests"]:
        failures.append("failed_preservation")
    if failures:
        raise ValueError(f"transactional invariants violated: {failures}")
    checksum_paths = [p for p in sorted(destination.rglob("*")) if p.is_file() and p.name != "SHA256SUMS"]
    (destination / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(destination)}\n" for p in checksum_paths))
    print(f"PASS: {sum(row['requests'] for row in rows.values())} measured requests, "
          f"{len(shared_manager_cases)} shared manager scenarios; transactional invariants hold")


if __name__ == "__main__":
    main()
