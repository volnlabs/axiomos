#!/usr/bin/env python3
"""Recompute publication invariants from observed Rust campaign state."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

PROTOCOLS = ("attach_first", "detach_first", "atomic_publication", "transactional")
PAIRED_PROTOCOLS = ("atomic_publication", "transactional")
SUPPORTING_PROTOCOLS = ("attach_first", "detach_first")
PAIRED_CASES = (
    "snapshot_prep_failure", "budget_rejection", "authority_rejection",
    "stale_expected", "completed_retry", "rollback", "aba",
    "concurrent_proposers", "held_a_schedule",
)
METRICS = (
    "requests", "unsupported_cases", "snapshots", "single_snapshots",
    "dual_snapshots", "empty_snapshots", "guard_checks", "guard_overlap",
    "execution_checks", "execution_overlap", "accounting_checks",
    "accounting_mismatches", "receipt_checks", "receipt_violations",
    "failed_requests", "failed_preserved", "expected_requests",
    "stale_acceptances", "installation_violations", "skipped_dispatches",
)


def _outcome_kind(outcome):
    return outcome.split(" ", 1)[0].split("{", 1)[0]


def _guards(record, state):
    return state.get("guards", []) if record["schema"] == 2 else state.get("executing", [])


def _same_state(left, right, schema):
    keys = ["snapshot", "installation", "committed"]
    if schema == 2:
        keys.append("receipt")
    return all(left.get(key) == right.get(key) for key in keys)


def _receipt_valid(record, before, after):
    receipt = after.get("receipt")
    if receipt is None or after.get("installation") is None:
        return False
    candidate = record["candidate"]
    costs = record["costs"]
    old_charge = sum(costs[str(program)] for program in before["snapshot"])
    new_charge = costs[str(candidate)]
    return (
        receipt.get("previous") == before.get("installation")
        and receipt.get("installed") == after.get("installation")
        and after["installation"][0] == candidate
        and receipt.get("committed") == new_charge
        and receipt.get("admission_delta") == new_charge - old_charge
    )


def analyze(records):
    result = {}
    seen = set()
    for record in records:
        protocol = record.get("protocol")
        schema = record.get("schema")
        if schema not in (1, 2) or protocol not in PROTOCOLS:
            raise ValueError("unknown trace schema/protocol")
        identity = (schema, protocol, record["case"], record["request_id"])
        if identity in seen:
            raise ValueError(f"duplicate request: {identity}")
        seen.add(identity)
        observations = record["observations"]
        encoded = [json.dumps(state, sort_keys=True) for state in observations]
        if len(encoded) != len(set(encoded)):
            raise ValueError(f"duplicate observation: {identity}")
        row = result.setdefault(protocol, dict.fromkeys(METRICS, 0))
        if record["outcome"] == "Unsupported":
            row["unsupported_cases"] += 1
            continue
        row["requests"] += 1
        before, after = record["before"], record["after"]
        costs = record["costs"]
        for state in [*observations, after]:
            cardinality = len(state["snapshot"])
            row["snapshots"] += 1
            row["single_snapshots"] += cardinality == 1
            row["dual_snapshots"] += cardinality > 1
            row["empty_snapshots"] += cardinality == 0
            guards = {json.dumps(identity) for identity in _guards(record, state)}
            if schema == 2:
                row["guard_checks"] += bool(guards)
                row["guard_overlap"] += len(guards) > 1
            else:
                row["execution_checks"] += bool(guards)
                row["execution_overlap"] += len(guards) > 1
            if state["committed"] is not None:
                row["accounting_checks"] += 1
                try:
                    expected_charge = record["ordinary_charge"] + sum(
                        costs[str(program)] for program in state["snapshot"])
                except (KeyError, TypeError) as error:
                    raise ValueError(f"incomplete accounting evidence: {identity}") from error
                row["accounting_mismatches"] += state["committed"] != expected_charge
        succeeded = record["outcome"] == "Ok"
        if not succeeded:
            row["failed_requests"] += 1
            row["failed_preserved"] += _same_state(before, after, schema)
        expected = record["expected"]
        if expected is not None:
            row["expected_requests"] += 1
            row["stale_acceptances"] += succeeded and expected != before["installation"]
        manager_publication = schema == 2 and protocol in PAIRED_PROTOCOLS
        if succeeded and (manager_publication or protocol == "transactional"):
            installed = after["installation"]
            old = before["installation"]
            row["installation_violations"] += not (
                installed is not None and installed[0] == record["candidate"]
                and after["snapshot"] == [record["candidate"]]
                and (old is None or installed[1] > old[1]))
        if manager_publication:
            row["receipt_checks"] += 1
            if succeeded:
                row["receipt_violations"] += not _receipt_valid(record, before, after)
            else:
                row["receipt_violations"] += before.get("receipt") != after.get("receipt")
        row["skipped_dispatches"] += record["skipped_dispatches"]
    if not result:
        raise ValueError("empty campaign")
    return result


def validate_paired(records):
    paired = [record for record in records if record.get("protocol") in PAIRED_PROTOCOLS]
    by_protocol = {protocol: [r for r in paired if r["protocol"] == protocol]
                   for protocol in PAIRED_PROTOCOLS}
    if any(not group for group in by_protocol.values()):
        raise ValueError("paired campaign requires AP and TX records")
    case_sets = {protocol: {record["case"] for record in group}
                 for protocol, group in by_protocol.items()}
    if case_sets[PAIRED_PROTOCOLS[0]] != case_sets[PAIRED_PROTOCOLS[1]]:
        raise ValueError("AP/TX case sets differ")

    rows = analyze(paired)
    for protocol in PAIRED_PROTOCOLS:
        row = rows[protocol]
        if row["failed_preserved"] != row["failed_requests"]:
            raise ValueError(f"{protocol} failed preservation invariant violated")
        if row["accounting_mismatches"]:
            raise ValueError(f"{protocol} accounting invariant violated")
        if row["receipt_violations"]:
            raise ValueError(f"{protocol} receipt invariant violated")
        if row["stale_acceptances"] or row["installation_violations"]:
            raise ValueError(f"{protocol} identity invariant violated")
        if row["dual_snapshots"] or row["empty_snapshots"]:
            raise ValueError(f"{protocol} publication cardinality invariant violated")
        if protocol == "transactional" and row["guard_overlap"]:
            raise ValueError("transactional guard overlap is forbidden")

    for record in paired:
        all_states = [record["before"], *record["observations"], record["after"]]
        for state in all_states:
            if any(not isinstance(identity, list) or len(identity) != 2
                   or not all(isinstance(value, int) for value in identity)
                   for identity in _guards(record, state)):
                raise ValueError("malformed guard identity")
        overlaps = [state for state in [*record["observations"], record["after"]]
                    if len({tuple(identity) for identity in _guards(record, state)}) > 1]
        if record["protocol"] == "atomic_publication" and overlaps and record["case"] != "held_a_schedule":
            raise ValueError("atomic guard overlap outside held_a_schedule")
        for label, state in (("before", record["before"]), ("after", record["after"])):
            installation = state.get("installation")
            if (len(state["snapshot"]) != 1 or installation is None
                    or state["snapshot"] != [installation[0]]
                    or state.get("committed") is None or state.get("receipt") is None
                    or state.get("guards") != [installation]):
                raise ValueError(f"malformed paired {label} state")
        if record["case"] == "held_a_schedule" and record["protocol"] == "atomic_publication":
            if len(record["observations"]) != 1 or len(overlaps) != 1:
                raise ValueError("atomic held_a_schedule requires one guard overlap")
            overlap = overlaps[0]
            if (overlap["snapshot"] != [record["candidate"]]
                    or overlap["installation"][0] != record["candidate"]
                    or overlap["committed"] is not None
                    or overlap.get("receipt") is not None
                    or {tuple(identity) for identity in overlap["guards"]}
                    != {tuple(record["before"]["installation"]),
                        tuple(overlap["installation"])}):
                raise ValueError("atomic held_a_schedule overlap is malformed")
        if record["case"] == "held_a_schedule" and record["protocol"] == "transactional":
            if len(record["observations"]) != 1 or not _same_state(
                    record["before"], record["observations"][0], record["schema"]):
                raise ValueError("transactional Busy attempt did not preserve A")

    indexed = {(record["protocol"], record["case"]): record for record in paired}
    for case in case_sets[PAIRED_PROTOCOLS[0]]:
        atomic = indexed[("atomic_publication", case)]
        guarded = indexed[("transactional", case)]
        if (atomic["costs"] != guarded["costs"]
                or atomic["ordinary_charge"] != guarded["ordinary_charge"]):
            raise ValueError(f"AP/TX accounting fixtures differ for {case}")

    expected = {
        "snapshot_prep_failure": {protocol: ["SnapshotAllocationFailed"] for protocol in PAIRED_PROTOCOLS},
        "budget_rejection": {protocol: ["AdmissionRejected"] for protocol in PAIRED_PROTOCOLS},
        "authority_rejection": {protocol: ["AuthorityExceeded"] for protocol in PAIRED_PROTOCOLS},
        "stale_expected": {protocol: ["StaleInstallation"] for protocol in PAIRED_PROTOCOLS},
        "completed_retry": {protocol: ["StaleInstallation"] for protocol in PAIRED_PROTOCOLS},
        "rollback": {protocol: ["Ok"] for protocol in PAIRED_PROTOCOLS},
        "aba": {protocol: ["StaleInstallation"] for protocol in PAIRED_PROTOCOLS},
        "concurrent_proposers": {protocol: ["Ok", "StaleInstallation"] for protocol in PAIRED_PROTOCOLS},
        "held_a_schedule": {
            "atomic_publication": ["Ok"],
            "transactional": ["Busy", "Ok"],
        },
    }
    for record in paired:
        if record["case"] not in expected:
            continue
        attempts = record.get("attempts", [
            {"candidate": record["candidate"], "outcome": record["outcome"]}])
        actual = sorted(_outcome_kind(attempt["outcome"]) for attempt in attempts)
        wanted = sorted(expected[record["case"]][record["protocol"]])
        if actual != wanted:
            raise ValueError(f"unexpected outcome for {record['protocol']}/{record['case']}: {actual}")
    return rows


def _write_csv(path, protocols, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("protocol", *METRICS))
        writer.writeheader()
        writer.writerows({"protocol": protocol, **rows[protocol]} for protocol in protocols)


def write_artifacts(trace, records, rows, destination):
    validate_paired(records)
    destination.mkdir(parents=True, exist_ok=True)
    paired_rows = {protocol: rows[protocol] for protocol in PAIRED_PROTOCOLS}
    supporting_rows = {protocol: rows[protocol] for protocol in SUPPORTING_PROTOCOLS}
    cases = {protocol: sorted({r["case"] for r in records if r["protocol"] == protocol})
             for protocol in PROTOCOLS}
    outcomes = {
        case: {
            protocol: next(r.get("attempts", [{"candidate": r["candidate"], "outcome": r["outcome"]}])
                           for r in records if r["protocol"] == protocol and r["case"] == case)
            for protocol in PAIRED_PROTOCOLS
        }
        for case in sorted(set(cases[PAIRED_PROTOCOLS[0]]) & set(cases[PAIRED_PROTOCOLS[1]]))
    }
    _write_csv(destination / "summary.csv", PAIRED_PROTOCOLS, paired_rows)
    _write_csv(destination / "supporting-summary.csv", SUPPORTING_PROTOCOLS, supporting_rows)
    analysis = {
        "paired_summary": paired_rows,
        "supporting_summary": supporting_rows,
        "fault_outcomes": outcomes,
        "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
        "cases": cases,
        "paired_cases": sorted(set(cases[PAIRED_PROTOCOLS[0]]) & set(cases[PAIRED_PROTOCOLS[1]])),
        "scope": {protocol: sorted({r.get("scope", "unspecified") for r in records
                                     if r["protocol"] == protocol})
                  for protocol in PROTOCOLS},
        "denominator": "each emitted intermediate observation plus each request's final observation",
    }
    (destination / "analysis.json").write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    compact_faults = (
        ("Snapshot preparation", "reject; preserve", "reject; preserve"),
        ("Authority / budget", "reject (2/2)", "reject (2/2)"),
        ("Stale / retry / ABA", "reject (3/3)", "reject (3/3)"),
        ("Concurrent proposers", "one winner", "one winner"),
        ("Held predecessor", "publish; overlap", "Busy; retry OK"),
    )
    # These labels are emitted only after validate_paired verifies each named
    # outcome and error preservation; counts remain available in the full CSV.
    lines = ["% Generated from the validated paired manager campaign; do not hand-edit.\n",
             r"\begin{tabular}{lrr}" + "\n", r"\toprule" + "\n",
             r"Observation / fault & AP & GR \\" + "\n", r"\midrule" + "\n"]
    lines.append("Multi / empty snapshots & " + " & ".join(
        f"{paired_rows[p]['dual_snapshots']}/{paired_rows[p]['empty_snapshots']}"
        for p in PAIRED_PROTOCOLS) + r" \\" + "\n")
    lines.append("Overlapping guards & " + " & ".join(
        str(paired_rows[p]['guard_overlap']) for p in PAIRED_PROTOCOLS) + r" \\" + "\n")
    lines.append(r"\midrule" + "\n")
    for label, atomic, guarded in compact_faults:
        lines.append(f"{label} & {atomic} & {guarded} " + r"\\" + "\n")
    lines += [r"\bottomrule" + "\n", r"\end{tabular}" + "\n"]
    (destination / "result-table.tex").write_text("".join(lines))
    checksum_paths = [path for path in sorted(destination.rglob("*"))
                      if path.is_file() and path.name != "SHA256SUMS"]
    (destination / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(destination)}\n"
        for path in checksum_paths))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--write-artifacts", action="store_true",
                        help="write derived files beside the trace")
    parser.add_argument("--output-dir", type=Path,
                        help="write derived files here (implies --write-artifacts)")
    args = parser.parse_args()
    records = [json.loads(line) for line in args.trace.read_text().splitlines() if line.strip()]
    rows = analyze(records)
    if set(rows) != set(PROTOCOLS):
        raise ValueError("final campaign must contain all four protocols")
    is_v2 = any(record["schema"] == 2 for record in records)
    if is_v2:
        cases = {protocol: {r["case"] for r in records if r["protocol"] == protocol}
                 for protocol in PAIRED_PROTOCOLS}
        if any(cases[protocol] != set(PAIRED_CASES) for protocol in PAIRED_PROTOCOLS):
            raise ValueError("v2 paired campaign has an incomplete case set")
        validate_paired(records)
        if args.write_artifacts or args.output_dir:
            write_artifacts(args.trace, records, rows, args.output_dir or args.trace.parent)
        print(f"PASS: {sum(rows[p]['requests'] for p in PAIRED_PROTOCOLS)} paired AP/TX requests; invariants hold")
        return

    transactional = rows["transactional"]
    failures = [key for key in ("dual_snapshots", "empty_snapshots", "execution_overlap",
                                "accounting_mismatches", "stale_acceptances", "installation_violations")
                if transactional[key]]
    if transactional["failed_preserved"] != transactional["failed_requests"]:
        failures.append("failed_preservation")
    if failures:
        raise ValueError(f"transactional invariants violated: {failures}")
    if args.write_artifacts or args.output_dir:
        raise ValueError("legacy v1 evidence is immutable; choose a separate v2 trace")
    print(f"PASS: legacy v1 trace read-only; {sum(row['requests'] for row in rows.values())} requests")


if __name__ == "__main__":
    main()
