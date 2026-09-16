#!/usr/bin/env python3
"""Stitch bounded v0.5 audit exports without turning them into a physical PASS."""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

HEADER = {"type", "format", "version", "clock_frequency", "session",
          "session_established", "persistent_boot_identity", "oldest", "end",
          "overwritten", "dropped", "suppressed", "flags", "capacity",
          "record_bytes", "latest_stop", "payloads_decoded", "slot_generation",
          "slot_last_id", "artifacts"}
RECORD = {"type", "sequence", "ticks", "correlation", "kind", "payload_hex"}
END = {"type", "cursor", "records", "gaps"}


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def integer(value, label, *, positive=False):
    if type(value) is not int or value < int(positive):
        raise ValueError(f"invalid {label}")
    return value


def rows(path):
    data = path.read_bytes()
    if not data or not data.endswith(b"\n"):
        raise ValueError(f"truncated audit export {path}")
    result = []
    for number, line in enumerate(data.splitlines(), 1):
        if not line or len(line) > 16 * 1024:
            raise ValueError(f"invalid audit line {path}:{number}")
        try:
            value = json.loads(line, object_pairs_hook=pairs,
                               parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v)))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(f"malformed audit line {path}:{number}: {error}") from None
        if not isinstance(value, dict):
            raise ValueError(f"audit line is not an object {path}:{number}")
        result.append(value)
    return result


def export(path):
    values = rows(path)
    if len(values) < 2 or set(values[0]) != HEADER or set(values[-1]) != END:
        raise ValueError(f"invalid audit envelope {path}")
    header, end = values[0], values[-1]
    if (header["type"], header["format"], header["version"],
            header["persistent_boot_identity"], header["payloads_decoded"]) != (
                "header", "axiomos-managed-audit", 1, False, False):
        raise ValueError(f"invalid audit header {path}")
    for key in ("clock_frequency", "oldest", "end", "overwritten", "dropped",
                "suppressed", "flags", "capacity", "record_bytes",
                "slot_generation", "slot_last_id", "session"):
        integer(header[key], key, positive=key == "clock_frequency")
    if (header["capacity"], header["record_bytes"], header["overwritten"],
            header["dropped"], header["flags"] & 12) != (
                2048, 96, header["oldest"], 0, 0):
        raise ValueError(f"audit loss, exhaustion, or layout mismatch {path}")
    if type(header["session_established"]) is not bool or not isinstance(header["artifacts"], list):
        raise ValueError(f"invalid audit context {path}")
    records = []
    cursor = header["oldest"]
    previous_ticks = None
    for value in values[1:-1]:
        if value.get("type") == "gap":
            raise ValueError(f"audit export contains a gap {path}")
        if set(value) != RECORD:
            raise ValueError(f"invalid audit record {path}")
        for key in ("sequence", "ticks", "correlation", "kind"):
            integer(value[key], key)
        payload = value["payload_hex"]
        if (value["type"] != "record" or value["sequence"] != cursor
                or value["kind"] not in range(1, 6) or not isinstance(payload, str)
                or len(payload) != 128 or any(c not in "0123456789abcdef" for c in payload)):
            raise ValueError(f"invalid or reordered audit record {path}")
        value = dict(value)
        value["payload"] = bytes.fromhex(payload)
        if previous_ticks is not None and value["ticks"] < previous_ticks:
            raise ValueError(f"audit ticks decreased {path}")
        previous_ticks = value["ticks"]
        records.append(value)
        cursor += 1
    if (set(end) != END or end["type"] != "end"
            or any(type(end[key]) is not int or end[key] < 0 for key in END - {"type"})
            or (end["cursor"], end["records"], end["gaps"]) != (
                header["end"], len(records), 0) or cursor != header["end"]):
        raise ValueError(f"incomplete audit footer {path}")
    return header, records


def lifecycle(payload):
    return struct.unpack("<IIQQQQIIIIII", payload)


def cycle(payload):
    return struct.unpack("<QQQQIIhhhhIIII", payload)


def handoff(payload):
    return struct.unpack("<IIIIQQQIII12s", payload)


def session(payload):
    return struct.unpack("<IIII32s16s", payload)


def stitch(paths, acceptance):
    period_ns = integer(acceptance.get("cpu", {}).get("period_ns"), "period_ns", positive=True)
    quiet_ns = integer(acceptance.get("timing", {}).get("reset_quiescence_ns"),
                       "reset_quiescence_ns", positive=True)
    retained = {}
    frequency = None
    previous_end = previous_suppressed = 0
    for index, path in enumerate(paths):
        header, records = export(path)
        if frequency is None:
            frequency = header["clock_frequency"]
        if header["clock_frequency"] != frequency or header["end"] < previous_end:
            raise ValueError("audit clock changed or export ends reordered")
        if index == 0 and header["oldest"] != 0:
            raise ValueError("first audit export does not begin at sequence zero")
        if header["suppressed"] < previous_suppressed:
            raise ValueError("audit suppression counter decreased")
        previous_end, previous_suppressed = header["end"], header["suppressed"]
        for record in records:
            old = retained.setdefault(record["sequence"], record)
            if old != record:
                raise ValueError("overlapping audit exports disagree")
    if not retained or set(retained) != set(range(previous_end)):
        raise ValueError("audit exports do not retain one contiguous interval")

    cycles = []
    transitions = {"activate": 0, "rollback": 0}
    rearm = {}
    rearm_committed = set()
    rearm_failed = set()
    uploads = {"resident": 0, "rejected_by_errno": {}}
    completion_misses = 0
    stops = {}
    for record in (retained[index] for index in range(previous_end)):
        payload = record["payload"]
        if record["kind"] == 3:
            fields = cycle(payload)
            item = dict(cycle_id=fields[0], scheduled=fields[1], actual=fields[2],
                        missed=fields[3], flags=fields[5], failure=fields[12],
                        record_ticks=record["ticks"])
            if (item["cycle_id"] == 0 or item["scheduled"] > item["actual"]
                    or item["actual"] > item["record_ticks"] or item["flags"] & ~31):
                raise ValueError("invalid cycle audit payload")
            cycles.append(item)
        elif record["kind"] == 2:
            fields = lifecycle(payload)
            if fields[0] == 1:
                upload = struct.unpack("<IIIIIIIIQQ16s", payload)
                if upload[1] == 4 and upload[2] == 0:
                    uploads["resident"] += 1
                elif upload[1] in (5, 6) and upload[2] != 0:
                    key = str(upload[2])
                    uploads["rejected_by_errno"][key] = uploads["rejected_by_errno"].get(key, 0) + 1
            elif fields[0] == 2:
                if fields[1] == 5 and fields[9] == 0 and fields[7] in (1, 2):
                    transitions[("activate", "rollback")[fields[7] - 1]] += 1
                if fields[7] == 5 and fields[1] == 5 and fields[9] == 0:
                    rearm_committed.add(record["correlation"])
                if fields[7] == 5 and fields[1] == 6 and fields[9] != 0:
                    rearm_failed.add(record["correlation"])
        elif record["kind"] == 4:
            fields = struct.unpack("<QQQIIIIII16s", payload)
            completion_misses += int(fields[5] == 4)
            key = f"{fields[5]}:{fields[7]}:{fields[8]}"
            stops[key] = stops.get(key, 0) + 1
        elif record["kind"] == 5:
            subtype = struct.unpack_from("<I", payload)[0]
            if subtype == 5:
                link, event, wire_session, flags, reserved, tail = session(payload)
                if (event not in (1, 2) or wire_session == 0 or flags != 1
                        or reserved != bytes(32) or tail != bytes(16) or record["correlation"] == 0):
                    raise ValueError("invalid session audit payload")
                state = rearm.setdefault(record["correlation"], {"session": wire_session})
                if state["session"] != wire_session or event in state:
                    raise ValueError("duplicate or mismatched session audit payload")
                state[event] = (record["sequence"], record["ticks"])
            elif subtype == 4:
                fields = handoff(payload)
                _, event, wire_session, _, _, observed, _, message, error, flags, reserved = fields
                if record["correlation"] and message in (1, 2, 5, 6):
                    state = rearm.setdefault(record["correlation"], {"session": wire_session})
                    if (state["session"] != wire_session or error or flags & ~3 or reserved != bytes(12)):
                        raise ValueError("invalid rearm handoff payload")
                    key = {(2, 5): "requalify", (4, 6): "prepared",
                           (2, 1): "offer", (4, 2): "ready"}.get((event, message))
                    if key:
                        if key in state:
                            raise ValueError("duplicate rearm handoff stage")
                        state[key] = (record["sequence"], observed)

    cycles.sort(key=lambda item: item["cycle_id"])
    if not cycles:
        raise ValueError("audit contains no recorded control release")
    missed = sum(item["missed"] for item in cycles)
    suppressed_through_last = cycles[-1]["cycle_id"] - len(cycles) - missed
    if not 0 <= suppressed_through_last <= previous_suppressed:
        raise ValueError("cycle IDs do not account for recorded, suppressed, and missed releases")
    for earlier, later in zip(cycles, cycles[1:]):
        distance = later["cycle_id"] - earlier["cycle_id"]
        if distance <= 0 or ((later["scheduled"] - earlier["scheduled"]) * 1_000_000_000
                             != distance * period_ns * frequency):
            raise ValueError("cycle schedule is missing, duplicated, or off the absolute grid")
    if any((item["record_ticks"] - item["scheduled"]) * 1_000_000_000
           >= period_ns * frequency for item in cycles):
        raise ValueError("cycle recording observation reached its deadline")

    quiet = []
    for operation, state in rearm.items():
        required = (1, "requalify", "prepared", "offer", "ready", 2)
        if any(key not in state for key in required):
            if operation not in rearm_failed or operation in rearm_committed or 2 in state:
                raise ValueError(f"rearm {operation} audit lifecycle is incomplete without failure")
            continue
        if operation not in rearm_committed or operation in rearm_failed:
            raise ValueError(f"rearm {operation} completion lacks one committed outcome")
        stages = [state[key] for key in required]
        if any(a[0] >= b[0] for a, b in zip(stages, stages[1:])):
            raise ValueError(f"rearm {operation} audit lifecycle is reordered")
        initial, final = stages[1][1] - stages[0][1], stages[3][1] - stages[2][1]
        if initial * 1_000_000_000 < quiet_ns * frequency or final * 1_000_000_000 < quiet_ns * frequency:
            raise ValueError(f"rearm {operation} quiescence interval is too short")
        quiet.append({"operation": operation, "session": state["session"],
                      "initial_ticks": initial, "final_ticks": final})
    return {"schema": "axiomos.v05.audit-stitch.v1", "qualification_evaluated": False,
            "clock_frequency": frequency, "records": len(retained),
            "first_sequence": 0, "last_sequence": previous_end - 1,
            "releases": len(cycles) + previous_suppressed + missed,
            "last_recorded_cycle_id": cycles[-1]["cycle_id"], "recorded_cycles": len(cycles),
            "suppressed_cycles": previous_suppressed, "missed_releases": missed,
            "completion_misses": completion_misses,
            "safe_cycles_recorded": sum(bool(item["flags"] & 2) for item in cycles),
            "handoff_cycles_recorded": sum(bool(item["flags"] & 4) for item in cycles),
            "cycle_failures": sum(item["failure"] != 0 for item in cycles),
            "successful_transitions": transitions, "uploads": uploads, "stops": stops,
            "failed_rearms": len(rearm_failed), "rearm_quiescence": quiet}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path,
                        default=Path(__file__).resolve().parents[2] / "docs/performance/v0.5-acceptance.json")
    parser.add_argument("exports", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        acceptance = json.loads(args.acceptance.read_text(), object_pairs_hook=pairs)
        print(json.dumps(stitch(args.exports, acceptance), sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, struct.error) as error:
        print(f"v0.5 audit stitch failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
