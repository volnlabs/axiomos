import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("v05_audit_stitch", ROOT / "scripts/benchmark/v05-audit-stitch.py")
stitcher = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(stitcher)


def packed(sequence, ticks, correlation, kind, payload):
    return {"type": "record", "sequence": sequence, "ticks": ticks,
            "correlation": correlation, "kind": kind, "payload_hex": payload.hex()}


def fixture():
    hz = 1_000_000_000
    records = []
    session = lambda event: struct.pack("<IIII32s16s", 5, event, 9, 1, bytes(32), bytes(16))
    handoff = lambda event, message, observed: struct.pack(
        "<IIIIQQQIII12s", 4, event, 9, 0, 0, observed, 0, message, 0, 1, bytes(12))
    lifecycle = lambda action: struct.pack(
        "<IIQQQQIIIIII", 2, 5, action, action - 1, action, action, 7 + action,
        action, 5, 0, 1, 0)
    cycle = lambda ident, flags=17: struct.pack(
        "<QQQQIIhhhhIIII", ident, 400_000_000 + ident * 10_000_000,
        400_000_000 + ident * 10_000_000,
        0, 8, flags, 0, 0, 0, 0, 1, 1, 0, 0)
    values = [
        (0, 0, 40, 5, session(1)),
        (1, 200_000_000, 40, 5, handoff(2, 5, 200_000_000)),
        (2, 201_000_000, 40, 5, handoff(4, 6, 201_000_000)),
        (3, 401_000_000, 40, 5, handoff(2, 1, 401_000_000)),
        (4, 402_000_000, 40, 5, handoff(4, 2, 402_000_000)),
        (5, 403_000_000, 40, 5, session(2)),
        (6, 403_000_001, 40, 2, lifecycle(5)),
        (7, 404_000_000, 41, 2, lifecycle(1)),
        (8, 405_000_000, 42, 2, lifecycle(2)),
        (9, 410_000_001, 1, 3, cycle(1, 23)),
        (10, 420_000_001, 2, 3, cycle(2)),
    ]
    for value in values:
        records.append(packed(*value))
    return hz, records


def write_export(path, records, start, end, suppressed=0):
    hz, _ = fixture()
    header = {"type": "header", "format": "axiomos-managed-audit", "version": 1,
              "clock_frequency": hz, "session": 9, "session_established": True,
              "persistent_boot_identity": False, "oldest": start, "end": end,
              "overwritten": start, "dropped": 0, "suppressed": suppressed, "flags": 3,
              "capacity": 2048, "record_bytes": 96, "latest_stop": None,
              "payloads_decoded": False, "slot_generation": 2, "slot_last_id": 42,
              "artifacts": []}
    footer = {"type": "end", "cursor": end, "records": end - start, "gaps": 0}
    path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n"
                            for row in [header, *records[start:end], footer]))


class AuditStitchTests(unittest.TestCase):
    def setUp(self):
        self.acceptance = json.loads((ROOT / "docs/performance/v0.5-acceptance.json").read_text())

    def test_overlapping_exports_prove_cycles_transitions_and_quiescence(self):
        _, records = fixture()
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a.jsonl", Path(directory) / "b.jsonl"
            write_export(a, records, 0, 8)
            write_export(b, records, 4, 11)
            report = stitcher.stitch([a, b], self.acceptance)
        self.assertEqual(report["releases"], 2)
        self.assertEqual(report["successful_transitions"], {"activate": 1, "rollback": 1})
        self.assertEqual(report["rearm_quiescence"][0]["initial_ticks"], 200_000_000)
        self.assertFalse(report["qualification_evaluated"])

    def test_rejects_loss_disagreement_short_quiet_and_late_cycles(self):
        _, records = fixture()
        mutations = [
            lambda a, b: b.__setitem__(5, {**b[5], "ticks": b[5]["ticks"] + 1}),
            lambda a, b: b.__setitem__(slice(0, 1), []),
            lambda a, b: a[1].update(ticks=199_999_999,
                                     payload_hex=struct.pack("<IIIIQQQIII12s", 4, 2, 9, 0, 0,
                                                             199_999_999, 0, 5, 0, 1, bytes(12)).hex()),
            lambda a, b: b[-1].update(ticks=430_000_000,
                                      payload_hex=bytes.fromhex(b[-1]["payload_hex"][:16]
                                                               + (420_000_000).to_bytes(8, "little").hex()
                                                               + b[-1]["payload_hex"][32:]).hex()),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                changed = [dict(row) for row in records]
                other = [dict(row) for row in records]
                mutate(changed, other)
                a, b = Path(directory) / "a.jsonl", Path(directory) / "b.jsonl"
                write_export(a, changed, 0, min(8, len(changed)))
                write_export(b, other, 4, len(other))
                with self.assertRaises((ValueError, struct.error)):
                    stitcher.stitch([a, b], self.acceptance)


if __name__ == "__main__":
    unittest.main()
