#!/usr/bin/env python3
"""Reduce a V03-D sigrok capture into GPIO24-to-GPIO12 e-stop latencies.

Usage: v03d-reduce.py [--count N] capture.sr [capture.sr ...]

The capture must be acquired at 24 MHz with D0=GPIO24 and D1=GPIO12.  Each D0
falling edge is paired with the next D1 falling edge.  The reducer rejects
missing/extra edges, missing re-arms, out-of-order responses, unsafe final
levels, fewer than N=100 samples, and a maximum latency of 1 ms or more.
"""
import argparse
import math
import re
import sys
import tempfile
import unittest
import zipfile
from dataclasses import dataclass

SAMPLE_RATE_HZ = 24_000_000
LIMIT_NS = 1_000_000
SAMPLERATE = re.compile(r"^\s*(?:24\s*MHz|24000000)\s*$", re.IGNORECASE)
EDGE_TABLE = bytes.maketrans(bytes(range(256)), bytes(value & 3 for value in range(256)))
D0_FALL = re.compile(b"(?<=[\x01\x03])[\x00\x02]")
D0_RISE = re.compile(b"(?<=[\x00\x02])[\x01\x03]")
D1_FALL = re.compile(b"(?<=[\x02\x03])[\x00\x01]")
D1_RISE = re.compile(b"(?<=[\x00\x01])[\x02\x03]")


@dataclass
class Edges:
    d0_falls: list[int]
    d0_rises: list[int]
    d1_falls: list[int]
    d1_rises: list[int]
    initial: tuple[int, int] | None
    final: tuple[int, int] | None


def pct(values: list[int], percentile: float) -> int:
    # Nearest-rank percentile (also used by the V03-B reducer).
    k = max(0, min(len(values) - 1, math.ceil(percentile / 100 * len(values)) - 1))
    return values[k]


def ns(sample: int) -> int:
    return round(sample * 1_000_000_000 / SAMPLE_RATE_HZ)


def validate(edges: Edges, expected_count: int) -> tuple[list[int], list[str]]:
    errors: list[str] = []
    if edges.initial != (1, 1):
        errors.append(
            "capture must begin D0=1/D1=1 before the first D0 falling edge; "
            f"got {edges.initial!r}"
        )
    if edges.final != (0, 0):
        errors.append(f"capture must end safe with D0=0/D1=0; got {edges.final!r}")

    actual = (len(edges.d0_falls), len(edges.d0_rises), len(edges.d1_falls), len(edges.d1_rises))
    wanted = (expected_count, expected_count - 1, expected_count, expected_count - 1)
    labels = ("D0 falls (presses)", "D0 rises (releases)", "D1 falls (safe responses)", "D1 rises (re-arms)")
    for label, got, need in zip(labels, actual, wanted):
        if got != need:
            errors.append(f"{label}: got {got}, expected exactly {need}")

    latencies: list[int] = []
    for index, d0_fall in enumerate(edges.d0_falls):
        if index >= len(edges.d1_falls):
            errors.append(f"press {index + 1}: no D1 falling safe response")
            break
        d1_fall = edges.d1_falls[index]
        next_d0 = edges.d0_falls[index + 1] if index + 1 < len(edges.d0_falls) else None
        if d1_fall < d0_fall:
            errors.append(f"press {index + 1}: D1 fell before its D0 press")
        elif next_d0 is not None and d1_fall >= next_d0:
            errors.append(f"press {index + 1}: D1 did not fall before the next press")
        else:
            latencies.append(ns(d1_fall - d0_fall))

        if index + 1 < len(edges.d0_falls):
            # The output must remain safe until the physical e-stop releases:
            # press -> safe output -> release -> re-arm -> next press.
            if index >= len(edges.d0_rises) or index >= len(edges.d1_rises):
                errors.append(f"press {index + 1}: release/re-arm edge missing")
            elif not (
                d0_fall
                < d1_fall
                < edges.d0_rises[index]
                < edges.d1_rises[index]
                < next_d0
            ):
                errors.append(f"press {index + 1}: release/re-arm sequence is misaligned")

    # Any response edge not used in the positional pairing is an invalid extra.
    if len(edges.d1_falls) > len(edges.d0_falls):
        first_extra = edges.d1_falls[len(edges.d0_falls)]
        errors.append(f"extra D1 falling response at sample {first_extra}")
    return latencies, errors


def _srzip_metadata(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
        elif "=" in line and section == "device 1":
            key, value = line.split("=", 1)
            values[key.strip().lower()] = value.strip()
    return values


def _parse_srzip(path: str) -> Edges:
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f"invalid srzip capture: {exc}") from None
    with archive:
        try:
            metadata = archive.read("metadata").decode("utf-8")
        except (KeyError, UnicodeDecodeError) as exc:
            raise RuntimeError("srzip metadata is missing or invalid") from None
        values = _srzip_metadata(metadata)
        if not SAMPLERATE.fullmatch(values.get("samplerate", "")):
            raise RuntimeError("capture does not declare the required 24 MHz samplerate")
        if values.get("unitsize") != "1":
            raise RuntimeError("capture must use unitsize=1")
        try:
            total_probes = int(values["total probes"])
        except (KeyError, ValueError):
            raise RuntimeError("capture must declare a valid probe count") from None
        if total_probes < 2:
            raise RuntimeError("capture must declare at least two probes")
        if values.get("probe1") != "D0" or values.get("probe2") != "D1":
            raise RuntimeError("capture probes must be probe1=D0 and probe2=D1")
        capturefile = values.get("capturefile")
        if not capturefile:
            raise RuntimeError("srzip capturefile is missing")
        names = [info.filename for info in archive.infolist()]
        direct = [name for name in names if name == capturefile]
        numbered = [
            name for name in names
            if name.startswith(capturefile + "-") and name[len(capturefile) + 1:].isdigit()
        ]
        if direct and numbered:
            raise RuntimeError("srzip capturefile mixes unsuffixed and numbered raw chunks")
        if direct:
            members = direct
        else:
            chunk_numbers = sorted(int(name.rsplit("-", 1)[1]) for name in numbered)
            if chunk_numbers != list(range(1, len(chunk_numbers) + 1)):
                raise RuntimeError("srzip numbered raw chunks are missing or duplicated")
            members = [f"{capturefile}-{number}" for number in chunk_numbers]
        if not members:
            raise RuntimeError(f"srzip capturefile {capturefile!r} is missing")

        d0_falls: list[int] = []
        d0_rises: list[int] = []
        d1_falls: list[int] = []
        d1_rises: list[int] = []
        previous: tuple[int, int] | None = None
        initial: tuple[int, int] | None = None
        samples = 0
        carry = b""
        try:
            for member in members:
                with archive.open(member) as raw:
                    while chunk := raw.read(1024 * 1024):
                        data = (carry + chunk).translate(EDGE_TABLE)
                        base = samples - len(carry)
                        if initial is None:
                            initial = (data[0] & 1, (data[0] >> 1) & 1)
                        d0_falls.extend(base + match.start() for match in D0_FALL.finditer(data))
                        d0_rises.extend(base + match.start() for match in D0_RISE.finditer(data))
                        d1_falls.extend(base + match.start() for match in D1_FALL.finditer(data))
                        d1_rises.extend(base + match.start() for match in D1_RISE.finditer(data))
                        samples += len(data) - len(carry)
                        carry = data[-1:]
        except (OSError, zipfile.BadZipFile) as exc:
            raise RuntimeError(f"srzip raw data is unreadable: {exc}") from None
        previous = None if not carry else (carry[0] & 1, (carry[0] >> 1) & 1)
        return Edges(d0_falls, d0_rises, d1_falls, d1_rises, initial, previous)


def read_capture(path: str) -> Edges:
    return _parse_srzip(path)


def summarize(latencies: list[int]) -> None:
    values = sorted(latencies)
    print(f"latency samples: n={len(values)}")
    if not values:
        return
    for label, percentile in (("min", 0), ("median", 50), ("p95", 95),
                              ("p99", 99), ("p99.9", 99.9), ("max", 100)):
        value = values[0] if percentile == 0 else values[-1] if percentile == 100 else pct(values, percentile)
        print(f"  {label:>6}: {value:>9} ns ({value / 1000:.3f} us)")


def _write_test_srzip(path: str, raw: bytes, *, samplerate: str = "24 MHz",
                      probes: tuple[str, str] = ("D0", "D1"), unitsize: str = "1",
                      numbered_chunks: tuple[bytes, ...] | None = None) -> None:
    metadata = (
        "[global]\n"
        "[device 1]\n"
        "capturefile=logic-1\n"
        f"total probes={len(probes)}\n"
        f"samplerate={samplerate}\n"
        f"unitsize={unitsize}\n"
        f"probe1={probes[0]}\nprobe2={probes[1]}\n"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("metadata", metadata)
        if numbered_chunks is None:
            archive.writestr("logic-1", raw)
        else:
            for number, chunk in enumerate(numbered_chunks, 1):
                archive.writestr(f"logic-1-{number}", chunk)


class ReducerSelfTests(unittest.TestCase):
    def test_streams_chunk_boundary_and_validates_continuous_capture(self):
        raw = bytearray(b"\x03" * (1024 * 1024 - 1))
        for index in range(100):
            raw.extend((2, 0, 1, 3) if index < 99 else (2, 0))
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/capture.sr"
            _write_test_srzip(path, bytes(raw))
            edges = read_capture(path)
        latencies, errors = validate(edges, 100)
        self.assertEqual(errors, [])
        self.assertEqual(len(latencies), 100)

    def test_numbered_chunks_are_contiguous_and_preserve_cross_chunk_edges(self):
        raw = bytes((3, 2, 0, 1, 3) * 99 + (2, 0))
        with tempfile.TemporaryDirectory() as tmp:
            valid = f"{tmp}/numbered.sr"
            _write_test_srzip(valid, b"", numbered_chunks=(raw[:1], raw[1:]))
            edges = read_capture(valid)
            self.assertEqual(validate(edges, 100)[1], [])

            missing = f"{tmp}/missing-chunk.sr"
            metadata = (
                "[global]\n[device 1]\ncapturefile=logic-1\n"
                "total probes=2\nsamplerate=24 MHz\nunitsize=1\n"
                "probe1=D0\nprobe2=D1\n"
            )
            with zipfile.ZipFile(missing, "w") as archive:
                archive.writestr("metadata", metadata)
                archive.writestr("logic-1-1", raw[:1])
                archive.writestr("logic-1-3", raw[1:])
            with self.assertRaisesRegex(RuntimeError, "missing or duplicated"):
                read_capture(missing)

    def test_rejects_missing_edge_wrong_metadata_and_initial_state(self):
        raw = bytearray((3, 2, 0, 1, 3) * 98 + (2, 3) + (2, 0))
        with tempfile.TemporaryDirectory() as tmp:
            missing = f"{tmp}/missing.sr"
            _write_test_srzip(missing, bytes(raw))
            edges = read_capture(missing)
            self.assertTrue(any("D1 falls (safe responses)" in error for error in validate(edges, 100)[1]))

            wrong_rate = f"{tmp}/rate.sr"
            _write_test_srzip(wrong_rate, bytes(raw), samplerate="1 MHz")
            with self.assertRaisesRegex(RuntimeError, "24 MHz"):
                read_capture(wrong_rate)

            wrong_probe = f"{tmp}/probe.sr"
            _write_test_srzip(wrong_probe, bytes(raw), probes=("D1", "D0"))
            with self.assertRaisesRegex(RuntimeError, "probe1=D0"):
                read_capture(wrong_probe)

            wrong_unitsize = f"{tmp}/unitsize.sr"
            _write_test_srzip(wrong_unitsize, bytes(raw), unitsize="2")
            with self.assertRaisesRegex(RuntimeError, "unitsize=1"):
                read_capture(wrong_unitsize)

            initial_wrong = f"{tmp}/initial.sr"
            _write_test_srzip(initial_wrong, bytes((2,)) + bytes(raw))
            initial_edges = read_capture(initial_wrong)
            self.assertTrue(any("must begin" in error for error in validate(initial_edges, 100)[1]))

    def test_rejects_output_rearm_before_physical_release(self):
        raw = bytearray((3, 2, 0, 3, 1, 3) * 99 + (2, 0))
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/unsafe.sr"
            _write_test_srzip(path, bytes(raw))
            edges = read_capture(path)
        self.assertTrue(any("sequence is misaligned" in error for error in validate(edges, 100)[1]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=100, help="expected press count (default: 100)")
    parser.add_argument("--self-test", action="store_true", help="run reducer self-tests")
    parser.add_argument("captures", nargs="*", help="sigrok .sr captures")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.main(argv=[__file__], exit=False)
        return 0 if result.result.wasSuccessful() else 1
    if not args.captures:
        parser.error("provide at least one .sr capture")
    if args.count < 100:
        parser.error("--count must be >= 100")

    all_latencies: list[int] = []
    errors: list[str] = []
    for path in args.captures:
        if not path.endswith(".sr"):
            errors.append(f"{path}: expected a .sr capture")
            continue
        try:
            edges = read_capture(path)
        except RuntimeError as exc:
            errors.append(f"{path}: {exc}")
            continue
        latencies, capture_errors = validate(edges, args.count)
        all_latencies.extend(latencies)
        print(f"{path}: D0 falls={len(edges.d0_falls)} rises={len(edges.d0_rises)}; "
              f"D1 falls={len(edges.d1_falls)} rises={len(edges.d1_rises)}")
        errors.extend(f"{path}: {error}" for error in capture_errors)

    summarize(all_latencies)
    if len(all_latencies) < args.count:
        errors.append(f"only {len(all_latencies)} valid latency samples; need >= {args.count}")
    if all_latencies and max(all_latencies) >= LIMIT_NS:
        errors.append(f"max latency {max(all_latencies)} ns is not below {LIMIT_NS} ns (1 ms)")

    if errors:
        print("VERDICT: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"VERDICT: PASS (N={len(all_latencies)}, max < 1 ms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
