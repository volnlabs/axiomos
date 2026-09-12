#!/usr/bin/env python3
"""Verify retained ForgeFPGA setup evidence against the current canonical design.

This does not qualify hold/pulse timing, programming, runtime, or hardware.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys
import xml.etree.ElementTree as ET


BUILD_NAMES = ["final-nominal", *(f"final-guard-{index}" for index in range(5))]
CORNERS = [
    "tt1p1v25c_Typical",
    "ss0p99v85c_RCworst",
    "ss0p99vn40c_RCworst",
    "ff1p21v85c_RCbest",
    "ff1p21vn40c_RCbest",
]
IO_FUNCTIONS = {"clk": "OSC_CLK", "clk_en": "OSC_EN"}
for _signal, _gpio, _pin, _direction in [
    ("spi_sck", 3, 16, "IN"),
    ("spi_ss_n", 4, 17, "IN"),
    ("spi_mosi", 5, 18, "IN"),
    ("spi_miso", 6, 19, "OUT"),
    ("rst_n", 18, 9, "IN"),
    ("estop_n", 7, 20, "IN"),
    ("left_pwm_out", 8, 23, "OUT"),
    ("right_pwm_out", 9, 24, "OUT"),
    ("left_direction_out", 10, 1, "OUT"),
    ("right_direction_out", 11, 2, "OUT"),
]:
    IO_FUNCTIONS[_signal] = f"GPIO{_gpio}_{_direction} [PIN {_pin}]"
    if _direction == "OUT":
        IO_FUNCTIONS[_signal + "_en"] = f"GPIO{_gpio}_OE [PIN {_pin}]"


class EvidenceError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def require(condition: object, code: str, message: str) -> None:
    if not condition:
        raise EvidenceError(code, message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_manifest(evidence: Path) -> set[str]:
    manifest = evidence / "SHA256SUMS"
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise EvidenceError("missing_file", "SHA256SUMS is missing") from error
    except UnicodeDecodeError as error:
        raise EvidenceError("malformed_manifest", "SHA256SUMS is not UTF-8 text") from error
    require(lines, "malformed_manifest", "SHA256SUMS is empty")
    base = evidence.resolve()
    entries: dict[str, tuple[str, Path]] = {}
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9A-Fa-f]{64}) ([ *])(.+)", line)
        require(match, "malformed_manifest", f"SHA256SUMS line {number} is malformed")
        expected_hash, _, name = match.groups()
        relative = PurePosixPath(name)
        safe = (
            not relative.is_absolute()
            and name == relative.as_posix()
            and all(part not in ("", ".", "..") for part in relative.parts)
            and "\x00" not in name
        )
        require(safe, "unsafe_manifest_path", f"SHA256SUMS line {number} has an unsafe path")
        require(name not in entries, "duplicate_manifest_path", f"SHA256SUMS repeats {name}")
        path = evidence.joinpath(*relative.parts)
        try:
            resolved = path.resolve()
        except OSError as error:
            raise EvidenceError("unsafe_manifest_path", f"cannot resolve manifest path {name}") from error
        require(resolved.is_relative_to(base), "unsafe_manifest_path", f"manifest path escapes evidence: {name}")
        entries[name] = expected_hash.lower(), path
    for name, (expected_hash, path) in entries.items():
        require(path.is_file(), "missing_file", f"manifest file is missing: {name}")
        require(sha256(path) == expected_hash, "checksum_mismatch", f"SHA-256 mismatch: {name}")
    return set(entries)


class Evidence:
    def __init__(self, base: Path, manifest: set[str]):
        self.base = base
        self.manifest = manifest

    def file(self, relative: str) -> Path:
        require(relative in self.manifest, "unbound_evidence", f"file is absent from SHA256SUMS: {relative}")
        path = self.base / relative
        require(path.is_file(), "missing_file", f"evidence file is missing: {relative}")
        return path

    def text(self, relative: str) -> str:
        try:
            return self.file(relative).read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError("malformed_report", f"evidence is not UTF-8 text: {relative}") from error

    def xml(self, relative: str) -> ET.ElementTree:
        try:
            return ET.parse(self.file(relative))
        except ET.ParseError as error:
            raise EvidenceError("malformed_report", f"malformed XML: {relative}") from error


def parse_xml(path: Path, label: str) -> ET.ElementTree:
    try:
        return ET.parse(path)
    except FileNotFoundError as error:
        raise EvidenceError("missing_file", f"canonical file is missing: {label}") from error
    except ET.ParseError as error:
        raise EvidenceError("malformed_config", f"canonical XML is malformed: {label}") from error


def same_element(left: ET.Element | None, right: ET.Element | None) -> bool:
    return left is not None and right is not None and ET.tostring(left) == ET.tostring(right)


def project_config(project: ET.ElementTree, label: str, code: str) -> dict[str, ET.Element]:
    config = {}
    for tag in (
        "synthesize",
        "nvmData",
        "virtualProperties",
        "pllConfigurator",
        "generateBitstream",
        "timing-constraints",
        "io-spec-tool",
        "records",
    ):
        matches = project.findall(f".//{tag}")
        require(len(matches) == 1, code, f"{label}: expected one {tag} container")
        config[tag] = matches[0]
    settings = list(config["generateBitstream"])
    tags = [setting.tag for setting in settings]
    require(len(tags) == len(set(tags)), code, f"{label}: duplicate bitstream setting")
    require(tags.count("timingAnalysisCorner") == 1, code, f"{label}: expected one timingAnalysisCorner")
    return config


def normalized_bitstream_settings(settings: ET.Element) -> bytes:
    normalized = copy.deepcopy(settings)
    normalized.find("timingAnalysisCorner").text = "CORNER"
    return ET.tostring(normalized)


def parse_pin_assignments(text: str, build_name: str) -> dict[str, str]:
    actual: dict[str, str] = {}
    resource = None
    for line in text.splitlines():
        if line.startswith("EFLX_CLK"):
            match = re.search(r"chip_tile_x=(\d+), chip_tile_y=(\d+), clk_side=(\w)", line)
            require(match, "malformed_report", f"{build_name}: malformed clock resource")
            resource = f"CLK_t[{match[1]}:{match[2]}]_{match[3]}"
        elif line.startswith("EFLX_IOB"):
            match = re.search(r"chip_tile_x=(\d+), chip_tile_y=(\d+), chip_x=(\d+), chip_y=(\d+)", line)
            require(match, "malformed_report", f"{build_name}: malformed I/O resource")
            resource = f"IOB_t[{match[1]}:{match[2]}]_xy[{match[3]}:{match[4]}]"
        else:
            if re.match(r"\s*(?:Input|Output)=", line):
                match = re.fullmatch(
                    r"\s*(Input|Output)=(\d+),\s+pin=([A-Za-z_][A-Za-z0-9_]*)"
                    r"(?:,\s+(input_delay|output_delay)=(-?\d+))?\s*",
                    line,
                )
                require(match, "pin_mismatch", f"{build_name}: malformed pin assignment")
                assert match is not None
                require(
                    match[4] is None or match[4] == match[1].lower() + "_delay",
                    "pin_mismatch",
                    f"{build_name}: malformed pin delay",
                )
                require(resource is not None, "malformed_report", f"{build_name}: pin has no resource")
                require(match[3] not in actual, "pin_mismatch", f"{build_name}: duplicate pin {match[3]}")
                actual[match[3]] = resource + ("_in" if match[1] == "Input" else "_out") + match[2]
    return actual


def verify_build(
    evidence: Evidence,
    canonical: Path,
    canonical_project: ET.ElementTree,
    expected_pins: dict[str, str],
    name: str,
) -> dict[str, object]:
    prefix = f"{name}/ffpga"
    projects = [path for path in evidence.base.joinpath(name).glob("*.ffpga") if path.is_file()]
    require(len(projects) == 1, "malformed_report", f"{name}: expected one project snapshot")
    project_relative = projects[0].relative_to(evidence.base).as_posix()
    project = evidence.xml(project_relative)
    actual_config = project_config(project, name, "config_mismatch")
    canonical_config = project_config(canonical_project, "canonical project", "malformed_config")

    require(actual_config["synthesize"].findtext("useABC9") == "false", "config_mismatch", f"{name}: ABC9 is enabled")
    compiler_relative = f"{name}/PNR_STDOUT.log"
    compiler_retained = (evidence.base / compiler_relative).exists()
    if compiler_retained:
        compiler = evidence.text(compiler_relative)
        require(re.search(r"TIMING_DRIVEN_PACKING_THR\s*=\s*0\.8\b", compiler), "config_mismatch", f"{name}: packing threshold is not 0.8")
    console = evidence.text(f"{name}-console.log")
    success_candidates = [
        line
        for line in console.splitlines()
        if f"/{name}.tcl" in line and "successfully completed" in line
    ]
    success_pattern = re.compile(
        rf"\[\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}}\] "
        rf"\[Tcl\] \[info\] Evaluation of \S+/{re.escape(name)}\.tcl successfully completed"
    )
    require(
        len(success_candidates) == 1 and success_pattern.fullmatch(success_candidates[0]),
        "malformed_report",
        f"{name}: expected one exact Tcl completion record",
    )

    for tag in ("synthesize", "nvmData", "virtualProperties", "pllConfigurator"):
        require(same_element(actual_config[tag], canonical_config[tag]), "config_mismatch", f"{name}: {tag} differs from canonical")
    require(
        normalized_bitstream_settings(actual_config["generateBitstream"])
        == normalized_bitstream_settings(canonical_config["generateBitstream"]),
        "config_mismatch",
        f"{name}: bitstream settings differ from canonical",
    )

    script = evidence.text(f"{prefix}/build/synth_script.ys")
    require("-abc9" not in script and "-nocarry" not in script and "-widemux" not in script, "config_mismatch", f"{name}: rejected synthesis flags are present")
    require("synth_xilinx -nobram -noiopad -nodsp" in script, "config_mismatch", f"{name}: synthesis recipe differs")
    require("setattr -mod -unset keep_hierarchy; setattr -unset keep_hierarchy; flatten -noscopeinfo" in script, "config_mismatch", f"{name}: flatten recipe differs")
    require(actual_config["synthesize"].findtext("enableHardMultiplexerResources") == "false", "config_mismatch", f"{name}: hard muxes are enabled")

    netlist = evidence.text(f"{prefix}/build/post_synth_results.v")
    require(re.findall(r"^module (\w+)", netlist, re.M) == ["top"], "config_mismatch", f"{name}: synthesized module identity differs")
    require("history_enable_LUT4_O" in netlist, "config_mismatch", f"{name}: history LUT identity is missing")
    lut_cells = re.findall(r"LUT3 #\(.*?\n  \);", netlist, re.S)
    require(any(".O(\\receive_gate.active )" in cell for cell in lut_cells), "config_mismatch", f"{name}: receive gate LUT identity is missing")

    timing = evidence.text(f"{prefix}/build/PNR_TIMING.log")
    lines = timing.splitlines()
    summary_candidates = [line for line in lines if re.match(r"^\s*<DEFAULT>(?:\s|$)", line)]
    clock_candidates = [
        line
        for line in lines
        if re.match(r"^\s*clk\s+clk\s+<DEFAULT>(?:\s|$)", line) and "(" in line
    ]
    require(len(summary_candidates) == 1 and len(clock_candidates) == 1, "malformed_report", f"{name}: expected one setup summary and clock row")
    summary = re.fullmatch(r"\s*<DEFAULT>\s+1\s+1\s+(-?\d+)\s+(-?\d+)\s+(\d+)\s*", summary_candidates[0])
    clock = re.fullmatch(r"\s*clk\s+clk\s+<DEFAULT>\s+(\d+)\s+\([^)]*\)\s+(\d+)\s+([\d.]+)\s*", clock_candidates[0])
    require(summary and clock, "malformed_report", f"{name}: malformed setup summary or clock row")
    assert summary is not None and clock is not None
    period, _, frequency = clock.groups()
    wns, tns, endpoints = map(int, summary.groups())
    expected_period = 20000 if name == "final-nominal" else 18000
    require(int(period) == expected_period, "period_mismatch", f"{name}: expected {expected_period} ps period")

    constraints = project.findall(".//timing-constraints/module")
    expected_constraint = "clk_50mhz.sdc" if name == "final-nominal" else "clk_18ns_guard.sdc"
    require(len(constraints) == 1 and constraints[0].get("filename") == expected_constraint, "config_mismatch", f"{name}: timing constraint selection differs")
    placer = evidence.text(f"{prefix}/build/PNR_PLACER_TIMING.log")
    corner_candidates = [
        line
        for line in placer.splitlines()
        if line.lstrip().startswith("PLACER-ESTIMATED-TIMING TSMC 40nm ULP")
    ]
    require(len(corner_candidates) == 1, "malformed_report", f"{name}: expected one placer corner")
    corner_match = re.fullmatch(r"\s*PLACER-ESTIMATED-TIMING TSMC 40nm ULP (\S+)\s*", corner_candidates[0])
    require(corner_match, "malformed_report", f"{name}: malformed placer corner")
    assert corner_match is not None
    corner_text = actual_config["generateBitstream"].findtext("timingAnalysisCorner")
    corner_index = -1
    try:
        corner_index = int(corner_text) if corner_text is not None else -1
        expected_corner = CORNERS[corner_index] if corner_index >= 0 else ""
    except (ValueError, IndexError):
        expected_corner = ""
    required_corner_index = 0 if name == "final-nominal" else int(name.rsplit("-", 1)[1])
    require(corner_index == required_corner_index, "corner_mismatch", f"{name}: required corner is missing")
    corner = corner_match[1]
    require(corner == expected_corner, "corner_mismatch", f"{name}: process corner differs")

    pins = parse_pin_assignments(evidence.text(f"{prefix}/build/PNR_IO.log"), name)
    require(pins == expected_pins, "pin_mismatch", f"{name}: pin assignments differ")
    for subdirectory, pattern in (("src", "*.v"), ("timing-constraints", "*.sdc")):
        canonical_files = list(canonical.joinpath("ffpga", subdirectory).glob(pattern))
        require(canonical_files, "missing_file", f"canonical {subdirectory} files are missing")
        for source in canonical_files:
            retained = evidence.file(f"{prefix}/{subdirectory}/{source.name}")
            require(source.read_bytes() == retained.read_bytes(), "source_sdc_mismatch", f"{name}: {source.name} differs from canonical")

    utilization = evidence.text(f"{prefix}/build/resource-utilization-report.log")
    clb_match = re.search(r"CLBs:\s+(\d+)/140", utilization)
    require(clb_match, "malformed_report", f"{name}: CLB utilization is missing")
    bitstream = evidence.file(f"{prefix}/build/bitstream/FPGA_bitstream_MCU.bin")
    require(bitstream.stat().st_size == 46408, "malformed_report", f"{name}: MCU bitstream size differs")
    setup_pass = wns >= 0 and tns == 0 and endpoints == 0
    return {
        "build": name,
        "corner": corner,
        "period_ps": int(period),
        "setup_wns_ps": wns,
        "setup_tns_ps": tns,
        "failing_endpoints": endpoints,
        "achievable_frequency_mhz": float(frequency),
        "logic_clbs": int(clb_match[1]),
        "setup_pass": setup_pass,
        "pin_assignments_match": True,
        "source_and_sdc_match": True,
        "compiler_stdout_retained": compiler_retained,
        "mcu_sha256": sha256(bitstream),
        "final_hold": "not exported",
        "pulse_width": "not exported",
    }


def verify(root: Path, evidence_dir: Path) -> tuple[dict[str, object], int]:
    require(evidence_dir.is_dir(), "missing_file", "evidence directory is missing")
    manifest = validate_manifest(evidence_dir)
    evidence = Evidence(evidence_dir, manifest)
    canonical = root / "firmware/shrike/fpga/forgefpga"
    canonical_project = parse_xml(canonical / "axiomos_r04.ffpga", "axiomos_r04.ffpga")
    project_config(canonical_project, "canonical project", "malformed_config")
    expected_pins = {}
    for record in canonical_project.findall(".//io-spec-tool/records/record"):
        port = record.findtext("port-name")
        if port:
            require(port not in expected_pins, "malformed_config", f"canonical project repeats I/O port {port}")
            require("id" in record.attrib, "malformed_config", f"canonical I/O port {port} has no resource")
            expected_pins[port] = record.attrib["id"]
    require(expected_pins, "malformed_config", "canonical project has no I/O records")
    builds = [verify_build(evidence, canonical, canonical_project, expected_pins, name) for name in BUILD_NAMES]

    try:
        with evidence.file("final-io-planner.csv").open(encoding="utf-8") as stream:
            exported = {}
            for row in csv.DictReader(stream, delimiter=";"):
                if row["PORT"]:
                    require(row["PORT"] not in exported, "pin_mismatch", f"I/O planner repeats {row['PORT']}")
                    exported[row["PORT"]] = row["FUNCTION"]
    except (KeyError, csv.Error, UnicodeDecodeError) as error:
        raise EvidenceError("malformed_report", "I/O planner export is malformed") from error
    require(exported == IO_FUNCTIONS, "pin_mismatch", "I/O planner functions differ")
    report = {
        "builds": builds,
        "io_planner_match": True,
        "all_corner_setup_pass": all(build["setup_pass"] for build in builds),
        "physical_qualification": "pending",
        "runtime_enabled": False,
        "programmed": False,
    }
    require(report["all_corner_setup_pass"], "setup_failed", "one or more setup corners failed")
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite JSON number")
        return parsed

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    try:
        retained = json.loads(
            evidence.text("results.json"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise EvidenceError("malformed_report", "results.json is malformed") from error
    def same_json_type(left: object, right: object) -> bool:
        if type(left) is not type(right):
            return False
        if isinstance(left, dict):
            return left.keys() == right.keys() and all(same_json_type(left[key], right[key]) for key in left)
        if isinstance(left, list):
            return len(left) == len(right) and all(same_json_type(a, b) for a, b in zip(left, right))
        return left == right

    require(same_json_type(retained, report), "result_mismatch", "recomputed results differ from retained results.json")
    return report, len(manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        report, entries = verify(args.root.resolve(), args.evidence_dir.resolve())
        output = {"status": "pass", "manifest_entries": entries, "results": report}
        return_code = 0
    except EvidenceError as error:
        output = {"status": "error", "error": {"code": error.code, "message": str(error)[:240]}}
        return_code = 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        output = {"status": "error", "error": {"code": "invalid_evidence", "message": str(error)[:240]}}
        return_code = 1
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return return_code


if __name__ == "__main__":
    sys.exit(main())
