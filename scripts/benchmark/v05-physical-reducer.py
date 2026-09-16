#!/usr/bin/env python3
"""Reduce retained v0.5 physical evidence; raw inputs remain authoritative."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ACCEPTANCE = ROOT / "docs/performance/v0.5-acceptance.json"
AUDIT = runpy.run_path(str(Path(__file__).with_name("v05-audit-stitch.py")))
SHRIKE = runpy.run_path(str(ROOT / "scripts/hil/shrike-bench.py"))
SHA256 = re.compile(r"[0-9a-f]{64}")
SOURCE = re.compile(r"[0-9a-f]{40}")
BOOT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
PROVENANCE = {"source_features", "toolchain", "kernel", "rootfs", "firmware",
              "fpga", "wiring", "instrument", "rebuild_kernel"}
STATUS_FIELDS = {"type", "format", "version", "clock_frequency", "session",
                 "session_established", "persistent_boot_identity", "oldest", "end",
                 "overwritten", "dropped", "suppressed", "flags", "capacity",
                 "record_bytes", "latest_stop", "payloads_decoded", "timer"}
TIMER_FIELDS = {"releases_serviced", "releases_missed", "releases_late",
                "max_wake_lateness_ticks", "completion_misses", "safe_releases",
                "last_release_sequence", "last_scheduled_ticks", "last_actual_ticks",
                "timer_fault"}


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


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def json_file(path, limit=1024 * 1024):
    data = path.read_bytes()
    if not data or len(data) > limit:
        raise ValueError(f"empty or oversized JSON input {path}")
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v)))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"malformed JSON input {path}: {error}") from None
    if not isinstance(value, dict):
        raise ValueError(f"JSON input is not an object {path}")
    return value


def retained(root, value, *, directory=False):
    if not isinstance(value, str):
        raise ValueError("retained path is not a string")
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError(f"invalid retained path {value!r}")
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"retained path contains a symlink {value!r}")
    path = current.resolve()
    if not path.is_relative_to(root.resolve()) or (path.is_dir() if directory else path.is_file()) is False:
        raise ValueError(f"missing retained {'directory' if directory else 'file'} {value!r}")
    return path


def file_ref(root, value):
    if not isinstance(value, dict) or set(value) != {"path", "sha256"} or not SHA256.fullmatch(str(value.get("sha256"))):
        raise ValueError("invalid retained file reference")
    path = retained(root, value["path"])
    if sha256(path) != value["sha256"]:
        raise ValueError(f"retained file hash mismatch {value['path']}")
    return path


def status_sample(root, reference, expected_boot=None, query_timeout_ns=2_000_000_000):
    value = json_file(file_ref(root, reference), 64 * 1024)
    if set(value) != {"schema", "boot_id", "host_started_ns", "host_ended_ns", "status"} or value["schema"] != "axiomos.v05.status-sample.v1" or not BOOT.fullmatch(str(value["boot_id"])):
        raise ValueError("status sample envelope mismatch")
    if expected_boot is not None and value["boot_id"] != expected_boot:
        raise ValueError("status sample belongs to another boot")
    integer(value["host_started_ns"], "host_started_ns", positive=True)
    integer(value["host_ended_ns"], "host_ended_ns", positive=True)
    if (value["host_ended_ns"] < value["host_started_ns"]
            or value["host_ended_ns"] - value["host_started_ns"] > query_timeout_ns):
        raise ValueError("timing status query exceeded its bounded receipt interval")
    status = value["status"]
    if not isinstance(status, dict) or set(status) != STATUS_FIELDS or (
            status["type"], status["format"], status["version"],
            status["persistent_boot_identity"], status["payloads_decoded"]) != (
                "header", "axiomos-managed-audit", 2, False, False):
        raise ValueError("timing status schema mismatch")
    for key in ("clock_frequency", "session", "oldest", "end", "overwritten",
                "dropped", "suppressed", "flags", "capacity", "record_bytes"):
        integer(status[key], key, positive=key == "clock_frequency")
    if (type(status["session_established"]) is not bool or status["capacity"] != 2048
            or status["record_bytes"] != 96
            or status["oldest"] != max(0, status["end"] - status["capacity"])
            or status["oldest"] != status["overwritten"]
            or status["flags"] & ~63 or status["flags"] & 12
            or bool(status["flags"] & 1) != bool(status["clock_frequency"])
            or bool(status["flags"] & 2) != bool(status["session"])):
        raise ValueError("inconsistent timing recorder status")
    latest = status["latest_stop"]
    latest_recorded = isinstance(latest, dict) and latest.get("sequence") is not None
    if (bool(status["flags"] & 16) != (latest is not None)
            or bool(status["flags"] & 32) != latest_recorded):
        raise ValueError("latest-stop presence mismatch")
    if latest is not None:
        fields = {"type", "sequence", "ticks", "correlation", "kind", "payload_hex"}
        if (not isinstance(latest, dict) or set(latest) != fields
                or latest["type"] != "record" or latest["kind"] != 4
                or not isinstance(latest["payload_hex"], str)
                or len(latest["payload_hex"]) != 128
                or any(character not in "0123456789abcdef" for character in latest["payload_hex"])):
            raise ValueError("latest-stop record mismatch")
        for key in ("ticks", "correlation"):
            integer(latest[key], f"latest_stop.{key}")
        if latest["sequence"] is not None:
            integer(latest["sequence"], "latest_stop.sequence")
            if latest["sequence"] >= status["end"]:
                raise ValueError("latest-stop sequence is outside the retained history")
    timer = status["timer"]
    if not isinstance(timer, dict) or set(timer) != TIMER_FIELDS:
        raise ValueError("timing counter schema mismatch")
    for key in TIMER_FIELDS:
        integer(timer[key], key)
    if (timer["releases_serviced"] + timer["releases_missed"] != timer["last_release_sequence"]
            or timer["releases_late"] > timer["releases_serviced"]
            or timer["completion_misses"] > timer["releases_serviced"]
            or timer["safe_releases"] > timer["releases_serviced"]
            or timer["timer_fault"] > 8
            or (timer["releases_serviced"] == 0
                and any(timer[key] for key in ("last_release_sequence",
                                               "last_scheduled_ticks", "last_actual_ticks")))
            or (timer["releases_serviced"] != 0
                and (timer["last_release_sequence"] == 0
                     or timer["last_scheduled_ticks"] == 0))
            or timer["last_scheduled_ticks"] > timer["last_actual_ticks"]):
        raise ValueError("inconsistent cumulative timer status")
    return value


def status_delta(start, end, period_ns=10_000_000):
    if end["host_started_ns"] <= start["host_ended_ns"]:
        raise ValueError("status sample time did not advance")
    a, b = start["status"], end["status"]
    if a["clock_frequency"] != b["clock_frequency"]:
        raise ValueError("timer frequency changed within one interval")
    before, after = a["timer"], b["timer"]
    keys = TIMER_FIELDS - {"max_wake_lateness_ticks", "timer_fault"}
    if any(after[key] < before[key] for key in keys):
        raise ValueError("cumulative timer counter decreased")
    if (after["releases_missed"] != before["releases_missed"]
            or after["completion_misses"] != before["completion_misses"]
            or before["timer_fault"] != 0 or after["timer_fault"] != 0
            or after["max_wake_lateness_ticks"] < before["max_wake_lateness_ticks"]):
        raise ValueError("interval contains a missed release, completion miss, or timer fault")
    releases = after["last_release_sequence"] - before["last_release_sequence"]
    elapsed_min = end["host_started_ns"] - start["host_ended_ns"]
    elapsed_max = end["host_ended_ns"] - start["host_started_ns"]
    if releases * period_ns + period_ns < elapsed_min or releases * period_ns > elapsed_max + period_ns:
        raise ValueError("release count disagrees with the bounded host receipt interval")
    return {"elapsed_min_ns": elapsed_min, "elapsed_max_ns": elapsed_max,
            "releases": releases,
            "serviced": after["releases_serviced"] - before["releases_serviced"],
            "late": after["releases_late"] - before["releases_late"],
            "safe": after["safe_releases"] - before["safe_releases"],
            "max_wake_lateness_ticks": after["max_wake_lateness_ticks"]}


def reduce(manifest_path, acceptance_path=DEFAULT_ACCEPTANCE):
    root = manifest_path.resolve().parent
    campaign = json_file(manifest_path)
    expected = {"schema", "acceptance_config_sha256", "source_id", "motors_connected",
                "provenance", "bundles", "boots", "endurance", "load_trials", "fault_trials"}
    if set(campaign) != expected or campaign["schema"] != "axiomos.v05.physical-campaign.v1" or campaign["motors_connected"] is not False or not SOURCE.fullmatch(str(campaign["source_id"])):
        raise ValueError("physical campaign schema or source mismatch")
    acceptance = json_file(acceptance_path)
    config_digest = sha256(acceptance_path)
    if campaign["acceptance_config_sha256"] != config_digest:
        raise ValueError("physical campaign uses another acceptance configuration")
    provenance = campaign["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != PROVENANCE:
        raise ValueError("physical provenance is incomplete")
    provenance_paths = {name: file_ref(root, value) for name, value in provenance.items()}
    if sha256(provenance_paths["kernel"]) != sha256(provenance_paths["rebuild_kernel"]):
        raise ValueError("recorded kernel rebuild is not reproducible")
    source_features = json_file(provenance_paths["source_features"], 64 * 1024)
    if (set(source_features) != {"schema", "source_id", "features"}
            or source_features["schema"] != "axiomos.v05.source-features.v1"
            or source_features["source_id"] != campaign["source_id"]
            or not isinstance(source_features["features"], list)
            or any(not isinstance(value, str) for value in source_features["features"])
            or len(set(source_features["features"])) != len(source_features["features"])
            or not {"embedded-rpi5", "managed-runtime-bench-markers"}.issubset(
                source_features["features"])
            or {"bpf-unsigned-development", "bringup-diagnostics", "trace-control-link"}
            & set(source_features["features"])):
        raise ValueError("qualified source/features manifest mismatch")
    bundles = campaign["bundles"]
    if not isinstance(bundles, dict) or set(bundles) != {"controller_a", "controller_b", "private_state"}:
        raise ValueError("required signed bundle set is incomplete")
    bundle_paths = {name: file_ref(root, value) for name, value in bundles.items()}
    uploaded_digest = sha256(bundle_paths["controller_b"])

    boots = campaign["boots"]
    minimum = acceptance["campaign"]
    if not isinstance(boots, list) or len(boots) < minimum["physical_boots_min"]:
        raise ValueError("insufficient physical cold boots")
    boot_reports, run_reports = {}, {}
    total_releases = total_transitions = total_rearms = total_stops = total_cycle_failures = 0
    phase_counts = [0] * minimum["transition_phase_bins"]
    resident = rejected = 0
    for boot in boots:
        fields = {"boot_id", "boot_log", "boot_inventory", "audit_exports",
                  "status_start", "status_end", "shrike_runs"}
        if not isinstance(boot, dict) or set(boot) != fields or not BOOT.fullmatch(str(boot.get("boot_id"))) or boot["boot_id"] in boot_reports:
            raise ValueError("invalid or duplicate boot entry")
        boot_id = boot["boot_id"]
        log = file_ref(root, boot["boot_log"]).read_bytes()
        if len(log) > 16 * 1024 * 1024 or log.count(b"PI5_BOOT_OK") != 1 or any(marker in log for marker in (b"KERNEL_FATAL", b"kernel panicked", b"panicked at")):
            raise ValueError(f"boot {boot_id} lacks one clean PI5_BOOT_OK")
        inventory = json_file(file_ref(root, boot["boot_inventory"]), 64 * 1024)
        if set(inventory) != {"schema", "boot_id", "artifact_sha256"} or inventory["schema"] != "axiomos.v05.boot-inventory.v1" or inventory["boot_id"] != boot_id or not isinstance(inventory["artifact_sha256"], list) or any(not SHA256.fullmatch(str(value)) for value in inventory["artifact_sha256"]) or len(set(inventory["artifact_sha256"])) != len(inventory["artifact_sha256"]):
            raise ValueError(f"boot {boot_id} inventory is malformed")
        if uploaded_digest in inventory["artifact_sha256"]:
            raise ValueError(f"controller B was already present in boot {boot_id}")
        query_timeout = acceptance["timing"]["timing_status_query_timeout_ns"]
        start = status_sample(root, boot["status_start"], boot_id, query_timeout)
        end = status_sample(root, boot["status_end"], boot_id, query_timeout)
        interval = status_delta(start, end, acceptance["cpu"]["period_ns"])
        exports = boot["audit_exports"]
        if not isinstance(exports, list) or not exports:
            raise ValueError(f"boot {boot_id} has no audit exports")
        audit = AUDIT["stitch"]([file_ref(root, value) for value in exports], acceptance)
        transitions = sum(audit["successful_transitions"].values())
        if (audit["confirmed_handoffs"] != transitions
                or transitions < minimum["physical_successful_transitions_per_boot_min"]
                or not all(audit["successful_transitions"].values())
                or audit["missed_releases"] or audit["completion_misses"]
                or len(audit["transition_phase_bins"]) != len(phase_counts)
                or audit["uploads"]["resident"] == 0):
            raise ValueError(f"boot {boot_id} audit acceptance failed")
        for index, count in enumerate(audit["transition_phase_bins"]):
            phase_counts[index] += count
        resident += audit["uploads"]["resident"]
        rejected += sum(audit["uploads"]["rejected_by_errno"].values())
        total_rearms += len(audit["rearm_quiescence"])
        total_stops += sum(audit["stops"].values())
        total_cycle_failures += audit["cycle_failures"]
        runs = boot["shrike_runs"]
        if not isinstance(runs, list) or not runs:
            raise ValueError(f"boot {boot_id} has no physical analyzer run")
        for run in runs:
            if not isinstance(run, dict) or set(run) != {"path", "manifest_sha256"} or not SHA256.fullmatch(str(run.get("manifest_sha256"))) or run["path"] in run_reports:
                raise ValueError("invalid or duplicate analyzer run")
            path = retained(root, run["path"], directory=True)
            if sha256(path / "manifest.jsonl") != run["manifest_sha256"]:
                raise ValueError("analyzer manifest hash mismatch")
            report = SHRIKE["replay"](path)
            timing = report.get("v05_timing")
            if report.get("evidence_source") != "sigrok" or not isinstance(timing, dict) or timing.get("paired_overhead_p99_ppm", minimum["recorder_p99_overhead_ppm_max"] + 1) > minimum["recorder_p99_overhead_ppm_max"]:
                raise ValueError("analyzer run is not passing physical v0.5 evidence")
            run_reports[run["path"]] = report
        total_releases += interval["releases"]
        total_transitions += transitions
        boot_reports[boot_id] = {"timing": interval, "audit": audit,
                                 "analyzer_runs": len(runs)}

    if total_releases < minimum["physical_releases_min"] or total_transitions < minimum["physical_successful_transitions_min"] or any(count == 0 for count in phase_counts):
        raise ValueError("pooled release, transition, or phase coverage is insufficient")

    load_trials = campaign["load_trials"]
    required_loads = {"valid_post_boot", "invalid_signature", "verifier_rejection", "over_budget"}
    if not isinstance(load_trials, list) or {trial.get("case") for trial in load_trials if isinstance(trial, dict)} != required_loads:
        raise ValueError("physical loading cases are incomplete")
    valid = invalid = 0
    for trial in load_trials:
        if set(trial) != {"boot_id", "case", "errno"} or trial["boot_id"] not in boot_reports:
            raise ValueError("invalid physical loading trial")
        errno = integer(trial["errno"], "load trial errno")
        if (trial["case"] == "valid_post_boot") != (errno == 0):
            raise ValueError("loading trial outcome contradicts its case")
        valid += errno == 0
        invalid += errno != 0
    if resident < valid or rejected < invalid:
        raise ValueError("audit does not contain the declared physical loading outcomes")

    matrix = acceptance["fault_matrix"]
    trials = campaign["fault_trials"]
    if not isinstance(trials, list):
        raise ValueError("fault trials are not a list")
    coverage, assigned_runs = {}, set()
    for trial in trials:
        if not isinstance(trial, dict) or set(trial) != {"boot_id", "fault", "phase", "repeat", "run"} or trial["boot_id"] not in boot_reports or trial["run"] not in run_reports or trial["run"] in assigned_runs:
            raise ValueError("invalid or reused fault trial evidence")
        if trial["fault"] not in matrix["faults"] or trial["phase"] not in matrix["phases"]:
            raise ValueError("unknown fault or phase")
        repeat = integer(trial["repeat"], "fault repeat", positive=True)
        coverage.setdefault((trial["fault"], trial["phase"]), set()).add(repeat)
        assigned_runs.add(trial["run"])
    repeats = minimum["fault_phase_repeats_min"]
    for fault in matrix["faults"]:
        for phase in matrix["phases"]:
            observed = coverage.get((fault, phase), set())
            if observed != set(range(1, len(observed) + 1)) or len(observed) < repeats:
                raise ValueError(f"fault coverage incomplete for {fault}/{phase}")
    discontinuities = sum(1 for trial in trials if trial["fault"] in {"link_loss", "mcu_reset"})
    if total_stops < len(trials) or total_cycle_failures < sum(1 for trial in trials if trial["fault"] == "ack_failure") or total_rearms < len(boots) + discontinuities:
        raise ValueError("fault audit or reset/rearm custody is incomplete")

    endurance = campaign["endurance"]
    if not isinstance(endurance, dict) or set(endurance) != {"pilot", "soak"}:
        raise ValueError("pilot/soak evidence is incomplete")
    endurance_report = {}
    previous_end = None
    for name, seconds in (("pilot", minimum["pilot_seconds"]), ("soak", minimum["soak_seconds"])):
        interval = endurance[name]
        if not isinstance(interval, dict) or set(interval) != {"start", "end"}:
            raise ValueError(f"invalid {name} interval")
        query_timeout = acceptance["timing"]["timing_status_query_timeout_ns"]
        start = status_sample(root, interval["start"], query_timeout_ns=query_timeout)
        end = status_sample(root, interval["end"], start["boot_id"], query_timeout)
        result = status_delta(start, end, acceptance["cpu"]["period_ns"])
        if result["elapsed_min_ns"] < seconds * 1_000_000_000:
            raise ValueError(f"{name} interval is too short")
        if previous_end is not None and start["host_started_ns"] < previous_end:
            raise ValueError("soak did not follow the pilot")
        previous_end = end["host_ended_ns"]
        endurance_report[name] = result

    return {"schema": "axiomos.v05.physical-results.v1", "physical_acceptance": True,
            "source_id": campaign["source_id"], "acceptance_config_sha256": config_digest,
            "gate_results": {"reset_quiescence": "pass", "physical_campaign": "pass",
                             "fault_matrix": "pass", "recorder_overhead": "pass"},
            "totals": {"boots": len(boots), "releases": total_releases,
                       "successful_transitions": total_transitions,
                       "rearm_quiescence": total_rearms, "fault_trials": len(trials),
                       "phase_bins": phase_counts, "analyzer_runs": len(run_reports)},
            "endurance": endurance_report, "boots": boot_reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--acceptance", type=Path, default=DEFAULT_ACCEPTANCE)
    args = parser.parse_args()
    try:
        print(json.dumps(reduce(args.campaign, args.acceptance), sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"v0.5 physical reduction failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
