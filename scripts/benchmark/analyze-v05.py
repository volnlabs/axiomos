#!/usr/bin/env python3
"""Strict initial v0.5 JSONL reducer for trace integrity and cycle timing.

Input is UTF-8 JSONL: one ``header``, typed events with contiguous ``seq`` and
nondecreasing integer ``ticks``, then one ``terminal``. Exact event fields are
listed by ``--describe``. ``--expectations FILE`` supplies independent exact
event/outcome counts and a contiguous release range per boot.

Examples::

  python3 scripts/benchmark/analyze-v05.py --describe
  python3 scripts/benchmark/analyze-v05.py --self-test
  python3 scripts/benchmark/analyze-v05.py --expectations expected.json trace.jsonl
  python3 scripts/benchmark/analyze-v05.py --show-acceptance

Optional --reclamation validates retained host resource tests only.
Optional --software validates the fixed host software-property suite.
Optional --physical-campaign validates the retained hardware campaign.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ACCEPTANCE = ROOT / "docs/performance/v0.5-acceptance.json"
TRACE_SCHEMA = "axiomos.v05.trace.v1"
EXPECTATIONS_SCHEMA = "axiomos.v05.expectations.v1"
OUTCOMES = ("successful", "failed", "rejected", "canceled")
PHYSICAL_GATES = ("reset_quiescence", "physical_campaign", "fault_matrix",
                  "recorder_overhead")

RECLAMATION_CASES = {
    "ownership": "bpf::managed::tests::managed_ownership_lifecycle_survives_100_000_fresh_instances",
    "installation": "bpf::installation::tests::installation_100000_transitions_bound_real_retention_and_high_water",
    "deactivation": "bpf::installation::tests::deactivation_100000_transitions_keep_retained_code_and_zero_instance_floor",
    "generation_exhaustion": "bpf::installation::tests::installation_stale_exhaustion_and_failed_build_preserve_active",
    "preparation_exhaustion": "bpf::managed::tests::managed_preparation_counter_exhaustion_does_not_reserve_resources",
    "reclamation_exhaustion": "bpf::managed::tests::managed_reclamation_counter_exhaustion_preserves_tables_bindings_and_charges",
    "eviction_custody": "bpf::installation::tests::installation_a_b_c_rollback_keeps_actual_code_and_fresh_helper_state",
    "reader_retirement": "bpf::installation::tests::installation_permanent_worker_retries_exact_retirement_until_readers_and_weak_release",
}
# Fixed host acceptance cases, reviewed against the canonical contract. These
# logs prove the listed assertions ran; they are not execution attestations.
SOFTWARE_CASES = {
    "authentication_and_loading": {
        "manifest_tampering": ("kernel_bpf", "signing::managed::tests::every_wire_byte_is_authenticated_or_rejected_as_invalid"),
        "signed_unsupported_shape": ("kernel_bpf", "signing::managed::tests::supported_shape_checks_apply_even_to_validly_signed_inputs"),
        "malformed_bundles": ("kernel_bpf", "signing::managed::tests::truncated_extra_empty_and_oversized_bundles_reject"),
        "actual_preparation": ("kernel", "bpf::preparation::tests::managed_preparation_valid_dedup_auth_verify_and_cancel_paths_balance_charges"),
        "elf_rejection": ("kernel", "bpf::tests::legacy_elf_composition_rejects_without_publishing_resources"),
        "elf_acceptance": ("kernel", "bpf::tests::legacy_elf_composition_accepts_one_map_free_entry"),
    },
    "preparation_isolation": {
        "stateful_failures": ("kernel", "bpf::preparation::tests::isolation::preparation_failures_preserve_stateful_active_previous_and_admission"),
    },
    "private_state": {
        "separate_instances": ("kernel", "bpf::managed::tests::managed_execution_uses_exact_bindings_and_keeps_instance_state_isolated"),
        "external_access": ("kernel", "bpf::managed::tests::managed_objects_reject_legacy_access_and_bound_artifacts"),
        "fresh_rollback": ("kernel", "bpf::installation::tests::installation_a_b_c_rollback_keeps_actual_code_and_fresh_helper_state"),
        "local_handles": ("kernel_bpf", "verifier::managed::tests::managed_local_bindings_reject_absent_dynamic_global_and_stale_handles"),
    },
    "ownership": {
        "upload_and_preparation_exit": ("kernel", "bpf::preparation::tests::managed_preparation_exit_cancels_only_incomplete_process_owned_upload"),
        "active_exit": ("kernel", "bpf::preparation::tests::worker_cancellation_at_each_build_and_handoff_boundary_preserves_old_active"),
        "retirement_exit": ("kernel", "bpf::preparation::tests::worker_inactive_retirement_candidate_commit_keeps_public_identity_and_reader_custody"),
    },
    "publication_races": {
        "writer_schedules": ("kernel", "bpf::installation::tests::interleavings::all_legal_writer_cancel_stop_and_worker_schedules_preserve_the_active_installation"),
        "stop_commit_boundary": ("kernel", "bpf::installation::tests::interleavings::stop_before_or_after_release_commit_has_one_authoritative_generation"),
        "stale_a_b_a": ("kernel", "bpf::installation::tests::interleavings::stale_a_b_a_operation_and_generation_ids_cannot_republish"),
        "handoff_invalidation": ("kernel", "bpf::installation::tests::stop_cancel_timeout_and_reset_cannot_publish_even_with_matching_ack"),
    },
    "handoff": {
        "old_frame_offsets": ("shrike_link", "handoff::tests::barrier_follows_a_whole_old_frame_at_every_offset_and_discards_unsent_motion"),
        "matching_ack": ("shrike_link", "handoff::tests::only_matching_ack_after_whole_frame_makes_next_boundary_eligible_once"),
        "canceled_frame_offsets": ("shrike_link", "handoff::tests::cancelled_handoff_frame_keeps_completion_identity_at_every_byte_offset"),
        "barrier_identity": ("shrike_paired", "managed_offer_and_barrier_echo_exact_identity_and_block_stale_motion"),
        "fpga_status": ("shrike_paired", "managed_fpga_posttransaction_mismatch_cannot_emit_acknowledgement"),
        "reverse_tx_offsets": ("shrike_paired", "requalify_finishes_each_started_reply_offset_and_discards_pending_motion"),
    },
    "failure_custody": {
        "request_and_map_faults": ("kernel", "bpf::control::tests::map_failure_after_capture_discards_request_stops_release_and_releases_lease"),
        "request_validation": ("kernel_bpf", "execution::interpreter::tests::managed_verified_failures_never_publish_an_earlier_capture"),
        "queue_and_deadline_stop": ("kernel", "bpf::control::tests::missed_deadlines_reversed_clocks_and_queue_failure_never_resume_automatically"),
        "observer_separation": ("kernel", "bpf::managed::tests::managed_objects_reject_legacy_access_and_bound_artifacts"),
    },
    "scheduling": {
        "absolute_releases": ("kernel_time", "periodic::tests::absolute_releases_account_for_gaps_without_catch_up"),
        "masked_interval": ("kernel_time", "periodic::tests::long_masked_interval_cannot_look_like_a_passing_schedule"),
        "counter_exhaustion": ("kernel_time", "periodic::tests::invalid_clock_and_counter_exhaustion_reject_before_mutation"),
    },
    "abi": {
        "legacy_mode_restrictions": ("kernel", "syscall::bpf::tests::managed_wheel_ownership_blocks_legacy_mutations_but_preserves_read_commands"),
        "upload_shapes": ("kernel", "syscall::managed::tests::managed_abi_validates_its_own_shape_before_mutation"),
        "lifecycle_shapes": ("kernel", "syscall::managed::tests::lifecycle_layouts_validate_before_resolving_exact_targets"),
        "query_shapes": ("kernel", "syscall::managed::tests::artifact_query_keeps_v1_and_rejects_every_nonzero_output_byte"),
        "recorder_shapes": ("kernel", "syscall::managed::tests::recorder_headers_reject_inexact_lengths_and_unknown_versions"),
        "syscall_sizes": ("kernel", "syscall::managed::tests::managed_commands_reject_wrong_syscall_size_before_user_copy"),
    },
    "recorder": {
        "bounded_window": ("kernel", "bpf::recorder::tests::recorder_queries_preserve_clock_and_bound_lost_frozen_intervals"),
        "fault_custody": ("kernel", "bpf::recorder::events::tests::actual_controller_fault_keeps_queue_outcome_identity_and_stop_window"),
        "identity_decode": ("rk_cli", "commands::runtime::audit::decode::tests::offline_identity_and_lifecycle_require_exact_fragments_and_correlated_boundaries"),
        "malformed_decode": ("rk_cli", "commands::runtime::audit::decode::tests::offline_decode_rejects_incomplete_reordered_malformed_and_oversized_data"),
    },
}
SOFTWARE_EXECUTABLES = {"kernel": "host-test", "kernel_bpf": "bpf-test",
                        "rk_cli": "rk-cli-test", "kernel_time": "kernel-time-test",
                        "shrike_link": "shrike-link-test", "shrike_paired": "shrike-paired-test"}
RESOURCE_MAXIMA = {
    "ownership": {"instances_live": 1, "artifact_strong_live": 2, "instance_strong_live": 2},
    "installation": {"instances_before_reclamation": 2, "active_artifact_strong_after_reclamation": 3,
                     "previous_artifact_strong_after_reclamation": 2},
    "deactivation": {"instances_active": 1, "retained_artifact_strong_after_reclamation": 2},
}

FIELDS = {
    "operation_request": {"seq", "ticks", "operation_id", "operation", "generation", "artifact_id"},
    "operation_accepted": {"seq", "ticks", "operation_id", "generation", "artifact_id"},
    "handoff_enter": {"seq", "ticks", "operation_id", "generation", "artifact_id"},
    "sink_safe_ready": {"seq", "ticks", "operation_id", "generation", "artifact_id"},
    "operation_committed": {"seq", "ticks", "operation_id", "cycle", "generation", "artifact_id"},
    "operation_response": {"seq", "ticks", "operation_id", "outcome"},
    "cycle_release": {"seq", "ticks", "cycle", "scheduled_ticks", "mode", "generation"},
    "behavior_enter": {"seq", "ticks", "cycle", "generation", "artifact_id"},
    "behavior_exit": {"seq", "ticks", "cycle", "generation", "artifact_id"},
    "cycle_complete": {"seq", "ticks", "cycle", "mode", "generation"},
}
HEADER_FIELDS = {"type", "schema", "evidence_kind", "boot_id", "clock_hz", "source_id", "artifact_id", "acceptance_config_sha256"}
TERMINAL_FIELDS = {"type", "seq", "ticks", "event_count", "last_event_seq"}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def parse_json(text: str):
    try:
        return json.loads(text, object_pairs_hook=_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON number {value}")))
    except json.JSONDecodeError as error:
        raise ValueError(f"malformed JSON: {error.msg}") from None


def load_json(path: Path):
    return parse_json(path.read_text(encoding="utf-8"))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_jsonl(text: str) -> list[dict]:
    if not text or not text.endswith("\n"):
        raise ValueError("truncated JSONL: final newline missing")
    rows = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise ValueError(f"line {line_no}: empty record")
        value = parse_json(line)
        if not isinstance(value, dict):
            raise ValueError(f"line {line_no}: record must be an object")
        rows.append(value)
    return rows


def _integer(record: dict, key: str, *, positive: bool = False) -> int:
    value = record.get(key)
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError(f"{record.get('type')}: invalid {key}")
    return value


def _identity(value, key):
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid {key}")


def _one_of(value, allowed) -> bool:
    return isinstance(value, str) and value in allowed


def _at_or_over_ns(delta_ticks: int, limit_ns: int, clock_hz: int) -> bool:
    return delta_ticks * 1_000_000_000 >= limit_ns * clock_hz


def _over_ns(delta_ticks: int, limit_ns: int, clock_hz: int) -> bool:
    return delta_ticks * 1_000_000_000 > limit_ns * clock_hz


def _evidence_file(parent: Path, name, digest) -> Path:
    if (not isinstance(name, str) or not name or Path(name).is_absolute()
            or ".." in Path(name).parts):
        raise ValueError("invalid retained evidence path")
    path = (parent / name).resolve()
    if not path.is_relative_to(parent) or not path.is_file():
        raise ValueError("retained evidence path escapes or is missing")
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or file_sha256(path) != digest):
        raise ValueError("retained evidence hash mismatch")
    return path


def _resource_counter(row: dict, key: str, *, positive=False) -> int:
    value = _integer(row, key, positive=positive)
    if value > (1 << 64) - 1:
        raise ValueError("resource counter exceeds u64")
    return value


def _resource_witness(row: dict, case: str, minimum: int) -> None:
    fields = {"schema", "case", "iterations", "transitions", "generation", "baseline", "floor", "high_water", "final", "observed_maxima"}
    if not isinstance(row, dict) or set(row) != fields or row["schema"] != "axiomos.v05.resources.v1" or row["case"] != case:
        raise ValueError("malformed resource witness")
    iterations, transitions = _resource_counter(row, "iterations", positive=True), _resource_counter(row, "transitions")
    if case == "ownership":
        valid_count = iterations >= minimum and transitions == 0 and row["generation"] is None
    else:
        _resource_counter(row, "generation", positive=True)
        valid_count = (transitions >= minimum and type(row["generation"]) is int
                       and row["generation"] == transitions
                       and transitions == (iterations + 2 if case == "installation" else iterations * 2))
    if not valid_count:
        raise ValueError("resource churn coverage or generation mismatch")
    resource_fields = {"live_programs", "program_bytes", "live_maps", "map_bytes"}
    for key in ("baseline", "floor", "high_water", "final"):
        usage = row[key]
        if not isinstance(usage, dict) or set(usage) != resource_fields:
            raise ValueError("malformed resource usage")
        for field in resource_fields:
            _resource_counter(usage, field)
    baseline, floor, high, final = (row[key] for key in ("baseline", "floor", "high_water", "final"))
    if final != baseline or any(high[key] < floor[key] or floor[key] < baseline[key] for key in resource_fields):
        raise ValueError("resource plateau or high-water contradiction")
    expected_programs, expected_maps = (2, 1) if case == "installation" else (1, 0)
    if (floor["live_programs"] != expected_programs or floor["live_maps"] != expected_maps
            or high["live_programs"] != expected_programs or high["live_maps"] != expected_maps + 1
            or high["program_bytes"] <= floor["program_bytes"] or high["map_bytes"] <= floor["map_bytes"]):
        raise ValueError("resource instance high-water contradiction")
    if case == "ownership":
        if (baseline["live_programs"] != 0 or baseline["live_maps"] != 0
                or baseline["map_bytes"] != floor["map_bytes"]
                or baseline["program_bytes"] >= floor["program_bytes"]):
            raise ValueError("resource artifact baseline contradiction")
    elif baseline != floor:
        raise ValueError("resource retained floor contradiction")
    maxima = row["observed_maxima"]
    if (not isinstance(maxima, dict) or maxima != RESOURCE_MAXIMA[case]
            or any(type(value) is not int for value in maxima.values())):
        raise ValueError("resource retained-reference contradiction")


def validate_reclamation(path: Path, source: str, config: str, acceptance: dict) -> dict:
    evidence = load_json(path)
    if (not isinstance(evidence, dict) or set(evidence) != {"schema", "source_id", "acceptance_config_sha256", "executable", "cases"}
            or evidence["schema"] != "axiomos.v05.reclamation.v1"
            or evidence["source_id"] != source or evidence["acceptance_config_sha256"] != config):
        raise ValueError("reclamation schema, source or acceptance mismatch")
    parent = path.resolve().parent
    executable = evidence["executable"]
    if not isinstance(executable, dict) or set(executable) != {"path", "sha256"} or executable["path"] != "host-test":
        raise ValueError("malformed reclamation executable")
    used_paths = {_evidence_file(parent, executable["path"], executable["sha256"])}
    cases = evidence["cases"]
    if not isinstance(cases, list) or len(cases) != len(RECLAMATION_CASES):
        raise ValueError("missing reclamation cases")
    campaign = acceptance.get("campaign")
    if not isinstance(campaign, dict):
        raise ValueError("malformed reclamation campaign")
    minimum = _resource_counter(campaign, "host_churn_operations_min", positive=True)
    resources = acceptance.get("resources")
    if not isinstance(resources, dict) or not isinstance(resources.get("retire_batch_capacity"), dict):
        raise ValueError("malformed reclamation resource limits")
    # The fixed eviction case holds A/B/C plus one displaced instance and one
    # evicted artifact in a single retirement batch. Churn observes two instances.
    for limits, required in ((resources, {"max_artifacts": 3, "max_instances": 2, "max_retire_batches": 1}),
                             (resources["retire_batch_capacity"], {"displaced_instances": 1, "evicted_artifacts": 1})):
        if any(_resource_counter(limits, name) < count for name, count in required.items()):
            raise ValueError("reclamation observations exceed configured resource limits")
    seen, witnesses = set(), {}
    for case in cases:
        if (not isinstance(case, dict) or set(case) != {"case", "test", "stdout", "stdout_sha256", "stderr", "stderr_sha256", "returncode"}
                or not isinstance(case["case"], str) or case["case"] not in RECLAMATION_CASES
                or case["case"] in seen or case["test"] != RECLAMATION_CASES[case["case"]]
                or type(case["returncode"]) is not int or case["returncode"] != 0):
            raise ValueError("malformed, duplicate or failed reclamation case")
        name = case["case"]
        seen.add(name)
        logs = {}
        for stream in ("stdout", "stderr"):
            log = _evidence_file(parent, case[stream], case[stream + "_sha256"])
            if log in used_paths:
                raise ValueError("reclamation cases reuse evidence paths")
            used_paths.add(log)
            logs[stream] = log.read_text(encoding="utf-8")
        lines = logs["stdout"].splitlines()
        footer = [line for line in lines if line.startswith("test result:")]
        if (not logs["stdout"].endswith("\n") or lines.count("running 1 test") != 1
                or sum(line.startswith("running ") for line in lines) != 1 or len(footer) != 1
                or not re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", footer[0])
                or any(line.strip() for line in lines[lines.index(footer[0]) + 1:])):
            raise ValueError("reclamation log lacks exact successful test completion")
        test_lines = [line for line in lines if line.startswith("test ") and not line.startswith("test result:")]
        if len(test_lines) != 1 or not test_lines[0].startswith("test " + case["test"] + " ... "):
            raise ValueError("reclamation log test identity mismatch")
        if not lines.index("running 1 test") < lines.index(test_lines[0]) < lines.index(footer[0]):
            raise ValueError("reclamation test identity outside execution")
        witness_lines = [line for line in lines if line.startswith("V05_RESOURCE")]
        if name in RESOURCE_MAXIMA:
            if len(witness_lines) != 1 or not witness_lines[0].startswith("V05_RESOURCE "):
                raise ValueError("missing or malformed resource witness")
            if not lines.index("running 1 test") < lines.index(witness_lines[0]) < lines.index(footer[0]):
                raise ValueError("resource witness outside test execution")
            witness = parse_json(witness_lines[0][len("V05_RESOURCE "):])
            _resource_witness(witness, name, minimum)
            witnesses[name] = witness
        elif witness_lines:
            raise ValueError("unexpected resource witness")
    return {"manifest_sha256": file_sha256(path), "test_executable_sha256": executable["sha256"],
            "cases": sorted(seen), "witnesses": witnesses,
            "scope": "retained host tests; not physical or timing qualification"}


def validate_software(path: Path, source: str, config: str) -> dict:
    evidence = load_json(path)
    if (not isinstance(evidence, dict)
            or set(evidence) != {"schema", "source_id", "acceptance_config_sha256", "executables", "cases"}
            or evidence["schema"] != "axiomos.v05.software.v1"
            or evidence["source_id"] != source or evidence["acceptance_config_sha256"] != config):
        raise ValueError("software schema, source or acceptance mismatch")
    parent = path.resolve().parent
    executables = evidence["executables"]
    if not isinstance(executables, dict) or set(executables) != set(SOFTWARE_EXECUTABLES):
        raise ValueError("missing software executables")
    used_paths = {path.resolve()}
    for name, expected_path in SOFTWARE_EXECUTABLES.items():
        executable = executables[name]
        if (not isinstance(executable, dict) or set(executable) != {"path", "sha256"}
                or executable["path"] != expected_path):
            raise ValueError("malformed software executable")
        resolved = _evidence_file(parent, executable["path"], executable["sha256"])
        if resolved in used_paths:
            raise ValueError("software executables reuse evidence paths")
        used_paths.add(resolved)
    cases = evidence["cases"]
    if not isinstance(cases, list) or len(cases) != sum(map(len, SOFTWARE_CASES.values())):
        raise ValueError("missing software cases")
    seen = set()
    for case in cases:
        if (not isinstance(case, dict)
                or set(case) != {"gate", "case", "executable", "test", "stdout", "stdout_sha256", "stderr", "stderr_sha256", "returncode"}
                or not all(isinstance(case[key], str) for key in ("gate", "case", "executable", "test"))
                or case["gate"] not in SOFTWARE_CASES
                or case["case"] not in SOFTWARE_CASES[case["gate"]]
                or (case["executable"], case["test"]) != SOFTWARE_CASES[case["gate"]][case["case"]]
                or (case["gate"], case["case"]) in seen
                or type(case["returncode"]) is not int or case["returncode"] != 0):
            raise ValueError("malformed, duplicate or failed software case")
        seen.add((case["gate"], case["case"]))
        logs = {}
        for stream in ("stdout", "stderr"):
            log = _evidence_file(parent, case[stream], case[stream + "_sha256"])
            if log in used_paths:
                raise ValueError("software cases reuse evidence paths")
            used_paths.add(log)
            logs[stream] = log.read_text(encoding="utf-8")
        # These cases run with libtest capture enabled, without --quiet. Exact
        # ordered completion rejects empty selection, ignored tests and crashes.
        lines = [line for line in logs["stdout"].splitlines() if line]
        if (logs["stderr"] or not logs["stdout"].endswith("\n") or len(lines) != 3
                or lines[:2] != ["running 1 test", "test " + case["test"] + " ... ok"]
                or not re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[2])):
            raise ValueError("software log lacks exact successful test completion")
    return {"manifest_sha256": file_sha256(path),
            "executables_sha256": {name: value["sha256"] for name, value in executables.items()},
            "cases": [f"{gate}/{case}" for gate, case in sorted(seen)],
            "scope": "fixed host property tests; ownership uses manager cleanup calls, not process-exit scheduling; no physical or timing qualification"}


def validate_physical(path: Path, source: str, config: str, acceptance_path: Path) -> dict:
    reducer = runpy.run_path(str(Path(__file__).with_name("v05-physical-reducer.py")))
    evidence = reducer["reduce"](path, acceptance_path)
    gate_results = evidence.get("gate_results")
    valid_gates = (isinstance(gate_results, dict)
                   and set(gate_results) == set(PHYSICAL_GATES)
                   and all(_one_of(status, {"pass", "blocked", "not_evaluated"})
                           for status in gate_results.values()))
    all_pass = valid_gates and all(status == "pass" for status in gate_results.values())
    nonpassing = ({name for name, status in gate_results.items() if status != "pass"}
                  if isinstance(gate_results, dict) else set())
    blockers = evidence.get("qualification_blockers")
    if (evidence.get("schema") != "axiomos.v05.physical-results.v1"
            or evidence.get("source_id") != source
            or evidence.get("acceptance_config_sha256") != config
            or type(evidence.get("physical_acceptance")) is not bool
            or evidence["physical_acceptance"] != all_pass
            or not valid_gates
            or not isinstance(blockers, dict)
            or set(blockers) != nonpassing
            or any(not isinstance(reason, str) or not reason for reason in blockers.values())):
        raise ValueError("physical campaign identity or gate result mismatch")
    return evidence


def _validate_acceptance(value: dict) -> None:
    if not isinstance(value, dict) or value.get("schema") != "axiomos.v05.acceptance.v1":
        raise ValueError("acceptance schema mismatch")
    for section, keys in (("cpu", ("period_ns",)), ("timing", ("handoff_timeout_ns",))):
        fields = value.get(section)
        if not isinstance(fields, dict) or any(type(fields.get(key)) is not int or fields[key] <= 0 for key in keys):
            raise ValueError(f"malformed acceptance {section}")
    if not isinstance(value.get("required_gates"), dict):
        raise ValueError("malformed acceptance required_gates")
    if value.get("release_policy") != {"all_required_gates_must_pass": True,
                                       "synthetic_evidence_can_pass_release": False}:
        raise ValueError("malformed acceptance release_policy")
    for name, gate in value["required_gates"].items():
        if (not isinstance(gate, dict) or type(gate.get("required")) is not bool
                or type(gate.get("implemented_by_reducer")) is not bool
                or ("missing_policy" in gate and not _one_of(
                    gate["missing_policy"], {"blocked", "not_evaluated"}))
                or (not gate["implemented_by_reducer"] and "missing_policy" not in gate)):
            raise ValueError("malformed acceptance required_gates")
        if gate["implemented_by_reducer"] and name not in {"trace_subset", "resource_reclamation", *SOFTWARE_CASES, *PHYSICAL_GATES}:
            raise ValueError(f"unsupported reducer gate {name!r}")


def reduce_records(rows: list[dict], expectations: dict, acceptance: dict,
                   config_digest: str, reclamation: Path | None = None,
                   software: Path | None = None, physical: Path | None = None,
                   acceptance_path: Path = DEFAULT_ACCEPTANCE) -> dict:
    _validate_acceptance(acceptance)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("trace records must be objects")
    if len(rows) < 3 or rows[0].get("type") != "header" or rows[-1].get("type") != "terminal":
        raise ValueError("trace requires header, events, and terminal")
    header, terminal, events = rows[0], rows[-1], rows[1:-1]
    if set(header) != HEADER_FIELDS or header["schema"] != TRACE_SCHEMA or not _one_of(header.get("evidence_kind"), {"synthetic", "physical"}):
        raise ValueError("header schema mismatch")
    _identity(header.get("boot_id"), "boot_id")
    if not isinstance(header.get("source_id"), str) or len(header["source_id"]) != 40 or any(c not in "0123456789abcdef" for c in header["source_id"]):
        raise ValueError("source_id must be a lowercase SHA-1")
    if not isinstance(header.get("artifact_id"), str) or len(header["artifact_id"]) != 64 or any(c not in "0123456789abcdef" for c in header["artifact_id"]):
        raise ValueError("artifact_id must be a lowercase 256-bit digest")
    _identity(header.get("acceptance_config_sha256"), "acceptance_config_sha256")
    clock_hz = _integer(header, "clock_hz", positive=True)
    if header["acceptance_config_sha256"] != config_digest:
        raise ValueError("wrong acceptance config hash")
    if set(terminal) != TERMINAL_FIELDS:
        raise ValueError("terminal schema mismatch")

    previous_ticks = -1
    for expected_seq, event in enumerate(events, 1):
        kind = event.get("type")
        if not isinstance(kind, str) or kind not in FIELDS or set(event) != FIELDS[kind] | {"type"}:
            raise ValueError(f"unknown event shape {kind!r}")
        if _integer(event, "seq", positive=True) != expected_seq:
            raise ValueError(f"event seq is duplicate, missing, or reordered at {expected_seq}")
        ticks = _integer(event, "ticks")
        if ticks < previous_ticks:
            raise ValueError("event ticks decrease")
        previous_ticks = ticks
        for key in FIELDS[kind] & {"operation_id", "cycle", "generation"}:
            _integer(event, key, positive=True)
        if "scheduled_ticks" in event:
            _integer(event, "scheduled_ticks")
        if "artifact_id" in event:
            if not isinstance(event["artifact_id"], str) or len(event["artifact_id"]) != 64 or any(c not in "0123456789abcdef" for c in event["artifact_id"]):
                raise ValueError("artifact_id must be a lowercase 256-bit digest")
        if "mode" in event and not _one_of(event["mode"], {"controller", "safe"}):
            raise ValueError("invalid cycle mode")
        if kind == "operation_request" and not _one_of(event["operation"], {"activate", "rollback"}):
            raise ValueError("invalid operation")
        if kind == "operation_response" and not _one_of(event["outcome"], OUTCOMES):
            raise ValueError("invalid operation outcome")
    if _integer(terminal, "seq", positive=True) != len(events) + 1 or _integer(terminal, "event_count") != len(events) or _integer(terminal, "last_event_seq") != len(events):
        raise ValueError("terminal does not prove the complete expected event count")
    if _integer(terminal, "ticks") < previous_ticks:
        raise ValueError("terminal ticks decrease")

    if not isinstance(expectations, dict) or expectations.get("schema") != EXPECTATIONS_SCHEMA or expectations.get("acceptance_config_sha256") != config_digest:
        raise ValueError("expectations schema or config hash mismatch")
    boots = expectations.get("boots")
    if not isinstance(boots, dict):
        raise ValueError("malformed expectations boots")
    boot_expected = boots.get(header["boot_id"])
    if not isinstance(boot_expected, dict):
        raise ValueError("missing workload expectations for boot")
    if boot_expected.get("source_id") != header["source_id"] or boot_expected.get("artifact_id") != header["artifact_id"]:
        raise ValueError("expected boot identity does not match trace")
    expected_counts = boot_expected.get("event_counts")
    if not isinstance(expected_counts, dict) or any(type(value) is not int or value < 0 or value > len(events) for value in expected_counts.values()):
        raise ValueError("malformed expectations event counts")
    actual_counts = dict(sorted(Counter(event["type"] for event in events).items()))
    if actual_counts != expected_counts:
        raise ValueError("event counts do not match expectations")
    actual_outcomes = {name: 0 for name in OUTCOMES}
    requests = {}
    responses = set()
    for event in events:
        if event["type"] == "operation_request":
            if event["operation_id"] in requests:
                raise ValueError("duplicate operation request")
            requests[event["operation_id"]] = event
        elif event["type"] == "operation_response":
            if event["operation_id"] in responses or event["operation_id"] not in requests:
                raise ValueError("missing request or duplicate workload response")
            responses.add(event["operation_id"])
            actual_outcomes[event["outcome"]] += 1
    expected_outcomes = boot_expected.get("operation_outcomes")
    if not isinstance(expected_outcomes, dict) or set(expected_outcomes) != set(OUTCOMES) or any(type(value) is not int or value < 0 or value > len(events) for value in expected_outcomes.values()):
        raise ValueError("malformed expectations operation outcomes")
    if actual_outcomes != expected_outcomes:
        raise ValueError("operation outcomes do not match expectations")
    unfinished = len(set(requests) - responses)
    if unfinished:
        raise ValueError(f"missing workload response for {unfinished} operation(s)")

    releases = [event for event in events if event["type"] == "cycle_release"]
    coverage = boot_expected.get("release_cycles")
    if not isinstance(coverage, dict):
        raise ValueError("malformed expectations release coverage")
    first, count = coverage.get("first"), coverage.get("count")
    if type(first) is not int or first < 1 or type(count) is not int or count < 0 or count > len(events):
        raise ValueError("malformed expectations release coverage")
    if len(releases) != count or any(event["cycle"] != first + index for index, event in enumerate(releases)):
        raise ValueError("cycle release coverage does not match expectations")
    period_ns = acceptance["cpu"]["period_ns"]
    for earlier, later in zip(releases, releases[1:]):
        if (later["scheduled_ticks"] - earlier["scheduled_ticks"]) * 1_000_000_000 != period_ns * clock_hz:
            raise ValueError("scheduled releases are not exactly one period apart")

    cycles = {}
    for event in events:
        if event["type"] == "cycle_release":
            if event["cycle"] in cycles:
                raise ValueError(f"cycle {event['cycle']} has duplicate release")
            cycles[event["cycle"]] = [event]
        elif event["type"] in {"behavior_enter", "behavior_exit", "cycle_complete"}:
            if event["cycle"] not in cycles:
                raise ValueError(f"cycle {event['cycle']} has no release")
            cycles[event["cycle"]].append(event)
    for cycle, lifecycle in cycles.items():
        release, complete = lifecycle[0], lifecycle[-1]
        expected_lifecycle = ["cycle_release", "cycle_complete"] if release["mode"] == "safe" else ["cycle_release", "behavior_enter", "behavior_exit", "cycle_complete"]
        if [event["type"] for event in lifecycle] != expected_lifecycle:
            raise ValueError(f"cycle {cycle} lifecycle incomplete or reordered")
        if len({event["generation"] for event in lifecycle}) != 1:
            raise ValueError(f"cycle {cycle} has mixed generations")
        if complete["mode"] != release["mode"]:
            raise ValueError(f"cycle {cycle} mode mismatch")
        if release["ticks"] < release["scheduled_ticks"] or _at_or_over_ns(complete["ticks"] - release["scheduled_ticks"], period_ns, clock_hz):
            raise ValueError(f"cycle {cycle} deadline violation")
        if release["mode"] == "controller" and lifecycle[1]["artifact_id"] != lifecycle[2]["artifact_id"]:
            raise ValueError(f"cycle {cycle} artifact identity mismatch")

    by_operation = {}
    for event in events:
        if "operation_id" in event:
            if event["type"] in by_operation.setdefault(event["operation_id"], {}):
                raise ValueError(f"duplicate {event['type']} for operation {event['operation_id']}")
            by_operation.setdefault(event["operation_id"], {})[event["type"]] = event
    handoff = 0
    commits_by_cycle = {}
    # ponytail: per-operation scans suit bounded host fixtures; index by identity
    # and readiness tick before admitting soak-scale traces.
    for operation_id, grouped in by_operation.items():
        request, response = grouped.get("operation_request"), grouped.get("operation_response")
        if request is None:
            raise ValueError(f"operation {operation_id} stage has no request")
        if response is None:
            raise ValueError(f"operation {operation_id} missing workload response")
        stages = ("operation_accepted", "handoff_enter", "sink_safe_ready", "operation_committed")
        if response["outcome"] in {"failed", "rejected", "canceled"}:
            if "operation_committed" in grouped:
                raise ValueError(f"unsuccessful operation {operation_id} committed")
            intermediate = [name for name in ("operation_accepted", "handoff_enter", "sink_safe_ready") if name in grouped]
            if intermediate != list(("operation_accepted", "handoff_enter", "sink_safe_ready")[:len(intermediate)]):
                raise ValueError(f"unsuccessful operation {operation_id} has invalid stage prefix")
            prior = request
            for name in intermediate:
                stage = grouped[name]
                if prior["seq"] >= stage["seq"] or stage["seq"] >= response["seq"] or (stage["generation"], stage["artifact_id"]) != (request["generation"], request["artifact_id"]):
                    raise ValueError(f"unsuccessful operation {operation_id} has invalid stage prefix")
                prior = stage
            if any(event["type"] == "behavior_enter" and event["seq"] > request["seq"] and
                   (event["generation"], event["artifact_id"]) == (request["generation"], request["artifact_id"])
                   for event in events):
                raise ValueError(f"unsuccessful operation {operation_id} candidate entered")
            continue
        if request["operation"] in {"activate", "rollback"}:
            if any(stage not in grouped for stage in stages):
                raise ValueError(f"operation {operation_id} missing handoff stage")
            ordered = [request, *(grouped[stage] for stage in stages), response]
            if any(a["seq"] >= b["seq"] for a, b in zip(ordered, ordered[1:])):
                raise ValueError(f"operation {operation_id} handoff stages reordered")
            identity = (request["generation"], request["artifact_id"])
            if any((grouped[stage]["generation"], grouped[stage]["artifact_id"]) != identity for stage in stages):
                raise ValueError(f"operation {operation_id} handoff identity mismatch")
            commit = grouped["operation_committed"]
            if _over_ns(commit["ticks"] - grouped["handoff_enter"]["ticks"], acceptance["timing"]["handoff_timeout_ns"], clock_hz):
                raise ValueError(f"operation {operation_id} handoff timeout")
            ready = grouped["sink_safe_ready"]
            eligible = next((release for release in releases if release["scheduled_ticks"] > ready["ticks"] or
                             release["scheduled_ticks"] == ready["ticks"] and release["seq"] > ready["seq"]), None)
            if eligible is None or commit["cycle"] != eligible["cycle"] or not (eligible["seq"] < commit["seq"]):
                raise ValueError(f"operation {operation_id} did not commit at next eligible release")
            first_use = next((event for event in cycles.get(commit["cycle"], ()) if event["type"] == "behavior_enter"), None)
            if first_use is None or (first_use["generation"], first_use["artifact_id"]) != identity or not (commit["seq"] < first_use["seq"] < response["seq"]):
                raise ValueError(f"operation {operation_id} committed generation identity mismatch")
            if commit["cycle"] in commits_by_cycle:
                raise ValueError(f"cycle {commit['cycle']} has multiple commits")
            commits_by_cycle[commit["cycle"]] = identity
            handoff += 1

    active = None
    seen_generations = set()
    for release in releases:
        cycle = release["cycle"]
        if cycle in commits_by_cycle:
            proposed = commits_by_cycle[cycle]
            if proposed[0] in seen_generations:
                raise ValueError("successful commit reused an installation generation")
            active = proposed
            seen_generations.add(proposed[0])
        lifecycle = cycles[cycle]
        if active is None:
            artifact = header["artifact_id"] if release["mode"] == "safe" else lifecycle[1]["artifact_id"]
            if artifact != header["artifact_id"]:
                raise ValueError("initial installation does not match header artifact")
            active = (release["generation"], artifact)
            seen_generations.add(release["generation"])
        observed = (release["generation"], active[1] if release["mode"] == "safe" else lifecycle[1]["artifact_id"])
        if observed != active:
            raise ValueError("installation changed without a successful commit")

    failures = sum(actual_outcomes[name] for name in OUTCOMES if name != "successful")
    resource_evidence = None if reclamation is None else validate_reclamation(reclamation, header["source_id"], config_digest, acceptance)
    software_evidence = None if software is None else validate_software(software, header["source_id"], config_digest)
    physical_evidence = None if physical is None else validate_physical(
        physical, header["source_id"], config_digest, acceptance_path)
    evaluated = {"trace_subset": True, "resource_reclamation": resource_evidence is not None,
                 **{name: software_evidence is not None for name in SOFTWARE_CASES},
                 **{name: physical_evidence is not None for name in PHYSICAL_GATES}}
    gate_results = {
        name: (gate["missing_policy"] if not gate["implemented_by_reducer"]
               else physical_evidence["gate_results"][name]
               if physical_evidence is not None and name in PHYSICAL_GATES
               else "pass" if evaluated[name]
               else gate.get("missing_policy", "not_evaluated"))
        for name, gate in acceptance["required_gates"].items()
    }
    blockers = [name for name, gate in acceptance["required_gates"].items()
                if gate["required"] and gate_results[name] != "pass"]
    return {
        "reclamation_evidence": resource_evidence,
        "software_evidence": software_evidence,
        "physical_evidence": physical_evidence,
        "schema": "axiomos.v05.results.v1",
        "trace_verdict": "pass",
        "release_verdict": "pass" if not blockers else "blocked",
        "gate_results": gate_results,
        "release_blockers": blockers,
        "boots": [{"boot_id": header["boot_id"], "evidence_kind": header["evidence_kind"], "source_id": header["source_id"],
                   "artifact_id": header["artifact_id"], "acceptance_config_sha256": header["acceptance_config_sha256"], "event_counts": actual_counts,
                   "operation_outcomes": actual_outcomes, "failures": failures, "unfinished_operations": unfinished,
                   "release_count": len(releases), "handoff_samples": handoff}],
    }


def describe():
    return {"trace_schema": TRACE_SCHEMA, "expectations_schema": EXPECTATIONS_SCHEMA,
            "header_fields": sorted(HEADER_FIELDS), "event_fields": {key: sorted(value | {"type"}) for key, value in sorted(FIELDS.items())},
            "terminal_fields": sorted(TERMINAL_FIELDS), "implemented_checks": ["JSON and exact record shapes", "expected SHA identity/config binding", "sequence and tick order", "independent bounded exact counts/outcomes/release coverage", "controller/safe cycle lifecycle, generation, schedule, and deadline", "handoff-enter to next eligible release/commit timeout and first-use identity"],
            "unsupported_events": ["policy request", "enqueue", "sink acknowledgment"],
            "unsupported_operations": ["retire", "deactivate", "administrative lifecycle operations"],
            "expectations_shape": {"schema": EXPECTATIONS_SCHEMA, "acceptance_config_sha256": "lowercase SHA-256", "boots": {"<boot_id>": {"source_id": "lowercase SHA-1", "artifact_id": "lowercase canonical artifact digest (managed bundles use SHA3-256)", "event_counts": "exact nonnegative integer counts by event type", "operation_outcomes": "exact successful/failed/rejected/canceled integer counts", "release_cycles": {"first": "positive integer", "count": "bounded nonnegative integer"}}}},
            "operation_generation_semantics": "requested candidate installation generation; installed only after successful commit and matching first behavior entry",
            "gate_scope": "host trace, fixed software/reclamation tests, and optional retained physical campaign",
            "reclamation_cases": RECLAMATION_CASES,
            "software_cases": SOFTWARE_CASES,
            "physical_gates": list(PHYSICAL_GATES),
            "release_pass_supported": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, default=DEFAULT_ACCEPTANCE)
    parser.add_argument("--expectations", type=Path)
    parser.add_argument("--reclamation", type=Path, help="retained fixed host reclamation suite evidence")
    parser.add_argument("--software", type=Path, help="retained fixed host software-property suite evidence")
    parser.add_argument("--physical-campaign", type=Path, help="retained physical campaign manifest")
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--show-acceptance", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("trace", nargs="?", type=Path)
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(describe(), sort_keys=True, indent=2)); return 0
    if args.show_acceptance:
        print(json.dumps(load_json(args.acceptance), sort_keys=True, indent=2)); return 0
    if args.self_test:
        import unittest
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/scripts"), pattern="test_v05_reducer.py")
        result = unittest.TextTestRunner(stream=sys.stderr).run(suite)
        print(json.dumps({"schema": "axiomos.v05.self-test.v1", "successful": result.wasSuccessful(), "tests_run": result.testsRun}, sort_keys=True))
        return int(not result.wasSuccessful())
    if not args.trace or not args.expectations:
        parser.error("trace and --expectations are required")
    try:
        acceptance = load_json(args.acceptance)
        result = reduce_records(parse_jsonl(args.trace.read_text(encoding="utf-8")),
                                load_json(args.expectations), acceptance,
                                file_sha256(args.acceptance), args.reclamation,
                                args.software, args.physical_campaign,
                                args.acceptance)
        result["input_sha256"] = {"trace": file_sha256(args.trace), "expectations": file_sha256(args.expectations)}
    except (OSError, UnicodeError, ValueError) as error:
        print(json.dumps({"schema": "axiomos.v05.results.v1", "trace_verdict": "fail", "release_verdict": "blocked", "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
