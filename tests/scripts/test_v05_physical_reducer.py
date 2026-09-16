import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "v05_physical_reducer", ROOT / "scripts/benchmark/v05-physical-reducer.py")
physical = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(physical)
ACCEPTANCE = ROOT / "docs/performance/v0.5-acceptance.json"


def file_ref(root, relative, data=b"evidence\n"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": relative, "sha256": physical.sha256(path)}


def status(root, boot, name, host, releases):
    timer = {"releases_serviced": releases, "releases_missed": 0,
             "releases_late": 0, "max_wake_lateness_ticks": 0,
             "completion_misses": 0, "safe_releases": 0,
             "last_release_sequence": releases,
             "last_scheduled_ticks": releases * 10_000_000,
             "last_actual_ticks": releases * 10_000_000, "timer_fault": 0}
    value = {"schema": "axiomos.v05.status-sample.v1", "boot_id": boot,
             "host_started_ns": host, "host_ended_ns": host + 1_000_000,
             "status": {"type": "header", "format": "axiomos-managed-audit",
                        "version": 2, "clock_frequency": 1_000_000_000,
                        "session": 0, "session_established": False,
                        "persistent_boot_identity": False, "oldest": 0, "end": 0,
                        "overwritten": 0, "dropped": 0, "suppressed": 0,
                        "flags": 1, "capacity": 2048, "record_bytes": 96,
                        "latest_stop": None, "payloads_decoded": False,
                        "timer": timer}}
    return file_ref(root, name, (json.dumps(value) + "\n").encode())


def audit_report():
    return {"successful_transitions": {"activate": 2000, "rollback": 2000},
            "confirmed_handoffs": 4000, "transition_phase_bins": [400] * 10,
            "missed_releases": 0, "completion_misses": 0,
            "uploads": {"resident": 1, "rejected_by_errno": {"22": 1}},
            "rearm_quiescence": [{}] * 21, "stops": {"1:0:0": 20},
            "cycle_failures": 5}


def analyzer_report(source="sigrok"):
    return {"evidence_source": source, "v05_timing": {
        "paired_overhead_p99_ppm": 40_000, "paired_overhead_max_ppm": 60_000,
        "overhead_p99_samples": 20, "overhead_max_samples": 30,
        "release_p99_samples": 900, "release_max_samples": 950,
        "baseline_p99_samples": 880, "baseline_max_samples": 920,
        "releases": 10}}


def campaign(root):
    provenance = {}
    for name in physical.PROVENANCE:
        if name in {"kernel", "rebuild_kernel"}:
            data = b"kernel\n"
        elif name == "source_features":
            data = json.dumps({"schema": "axiomos.v05.source-features.v1",
                               "source_id": "b" * 40,
                               "features": ["embedded-rpi5",
                                            "managed-runtime-bench-markers"]}).encode()
        else:
            data = name.encode() + b"\n"
        provenance[name] = file_ref(root, f"provenance/{name}", data)
    bundles = {name: file_ref(root, f"bundles/{name}.bundle", name.encode())
               for name in ("controller_a", "controller_b", "private_state")}
    uploaded = bundles["controller_b"]["sha256"]
    boot_specs = [("boot-1", 1_000_000_000, 400_000),
                  ("boot-2", 5_000_000_000_000, 8_640_000),
                  ("boot-3", 92_000_000_000_000, 400_000)]
    boots, all_runs = [], []
    for boot, start_ns, releases in boot_specs:
        start = status(root, boot, f"{boot}/start.json", start_ns, 0)
        end = status(root, boot, f"{boot}/end.json",
                     start_ns + 1_000_000 + releases * 10_000_000, releases)
        log = file_ref(root, f"{boot}/boot.log", b"INIT_PROCESS_STARTED pid=1\nPI5_BOOT_OK\n")
        inventory_value = {"schema": "axiomos.v05.boot-inventory.v1", "boot_id": boot,
                           "artifact_sha256": ["a" * 64]}
        assert uploaded not in inventory_value["artifact_sha256"]
        inventory = file_ref(root, f"{boot}/inventory.json",
                             (json.dumps(inventory_value) + "\n").encode())
        audit = file_ref(root, f"{boot}/audit.jsonl")
        runs = []
        for index in range(20):
            relative = f"{boot}/run-{index + 1}"
            run = root / relative
            run.mkdir()
            (run / "manifest.jsonl").write_text("physical fixture\n")
            item = {"path": relative, "manifest_sha256": physical.sha256(run / "manifest.jsonl")}
            runs.append(item); all_runs.append((boot, relative))
        boots.append({"boot_id": boot, "boot_log": log, "boot_inventory": inventory,
                      "audit_exports": [audit], "status_start": start,
                      "status_end": end, "shrike_runs": runs})
    faults = []
    for index, (fault, phase, repeat) in enumerate(
            (f, p, r) for f in ("stop", "link_loss", "mcu_reset", "ack_failure")
            for p in ("preparation", "handoff", "committed") for r in range(1, 6)):
        boot, run = all_runs[index]
        faults.append({"boot_id": boot, "fault": fault, "phase": phase,
                       "repeat": repeat, "run": run})
    loads = [{"boot_id": "boot-1", "case": case, "errno": 0 if case == "valid_post_boot" else 22}
             for case in ("valid_post_boot", "invalid_signature", "verifier_rejection", "over_budget")]
    value = {"schema": "axiomos.v05.physical-campaign.v1",
             "acceptance_config_sha256": physical.sha256(ACCEPTANCE),
             "source_id": "b" * 40, "motors_connected": False,
             "provenance": provenance, "bundles": bundles, "boots": boots,
             "endurance": {"pilot": {"start": boots[0]["status_start"],
                                       "end": boots[0]["status_end"]},
                           "soak": {"start": boots[1]["status_start"],
                                    "end": boots[1]["status_end"]}},
             "load_trials": loads, "fault_trials": faults}
    path = root / "campaign.json"
    path.write_text(json.dumps(value) + "\n")
    return path


class PhysicalReducerTests(unittest.TestCase):
    def test_complete_raw_campaign_is_required_before_physical_gates_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = campaign(root)
            with mock.patch.dict(physical.AUDIT, {"stitch": lambda paths, acceptance: audit_report()}), \
                 mock.patch.dict(physical.SHRIKE, {"replay": lambda path: analyzer_report()}):
                result = physical.reduce(path, ACCEPTANCE)
            self.assertTrue(result["physical_acceptance"])
            self.assertEqual(result["totals"]["boots"], 3)
            self.assertGreaterEqual(result["totals"]["releases"], 1_000_000)
            self.assertEqual(set(result["gate_results"].values()), {"pass"})

    def test_tampering_and_nonphysical_analyzer_input_cannot_pass(self):
        for damage in ("file", "source"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); path = campaign(root)
                if damage == "file": (root / "provenance/toolchain").write_text("changed\n")
                report = analyzer_report("synthetic-or-import" if damage == "source" else "sigrok")
                with mock.patch.dict(physical.AUDIT, {"stitch": lambda paths, acceptance: audit_report()}), \
                     mock.patch.dict(physical.SHRIKE, {"replay": lambda path: report}), \
                     self.assertRaises(ValueError):
                    physical.reduce(path, ACCEPTANCE)


if __name__ == "__main__":
    unittest.main()
