import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "v05_physical_reducer", ROOT / "scripts/benchmark/v05-physical-reducer.py")
physical = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(physical)
VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "verifier_cost", ROOT / "scripts/benchmark/verifier-cost.py")
verifier_cost = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(verifier_cost)
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
            "uploads": {
                "resident": 1,
                "rejected_by_errno": {"1": 1, "2": 1, "44": 1},
                "outcomes": {
                    "1": {"phase": 4, "errno": 0, "artifact_handle": 7,
                          "bundle_digest": hashlib.sha3_256(b"controller_b").hexdigest()},
                    "2": {"phase": 5, "errno": 2, "artifact_handle": None,
                          "bundle_digest": None},
                    "3": {"phase": 5, "errno": 44, "artifact_handle": None,
                          "bundle_digest": hashlib.sha3_256(b"verifier_rejection").hexdigest()},
                    "4": {"phase": 5, "errno": 1, "artifact_handle": None,
                          "bundle_digest": None},
                },
            },
            "rearm_quiescence": [{}] * 21, "stops": {"1:0:0": 20},
            "cycle_failures": 5}


def analyzer_report(source="sigrok", run=None):
    header, footer = [json.loads(line) for line in
                      (run / "manifest.jsonl").read_text().splitlines()]
    return {"evidence_source": source, "samples": footer["samples"],
            "sample_rate_hz": header["config"]["sample_rate_hz"],
            "capture_started_ns": header["started_ns"],
            "capture_ended_ns": footer["ended_ns"], "v05_timing": {
        "paired_overhead_p99_ppm": 40_000, "paired_overhead_max_ppm": 60_000,
        "overhead_p99_samples": 20, "overhead_max_samples": 30,
        "release_p99_samples": 900, "release_max_samples": 950,
        "baseline_p99_samples": 880, "baseline_max_samples": 920,
        "releases": header["config"]["release_count"]}}


def calibration_log():
    lines = ["=== Verifier Cost Bench ==="]
    program = 1
    for shape, sizes in physical.CALIBRATION_SHAPES.items():
        for size in sizes:
            wcet = size * 20
            lines += [
                f"AXIOM VERIFIER COST prog_id={program} insns={size} states={size - 1} cycles=1 wcet={wcet}",
                f"{shape} n={size} prog_id={program}",
                *[f"AXIOM EXEC COST prog_id={program} insns={size} runs=64 cycles={size} clock_hz=54000000 wcet={wcet} modeled_ns={wcet * 6}"
                  for _ in range(5)],
            ]
            program += 1
    lines += ["AXIOM ADMISSION printk-ban rc=-1 PASS",
              "AXIOM ADMISSION control rc=0 PASS",
              "=== Verifier Cost Bench Done ==="]
    return ("\n".join(lines) + "\n").encode()


def campaign(root):
    provenance = {}
    for name in physical.PROVENANCE:
        if name in {"kernel", "rebuild_kernel"}:
            data = b"kernel\n"
        elif name == "source_features":
            data = json.dumps({"schema": "axiomos.v05.source-features.v1",
                               "source_id": "b" * 40,
                               "features": ["embedded-rpi5",
                                            "managed-runtime-bench-markers",
                                            "verifier-cost"]}).encode()
        else:
            data = name.encode() + b"\n"
        provenance[name] = file_ref(root, f"provenance/{name}", data)
    bundles = {name: file_ref(root, f"bundles/{name}.bundle", name.encode())
               for name in ("controller_a", "controller_b", "private_state")}
    calibration = file_ref(root, "calibration.log", calibration_log())
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
        audit = file_ref(root, f"{boot}/audit.jsonl", f"{boot} audit fixture\n".encode())
        runs = []
        for index in range(20):
            relative = f"{boot}/run-{index + 1}"
            run = root / relative
            run.mkdir()
            header = {"type": "header", "format": 1, "source": "sigrok",
                      "fixture_run": relative, "started_ns": start_ns,
                      "config": {"sample_rate_hz": 24_000_000,
                                 "release_count": releases}}
            footer = {"type": "end", "complete": True,
                      "ended_ns": start_ns + 2_000_000 + releases * 10_000_000,
                      "samples": releases * 240_000 + 48_000}
            (run / "manifest.jsonl").write_text(
                json.dumps(header) + "\n" + json.dumps(footer) + "\n")
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
    errors = {"valid_post_boot": 0, "invalid_signature": 2,
              "verifier_rejection": 44, "over_budget": 1}
    trial_bundles = {
        "valid_post_boot": bundles["controller_b"],
        **{case: file_ref(root, f"bundles/{case}.bundle", case.encode())
           for case in ("invalid_signature", "verifier_rejection", "over_budget")},
    }
    loads = [{"boot_id": "boot-1", "case": case, "operation_id": index,
              "errno": errors[case], "bundle": trial_bundles[case]}
             for index, case in enumerate(
                 ("valid_post_boot", "invalid_signature", "verifier_rejection", "over_budget"), 1)]
    value = {"schema": "axiomos.v05.physical-campaign.v1",
             "acceptance_config_sha256": physical.sha256(ACCEPTANCE),
             "source_id": "b" * 40, "motors_connected": False,
             "provenance": provenance, "bundles": bundles,
             "calibration": calibration, "boots": boots,
             "endurance": {"pilot": {"start": boots[0]["status_start"],
                                       "end": boots[0]["status_end"],
                                       "run": boots[0]["shrike_runs"][0]["path"]},
                           "soak": {"start": boots[1]["status_start"],
                                    "end": boots[1]["status_end"],
                                    "run": boots[1]["shrike_runs"][0]["path"]}},
             "load_trials": loads, "fault_trials": faults}
    path = root / "campaign.json"
    path.write_text(json.dumps(value) + "\n")
    return path


class PhysicalReducerTests(unittest.TestCase):
    def test_verifier_cost_parser_accepts_old_and_attributed_exec_markers(self):
        _, rows, _ = verifier_cost.parse([
            "AXIOM EXEC COST prog_id=1 insns=100 runs=64 cycles=20",
            "AXIOM EXEC COST prog_id=2 insns=100 runs=64 cycles=21 clock_hz=54000000 wcet=2000 modeled_ns=12000",
        ])
        self.assertEqual(rows[0]["clock_hz"], 0)
        self.assertEqual(rows[1]["modeled_ns"], 12000)

    def test_complete_manifest_cannot_prove_fault_injection_or_physical_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = campaign(root)
            with mock.patch.dict(physical.AUDIT, {"stitch": lambda paths, acceptance: audit_report()}), \
                 mock.patch.dict(physical.SHRIKE, {"replay": lambda path: analyzer_report(run=path)}):
                result = physical.reduce(path, ACCEPTANCE)
            self.assertFalse(result["physical_acceptance"])
            self.assertEqual(result["totals"]["boots"], 3)
            self.assertGreaterEqual(result["totals"]["releases"], 1_000_000)
            self.assertEqual(result["gate_results"]["fault_matrix"], "not_evaluated")
            self.assertEqual(result["gate_results"]["physical_campaign"], "blocked")
            self.assertIn("fault_matrix", result["qualification_blockers"])

    def test_audit_reuse_and_fault_boot_mismatch_reject(self):
        for damage in ("audit_path", "audit_copy", "fault_boot", "run_copy"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); path = campaign(root)
                value = json.loads(path.read_text())
                if damage == "audit_path":
                    value["boots"][1]["audit_exports"] = value["boots"][0]["audit_exports"]
                elif damage == "audit_copy":
                    original = root / value["boots"][0]["audit_exports"][0]["path"]
                    value["boots"][1]["audit_exports"] = [file_ref(
                        root, "boot-2/copied.jsonl", original.read_bytes())]
                elif damage == "run_copy":
                    original = root / value["boots"][0]["shrike_runs"][0]["path"] / "manifest.jsonl"
                    item = value["boots"][1]["shrike_runs"][0]
                    copied = root / item["path"] / "manifest.jsonl"
                    copied.write_bytes(original.read_bytes())
                    item["manifest_sha256"] = physical.sha256(copied)
                else:
                    value["fault_trials"][0]["boot_id"] = "boot-2"
                path.write_text(json.dumps(value))
                with mock.patch.dict(physical.AUDIT, {"stitch": lambda paths, acceptance: audit_report()}), \
                     mock.patch.dict(physical.SHRIKE, {"replay": lambda run: analyzer_report(run=run)}), \
                     self.assertRaisesRegex(ValueError, "reused|another boot"):
                    physical.reduce(path, ACCEPTANCE)

    def test_endurance_requires_one_same_boot_continuous_capture(self):
        for damage in ("missing", "unknown", "wrong_boot", "short", "late_start",
                       "early_end", "few_releases", "unlisted_boot"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); path = campaign(root)
                value = json.loads(path.read_text())
                soak = value["endurance"]["soak"]
                if damage == "missing": del soak["run"]
                if damage == "unknown": soak["run"] = "absent/run"
                if damage == "wrong_boot": soak["run"] = value["boots"][0]["shrike_runs"][0]["path"]
                if damage == "unlisted_boot":
                    for key in ("start", "end"):
                        sample = json.loads((root / soak[key]["path"]).read_text())
                        sample["boot_id"] = "unknown-boot"
                        soak[key] = file_ref(root, f"unknown-{key}.json", json.dumps(sample).encode())
                path.write_text(json.dumps(value))
                def replay(run):
                    report = analyzer_report(run=run)
                    if str(run.relative_to(root)) == soak.get("run"):
                        if damage == "short": report["samples"] = 24_000_000
                        if damage == "late_start": report["capture_started_ns"] += 1
                        if damage == "early_end": report["capture_ended_ns"] -= 1
                        if damage == "few_releases": report["v05_timing"]["releases"] = 10
                    return report
                with mock.patch.dict(physical.AUDIT, {"stitch": lambda paths, acceptance: audit_report()}), \
                     mock.patch.dict(physical.SHRIKE, {"replay": replay}), \
                     self.assertRaisesRegex(ValueError, "soak|endurance"):
                    physical.reduce(path, ACCEPTANCE)

    def test_tampering_and_nonphysical_analyzer_input_cannot_pass(self):
        for damage in ("file", "source", "calibration", "calibration_extra",
                       "load_operation", "load_bundle"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); path = campaign(root)
                if damage == "file": (root / "provenance/toolchain").write_text("changed\n")
                if damage == "calibration":
                    value = json.loads(path.read_text())
                    retained = root / value["calibration"]["path"]
                    retained.write_text(retained.read_text().replace(
                        "cycles=100 clock_hz=54000000", "cycles=999999999 clock_hz=54000000", 1))
                    value["calibration"]["sha256"] = physical.sha256(retained)
                    path.write_text(json.dumps(value) + "\n")
                if damage == "calibration_extra":
                    value = json.loads(path.read_text())
                    retained = root / value["calibration"]["path"]
                    retained.write_text(retained.read_text().replace(
                        "=== Verifier Cost Bench Done ===",
                        "ringbuf n=100 prog_id=99\n=== Verifier Cost Bench Done ==="))
                    value["calibration"]["sha256"] = physical.sha256(retained)
                    path.write_text(json.dumps(value) + "\n")
                if damage == "load_operation":
                    value = json.loads(path.read_text())
                    value["load_trials"][0]["operation_id"] = 999
                    path.write_text(json.dumps(value) + "\n")
                if damage == "load_bundle":
                    value = json.loads(path.read_text())
                    trial = value["load_trials"][2]
                    retained = root / trial["bundle"]["path"]
                    retained.write_bytes(b"another verifier candidate")
                    trial["bundle"]["sha256"] = physical.sha256(retained)
                    path.write_text(json.dumps(value) + "\n")
                source = "synthetic-or-import" if damage == "source" else "sigrok"
                with mock.patch.dict(physical.AUDIT, {"stitch": lambda paths, acceptance: audit_report()}), \
                     mock.patch.dict(physical.SHRIKE, {"replay": lambda path: analyzer_report(source, path)}), \
                     self.assertRaises(ValueError):
                    physical.reduce(path, ACCEPTANCE)


if __name__ == "__main__":
    unittest.main()
