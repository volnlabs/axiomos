#!/usr/bin/env python3
"""Host tests for the retained ForgeFPGA evidence verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify/fpga-build-evidence.py"
BUILDS = ["final-nominal", *(f"final-guard-{index}" for index in range(5))]
CORNERS = [
    "tt1p1v25c_Typical",
    "ss0p99v85c_RCworst",
    "ss0p99vn40c_RCworst",
    "ff1p21v85c_RCbest",
    "ff1p21vn40c_RCbest",
]
FUNCTIONS = {
    "clk": "OSC_CLK",
    "clk_en": "OSC_EN",
    "spi_sck": "GPIO3_IN [PIN 16]",
    "spi_ss_n": "GPIO4_IN [PIN 17]",
    "spi_mosi": "GPIO5_IN [PIN 18]",
    "spi_miso": "GPIO6_OUT [PIN 19]",
    "spi_miso_en": "GPIO6_OE [PIN 19]",
    "rst_n": "GPIO18_IN [PIN 9]",
    "estop_n": "GPIO7_IN [PIN 20]",
    "left_pwm_out": "GPIO8_OUT [PIN 23]",
    "left_pwm_out_en": "GPIO8_OE [PIN 23]",
    "right_pwm_out": "GPIO9_OUT [PIN 24]",
    "right_pwm_out_en": "GPIO9_OE [PIN 24]",
    "left_direction_out": "GPIO10_OUT [PIN 1]",
    "left_direction_out_en": "GPIO10_OE [PIN 1]",
    "right_direction_out": "GPIO11_OUT [PIN 2]",
    "right_direction_out_en": "GPIO11_OE [PIN 2]",
}


def write(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


def project_xml(corner: int, constraint: str, pin_ids: dict[str, str]) -> str:
    records = "".join(
        f'<record id="{resource}"><port-name>{signal}</port-name></record>'
        for signal, resource in pin_ids.items()
    )
    return (
        "<project><synthesize><useABC9>false</useABC9>"
        "<enableHardMultiplexerResources>false</enableHardMultiplexerResources>"
        "</synthesize><nvmData>fixture</nvmData><virtualProperties/>"
        "<pllConfigurator/><generateBitstream><option>same</option>"
        f"<timingAnalysisCorner>{corner}</timingAnalysisCorner></generateBitstream>"
        f'<timing-constraints><module filename="{constraint}"/></timing-constraints>'
        f"<io-spec-tool><records>{records}</records></io-spec-tool></project>"
    )


def pin_fixture() -> tuple[dict[str, str], str]:
    ids = {"clk": "CLK_t[0:0]_W_in0", "clk_en": "CLK_t[0:0]_W_out0"}
    lines = [
        "EFLX_CLK chip_tile_x=0, chip_tile_y=0, clk_side=W",
        "Input=0, pin=clk",
        "Output=0, pin=clk_en",
    ]
    for index, signal in enumerate(list(FUNCTIONS)[2:]):
        direction = "Input" if "_IN " in FUNCTIONS[signal] else "Output"
        suffix = "in" if direction == "Input" else "out"
        ids[signal] = f"IOB_t[0:0]_xy[0:{index}]_{suffix}0"
        lines.extend([
            f"EFLX_IOB chip_tile_x=0, chip_tile_y=0, chip_x=0, chip_y={index}",
            f"{direction}=0, pin={signal}",
        ])
    return ids, "\n".join(lines) + "\n"


def refresh_manifest(evidence: Path) -> None:
    rows = []
    for path in sorted(p for p in evidence.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(evidence).as_posix()}\n")
    write(evidence / "SHA256SUMS", "".join(rows))


def make_fixture(root: Path) -> tuple[Path, dict[str, object]]:
    canonical = root / "firmware/shrike/fpga/forgefpga"
    evidence = root / "evidence"
    pin_ids, pin_log = pin_fixture()
    write(canonical / "axiomos_r04.ffpga", project_xml(0, "clk_50mhz.sdc", pin_ids))
    sources = {"top.v": "module source; endmodule\n", "gate.v": "module gate; endmodule\n"}
    constraints = {"clk_50mhz.sdc": "create_clock -period 20 clk\n", "clk_18ns_guard.sdc": "create_clock -period 18 clk\n"}
    for name, text in sources.items():
        write(canonical / "ffpga/src" / name, text)
    for name, text in constraints.items():
        write(canonical / "ffpga/timing-constraints" / name, text)

    bitstream = b"x" * 46408
    bitstream_hash = hashlib.sha256(bitstream).hexdigest()
    builds = []
    for index, name in enumerate(BUILDS):
        corner_index = 0 if index == 0 else index - 1
        period = 20000 if index == 0 else 18000
        constraint = "clk_50mhz.sdc" if index == 0 else "clk_18ns_guard.sdc"
        directory = evidence / name
        build = directory / "ffpga/build"
        write(directory / "timing.ffpga", project_xml(corner_index, constraint, pin_ids))
        write(evidence / f"{name}-console.log", f"[2026-09-12 15:35:13.305] [Tcl] [info] Evaluation of /fixture/{name}.tcl successfully completed\n")
        write(build / "synth_script.ys", "synth_xilinx -nobram -noiopad -nodsp\nsetattr -mod -unset keep_hierarchy; setattr -unset keep_hierarchy; flatten -noscopeinfo\n")
        write(build / "post_synth_results.v", "module top;\nwire history_enable_LUT4_O;\nLUT3 #(\n.INIT(8'h80)\n) cell (\n.I0(in),\n.O(\\receive_gate.active )\n  );\nendmodule\n")
        write(build / "PNR_TIMING.log", f" <DEFAULT> 1 1 100 0 0\n clk clk <DEFAULT> {period} (0,1) 16000 62.5\n")
        write(build / "PNR_PLACER_TIMING.log", f"PLACER-ESTIMATED-TIMING TSMC 40nm ULP {CORNERS[corner_index]}\n")
        write(build / "PNR_IO.log", pin_log)
        write(build / "resource-utilization-report.log", "CLBs: 7/140\n")
        write(build / "bitstream/FPGA_bitstream_MCU.bin", bitstream)
        for source, text in sources.items():
            write(directory / "ffpga/src" / source, text)
        for constraint_name, text in constraints.items():
            write(directory / "ffpga/timing-constraints" / constraint_name, text)
        builds.append({
            "build": name,
            "corner": CORNERS[corner_index],
            "period_ps": period,
            "setup_wns_ps": 100,
            "setup_tns_ps": 0,
            "failing_endpoints": 0,
            "achievable_frequency_mhz": 62.5,
            "logic_clbs": 7,
            "setup_pass": True,
            "pin_assignments_match": True,
            "source_and_sdc_match": True,
            "compiler_stdout_retained": False,
            "mcu_sha256": bitstream_hash,
            "final_hold": "not exported",
            "pulse_width": "not exported",
        })
    write(evidence / "final-io-planner.csv", "PORT;FUNCTION\n" + "".join(
        f"{signal};{function}\n" for signal, function in FUNCTIONS.items()
    ))
    results = {
        "builds": builds,
        "io_planner_match": True,
        "all_corner_setup_pass": True,
        "physical_qualification": "pending",
        "runtime_enabled": False,
        "programmed": False,
    }
    write(evidence / "results.json", json.dumps(results))
    refresh_manifest(evidence)
    return evidence, results


class FpgaBuildEvidenceTests(unittest.TestCase):
    def run_verifier(self, root: Path, evidence: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        result = subprocess.run(
            ["python3", str(SCRIPT), "--root", str(root), "--evidence-dir", str(evidence)],
            text=True,
            capture_output=True,
        )
        return result, json.loads(result.stdout)

    def test_valid_fixture_matches_retained_results_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, expected = make_fixture(root)
            before = {path.relative_to(evidence): path.read_bytes() for path in evidence.rglob("*") if path.is_file()}
            result, report = self.run_verifier(root, evidence)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["results"], expected)
            self.assertEqual(report["manifest_entries"], len(before) - 1)
            self.assertEqual(before, {path.relative_to(evidence): path.read_bytes() for path in evidence.rglob("*") if path.is_file()})

    def test_corrupt_report_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, _ = make_fixture(root)
            write(evidence / "final-guard-2/ffpga/build/PNR_TIMING.log", "truncated\n")
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "malformed_report")

    def test_missing_report_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, _ = make_fixture(root)
            (evidence / "final-guard-2/ffpga/build/PNR_TIMING.log").unlink()
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "missing_file")

    def test_manifest_rejects_hash_damage_and_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, _ = make_fixture(root)
            manifest = evidence / "SHA256SUMS"
            original = manifest.read_text(encoding="utf-8")
            manifest.write_text("0" * 64 + original[64:], encoding="utf-8")
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "checksum_mismatch")
            manifest.write_text(original + "0" * 64 + "  ../escape\n", encoding="utf-8")
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "unsafe_manifest_path")

    def test_retained_result_identity_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, expected = make_fixture(root)
            expected["builds"][0]["setup_wns_ps"] = 101
            write(evidence / "results.json", json.dumps(expected))
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "result_mismatch")

    def test_evidence_mismatch_classes_fail_closed(self) -> None:
        cases = [
            ("source_sdc_mismatch", "final-nominal/ffpga/src/top.v", lambda text: text + "// drift\n"),
            ("config_mismatch", "final-nominal/timing.ffpga", lambda text: text.replace("<useABC9>false", "<useABC9>true")),
            ("pin_mismatch", "final-nominal/ffpga/build/PNR_IO.log", lambda text: text.replace("pin=clk\n", "pin=wrong\n")),
            ("corner_mismatch", "final-nominal/ffpga/build/PNR_PLACER_TIMING.log", lambda text: text.replace(CORNERS[0], CORNERS[1])),
            ("period_mismatch", "final-nominal/ffpga/build/PNR_TIMING.log", lambda text: text.replace(" 20000 ", " 18000 ")),
            ("setup_failed", "final-nominal/ffpga/build/PNR_TIMING.log", lambda text: text.replace(" 1 1 100 0 0", " 1 1 -1 0 1")),
        ]
        for expected_code, relative, mutate in cases:
            with self.subTest(expected_code=expected_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence, _ = make_fixture(root)
                path = evidence / relative
                write(path, mutate(path.read_text(encoding="utf-8")))
                refresh_manifest(evidence)
                result, report = self.run_verifier(root, evidence)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report["error"]["code"], expected_code)

    def test_duplicate_timing_rows_fail_closed(self) -> None:
        cases = [
            ("final-nominal/ffpga/build/PNR_TIMING.log", " <DEFAULT> 1 1 -1 -1 1\n"),
            ("final-nominal/ffpga/build/PNR_TIMING.log", " <DEFAULT> 2 2 100 0 0\n"),
            ("final-nominal/ffpga/build/PNR_TIMING.log", " clk clk <DEFAULT> 18000 (0,1) 17000 58.8\n"),
            ("final-nominal/ffpga/build/PNR_TIMING.log", " clk clk <DEFAULT> bad (0,1) bad bad\n"),
            ("final-nominal/ffpga/build/PNR_PLACER_TIMING.log", f"PLACER-ESTIMATED-TIMING TSMC 40nm ULP {CORNERS[1]}\n"),
            ("final-nominal/ffpga/build/PNR_PLACER_TIMING.log", "PLACER-ESTIMATED-TIMING TSMC 40nm ULP\n"),
        ]
        for relative, extra in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence, _ = make_fixture(root)
                path = evidence / relative
                write(path, path.read_text(encoding="utf-8") + extra)
                refresh_manifest(evidence)
                result, report = self.run_verifier(root, evidence)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report["error"]["code"], "malformed_report")

    def test_extra_or_duplicate_xml_configuration_fails_closed(self) -> None:
        mutations = [
            lambda text: text.replace("</generateBitstream>", "<MAX_CPU>99</MAX_CPU></generateBitstream>"),
            lambda text: text.replace("</project>", "<synthesize><useABC9>true</useABC9></synthesize></project>"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence, _ = make_fixture(root)
                path = evidence / "final-nominal/timing.ffpga"
                write(path, mutate(path.read_text(encoding="utf-8")))
                refresh_manifest(evidence)
                result, _ = self.run_verifier(root, evidence)
                self.assertNotEqual(result.returncode, 0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, _ = make_fixture(root)
            paths = [root / "firmware/shrike/fpga/forgefpga/axiomos_r04.ffpga"]
            paths.extend(evidence / name / "timing.ffpga" for name in BUILDS)
            for path in paths:
                text = path.read_text(encoding="utf-8")
                write(path, text.replace("<option>same</option>", "<option>same</option><option>same</option>"))
            refresh_manifest(evidence)
            result, _ = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)

    def test_duplicate_pin_identities_fail_closed(self) -> None:
        cases = [
            (
                "report",
                "final-nominal/ffpga/build/PNR_IO.log",
                lambda text: "EFLX_CLK chip_tile_x=0, chip_tile_y=0, clk_side=W\nInput=1, pin=clk\n" + text,
            ),
            (
                "csv",
                "final-io-planner.csv",
                lambda text: text.replace("PORT;FUNCTION\n", "PORT;FUNCTION\nclk;WRONG\n"),
            ),
        ]
        for label, relative, mutate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence, _ = make_fixture(root)
                path = evidence / relative
                write(path, mutate(path.read_text(encoding="utf-8")))
                refresh_manifest(evidence)
                result, report = self.run_verifier(root, evidence)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report["error"]["code"], "pin_mismatch")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, _ = make_fixture(root)
            canonical = root / "firmware/shrike/fpga/forgefpga/axiomos_r04.ffpga"
            text = canonical.read_text(encoding="utf-8")
            duplicate = '<record id="CLK_t[0:0]_W_in0"><port-name>clk</port-name></record>'
            write(canonical, text.replace("</records>", duplicate + "</records>"))
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "malformed_config")

    def test_declared_corners_cannot_omit_a_required_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, expected = make_fixture(root)
            project = evidence / "final-guard-1/timing.ffpga"
            write(project, project.read_text(encoding="utf-8").replace(
                "<timingAnalysisCorner>1</timingAnalysisCorner>",
                "<timingAnalysisCorner>0</timingAnalysisCorner>",
            ))
            placer = evidence / "final-guard-1/ffpga/build/PNR_PLACER_TIMING.log"
            write(placer, placer.read_text(encoding="utf-8").replace(CORNERS[1], CORNERS[0]))
            expected["builds"][2]["corner"] = CORNERS[0]
            write(evidence / "results.json", json.dumps(expected))
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "corner_mismatch")

    def test_retained_json_rejects_duplicate_nonfinite_and_bool_number_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, expected = make_fixture(root)
            path = evidence / "results.json"
            write(path, path.read_text(encoding="utf-8").replace("{", '{"runtime_enabled":false,', 1))
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "malformed_report")

            expected["builds"][0]["setup_wns_ps"] = float("nan")
            write(path, json.dumps(expected))
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "malformed_report")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, expected = make_fixture(root)
            expected["runtime_enabled"] = 0
            write(evidence / "results.json", json.dumps(expected))
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "result_mismatch")

    def test_malformed_corner_returns_structured_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, _ = make_fixture(root)
            project = evidence / "final-guard-1/timing.ffpga"
            write(project, project.read_text(encoding="utf-8").replace(
                "<timingAnalysisCorner>1</timingAnalysisCorner>",
                "<timingAnalysisCorner>bad</timingAnalysisCorner>",
            ))
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["status"], "error")
            self.assertEqual(report["error"]["code"], "corner_mismatch")

    def test_pin_name_must_match_the_complete_producer_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, _ = make_fixture(root)
            path = evidence / "final-nominal/ffpga/build/PNR_IO.log"
            write(path, path.read_text(encoding="utf-8").replace("pin=clk\n", "pin=clk-invalid\n"))
            refresh_manifest(evidence)
            result, report = self.run_verifier(root, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report["error"]["code"], "pin_mismatch")

    def test_console_requires_one_exact_success_record(self) -> None:
        cases = [
            "Flow not successfully completed\n",
            "[2026-09-12 15:35:13.305] [Tcl] [info] Evaluation of /fixture/final-nominal.tcl successfully completed trailing\n",
            "[2026-09-12 15:35:13.305] [Tcl] [info] Evaluation of /fixture/final-nominal.tcl successfully completed\n" * 2,
        ]
        for contents in cases:
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence, _ = make_fixture(root)
                write(evidence / "final-nominal-console.log", contents)
                refresh_manifest(evidence)
                result, report = self.run_verifier(root, evidence)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report["error"]["code"], "malformed_report")


if __name__ == "__main__":
    unittest.main()
