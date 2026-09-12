#!/usr/bin/env python3
"""Host checks for the R0.4 W25Q32 contract."""

import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CHECK = ROOT / "firmware/shrike/rp2040/verify_flash_contract.py"
FLASH = ROOT / "firmware/shrike/rp2040/flash-uf2.sh"
BUILD = ROOT / "firmware/shrike/rp2040/build-uf2.sh"
FLASH_START = 0x10000000
FPGA_START = 0x10200000


def uf2_block(address: int) -> bytes:
    return struct.pack(
        "<IIIIIIII",
        0x0A324655,
        0x9E5D5157,
        0,
        address,
        16,
        0,
        1,
        0,
    ) + bytes(476) + struct.pack("<I", 0x0AB16F30)


class FlashContractTests(unittest.TestCase):
    def check(
        self,
        uf2: Path | None = None,
        *,
        allow_missing_factory: bool = True,
        converter_version: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = ["python3", str(CHECK), "--root", str(ROOT)]
        if allow_missing_factory:
            command.append("--allow-missing-factory")
        if uf2:
            command.extend(["--uf2", str(uf2)])
        if converter_version:
            command.extend(["--converter-version", converter_version])
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def test_committed_contract_and_recovery_cache_verify(self) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uf2_build_command_is_pinned(self) -> None:
        command = (ROOT / "firmware/shrike/rp2040/build-uf2.sh").read_text()
        self.assertIn("elf2uf2-rs@2.2.0", command)
        self.assertIn("cargo install --locked --force", command)
        self.assertIn("cargo build --locked --release", command)

    def test_recovery_is_not_ready_without_a_board_compatible_factory_uf2(self) -> None:
        result = self.check(allow_missing_factory=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOT READY", result.stderr)
        self.assertIn("board-compatible factory UF2", result.stderr)

    def test_rejects_a_different_converter_version(self) -> None:
        result = self.check(converter_version="2.1.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("elf2uf2-rs 2.2.0", result.stderr)

    def test_flash_script_cannot_copy_a_custom_uf2_without_factory_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "custom.uf2"
            mount = Path(directory) / "RPI-RP2"
            mount.mkdir()
            image.write_bytes(uf2_block(FLASH_START))
            image.with_suffix(".uf2.sha256").write_text(
                subprocess.check_output(["sha256sum", str(image)], text=True)
            )
            result = subprocess.run(
                [str(FLASH), str(image), str(mount)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("NOT READY", result.stderr)
            self.assertFalse((mount / image.name).exists())

    def test_flash_script_rejects_a_modified_in_range_uf2_before_copying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "custom.uf2"
            mount = Path(directory) / "RPI-RP2"
            mount.mkdir()
            image.write_bytes(uf2_block(FLASH_START))
            sidecar = image.with_suffix(".uf2.sha256")
            digest = subprocess.check_output(["sha256sum", str(image)], text=True)
            sidecar.write_text(digest)
            image.write_bytes(image.read_bytes()[:-5] + b"\x01" + image.read_bytes()[-4:])
            result = subprocess.run(
                [str(FLASH), str(image), str(mount)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("UF2 hash sidecar", result.stderr)
            self.assertFalse((mount / image.name).exists())

    def test_build_sidecar_accepts_documented_relative_uf2_path(self) -> None:
        subprocess.run([str(BUILD)], cwd=ROOT, check=True)
        image = Path("firmware/shrike/rp2040/target/thumbv6m-none-eabi/release/shrike_rp2040.uf2")
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory) / "RPI-RP2"
            mount.mkdir()
            result = subprocess.run(
                [str(FLASH), str(image), str(mount)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("NOT READY", result.stderr)
            self.assertFalse((mount / image.name).exists())

    def test_rejects_a_uf2_block_in_the_reserved_fpga_region(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "overlap.uf2"
            image.write_bytes(uf2_block(FPGA_START))
            result = self.check(image)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved FPGA/storage", result.stderr)

    def test_accepts_a_uf2_block_in_the_firmware_region(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "firmware.uf2"
            image.write_bytes(uf2_block(FLASH_START))
            result = self.check(image)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
