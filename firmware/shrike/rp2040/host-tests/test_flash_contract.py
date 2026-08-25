#!/usr/bin/env python3
"""Host checks for the R0.4 W25Q32 contract."""

import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CHECK = ROOT / "firmware/shrike/rp2040/verify_flash_contract.py"
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
    def check(self, uf2: Path | None = None) -> subprocess.CompletedProcess[str]:
        command = ["python3", str(CHECK), "--root", str(ROOT)]
        if uf2:
            command.extend(["--uf2", str(uf2)])
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def test_committed_contract_and_recovery_cache_verify(self) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uf2_build_command_is_pinned(self) -> None:
        command = (ROOT / "firmware/shrike/rp2040/build-uf2.sh").read_text()
        self.assertIn("elf2uf2-rs@2.2.0", command)
        self.assertIn("cargo build --locked --release", command)

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
