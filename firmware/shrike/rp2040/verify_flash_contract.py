#!/usr/bin/env python3
"""Verify the R0.4 firmware partition and cached recovery payloads."""

import argparse
import hashlib
import struct
import sys
import tomllib
from pathlib import Path


FIRMWARE_START = 0x10000000
FPGA_STORAGE_START = 0x10200000
UF2_BLOCK_SIZE = 512
UF2_MAGIC = (0x0A324655, 0x9E5D5157, 0x0AB16F30)
RECOVERY_FILES = {
    "main.py": "ce408fb16ee49d321131d28a4fc21ec9e28d4ea207c22e18ae0496d29f189fea",
    "blink_all.bin": "cd40b215efa40f272fe788202417d7f312a4e8f772fb06c2f96beafaf4fb65fd",
}


def fail(message: str) -> None:
    raise ValueError(message)


def check_layout(root: Path) -> None:
    memory_x = (root / "firmware/shrike/rp2040/memory.x").read_text()
    expected = "FLASH : ORIGIN = 0x10000100, LENGTH = 2048K - 0x100"
    if expected not in memory_x:
        fail("memory.x must reserve the upper 2 MiB for FPGA/storage")


def check_recovery_cache(root: Path) -> None:
    cache = root / "firmware/shrike/recovery/vicharak-763d0a7"
    for name, expected in RECOVERY_FILES.items():
        actual = hashlib.sha256((cache / name).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"recovery cache hash mismatch for {name}")


def check_factory_recovery(root: Path) -> None:
    cache = root / "firmware/shrike/recovery/vicharak-763d0a7"
    factory = tomllib.loads((cache / "SOURCE.toml").read_text())["factory_uf2"]
    required = ("file", "sha256", "board", "source")
    if not factory.get("ready") or any(not factory.get(key) for key in required):
        fail("NOT READY: custom flashing requires a board-compatible factory UF2 with source, board, and SHA-256")
    actual = hashlib.sha256((cache / factory["file"]).read_bytes()).hexdigest()
    if actual != factory["sha256"]:
        fail("factory UF2 hash mismatch")


def check_uf2(image: Path) -> None:
    data = image.read_bytes()
    if not data or len(data) % UF2_BLOCK_SIZE:
        fail("UF2 must contain complete 512-byte blocks")
    for offset in range(0, len(data), UF2_BLOCK_SIZE):
        block = data[offset : offset + UF2_BLOCK_SIZE]
        start0, start1, _flags, address, payload_size, *_ = struct.unpack("<IIIIIIII", block[:32])
        end = struct.unpack("<I", block[-4:])[0]
        if (start0, start1, end) != UF2_MAGIC:
            fail(f"invalid UF2 magic at block {offset // UF2_BLOCK_SIZE}")
        if payload_size > 476:
            fail(f"invalid UF2 payload length at block {offset // UF2_BLOCK_SIZE}")
        if address < FIRMWARE_START or address + payload_size > FPGA_STORAGE_START:
            fail("UF2 overlaps reserved FPGA/storage region")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--uf2", type=Path)
    parser.add_argument("--allow-missing-factory", action="store_true")
    parser.add_argument("--converter-version")
    args = parser.parse_args()
    try:
        check_layout(args.root)
        check_recovery_cache(args.root)
        if args.converter_version and args.converter_version != "2.2.0":
            fail("UF2 conversion requires elf2uf2-rs 2.2.0")
        if not args.allow_missing_factory:
            check_factory_recovery(args.root)
        if args.uf2:
            check_uf2(args.uf2)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
