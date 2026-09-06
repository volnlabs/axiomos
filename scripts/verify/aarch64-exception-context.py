#!/usr/bin/env python3
"""Execute the production exception vectors with live register canaries in QEMU.

This is architectural/emulator evidence, not Pi5 hardware timing evidence.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "scripts/verify/fixtures/aarch64-exception-context"


def main():
    with tempfile.TemporaryDirectory(prefix="axiomos-exception-") as directory:
        elf = Path(directory) / "canary.elf"
        subprocess.run([
            "aarch64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie",
            "-Wl,--build-id=none", "-Wl,-T," + str(FIXTURE / "link.ld"),
            str(FIXTURE / "canary.S"),
            str(ROOT / "kernel/src/arch/aarch64/exception_vectors.S"),
            "-o", str(elf),
        ], check=True)
        result = subprocess.run([
            "qemu-system-aarch64", "-machine", "virt,gic-version=2",
            "-cpu", "cortex-a53", "-m", "128M", "-nographic",
            "-monitor", "none", "-semihosting-config", "enable=on,target=native",
            "-kernel", str(elf),
        ], capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        print(output, end="")
        if result.returncode != 0 or "PASS: production AArch64 SVC and IRQ preserve x0-x30" not in output:
            raise SystemExit("exception context canary failed")


if __name__ == "__main__":
    main()
