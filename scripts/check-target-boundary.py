#!/usr/bin/env python3
"""Enforce the supported main-kernel and isolated experimental target boundary."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    targets = tomllib.loads((ROOT / "ci/targets.toml").read_text(encoding="utf-8"))["target"]
    by_name = {target["name"]: target for target in targets}

    require(by_name["x86_64 QEMU/OVMF"]["status"] == "supported", "x86_64 target lost support")
    require(
        by_name["Raspberry Pi 5"]["status"] == "supported after HIL",
        "Pi 5 support must remain conditional on physical HIL",
    )
    riscv_demo = by_name["RISC-V demo"]
    require(riscv_demo["status"] == "experimental standalone", "RISC-V demo status drifted")
    require(
        riscv_demo["artifact"] == "demo binary outside the axiomos release",
        "RISC-V demo entered the release artifact set",
    )

    kernel_manifest = (ROOT / "kernel/Cargo.toml").read_text(encoding="utf-8")
    require("riscv" not in kernel_manifest.lower(), "main kernel regained a RISC-V dependency or feature")

    forbidden = (
        "kernel/Cargo_riscv.toml",
        "kernel/linker-riscv64.ld",
        "kernel/src/main_riscv.rs",
        "kernel/src/main_riscv_minimal.rs",
        "kernel/src/arch/mod_new.rs",
    )
    for relative in forbidden:
        require(not (ROOT / relative).exists(), f"retired parallel target surface returned: {relative}")
    riscv_arch = ROOT / "kernel/src/arch/riscv64"
    require(
        not riscv_arch.exists() or not any(riscv_arch.rglob("*")),
        "retired main-kernel RISC-V architecture files returned",
    )

    demo_manifest = ROOT / "kernel/demos/riscv/Cargo.toml"
    require(demo_manifest.is_file(), "isolated RISC-V demo manifest is missing")
    demo = demo_manifest.read_text(encoding="utf-8")
    require("[workspace]" in demo, "RISC-V demo must remain isolated from the root workspace")

    components = (ROOT / "ci/components.toml").read_text(encoding="utf-8")
    require(
        'path = "kernel/demos/riscv/Cargo.toml"' in components
        and 'artifact = "experimental:riscv-kernel-demo"' in components,
        "component inventory lost the experimental RISC-V artifact",
    )

    print("supported target and entrypoint boundary: PASS")


if __name__ == "__main__":
    main()
