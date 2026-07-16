#!/usr/bin/env python3
"""Enforce ADR-0002 at supported boot and driver boundaries."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = (
    "panic!",
    ".unwrap(",
    ".expect(",
    "todo!",
    "unimplemented!",
)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def production_text(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    return source.split("#[cfg(test)]", 1)[0]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def reject_forbidden(relative: str, source: str) -> None:
    for token in FORBIDDEN:
        require(token not in source, f"{relative}: production boundary contains {token}")
    require(
        not re.search(r"Result\s*<[^>]+,\s*\(\)\s*>", source),
        f"{relative}: public operation collapses its error to ()",
    )
    require(
        "type Error = ();" not in source,
        f"{relative}: adapter collapses its error to ()",
    )


def main() -> None:
    adr = read("docs/adr/0002-kernel-error-policy.md")
    require("Boot prerequisite failure" in adr and "`BootError`" in adr, "ADR boot policy missing")
    require("Kernel invariant violation" in adr, "ADR invariant policy missing")

    boot = read("kernel/src/main.rs")
    reject_forbidden("kernel/src/main.rs", boot)
    require("enum BootError" in boot, "boot failures must have a typed BootError")
    require('"BOOT_FATAL code={}"' in boot, "boot fatal path must emit one stable record")
    require("fn boot_fatal(error: BootError) -> !" in boot, "boot fatal halt path missing")

    kernel = read("kernel/src/lib.rs")
    require("pub enum KernelInitError" in kernel, "kernel initialization must expose typed errors")
    require("pub fn init() -> Result<(), KernelInitError>" in kernel, "kernel init must be fallible")

    for relative in ("kernel/src/file/devfs.rs", "kernel/src/file/mod.rs"):
        reject_forbidden(relative, production_text(ROOT / relative))

    for relative in (
        "kernel/crates/kernel_physical_memory/src/types.rs",
        "kernel/crates/kernel_virtual_memory/src/addr.rs",
    ):
        source = production_text(ROOT / relative)
        require("Result<Self, ()>" not in source, f"{relative}: constructor uses a unit error")
        require("result_unit_err" not in source, f"{relative}: unit-error lint suppression remains")

    for relative in (
        "kernel/src/mcore/mtask/process/executable.rs",
        "kernel/src/mcore/mtask/process/fork.rs",
        "kernel/src/mcore/mtask/process/image.rs",
        "kernel/src/mcore/mtask/process/mem.rs",
    ):
        source = production_text(ROOT / relative)
        require(
            not re.search(r"Result\s*<[^\n]+,\s*&'static str\s*>", source),
            f"{relative}: process boundary collapses errors to &'static str",
        )

    address_space = production_text(ROOT / "kernel/src/mem/address_space/mod.rs")
    fork = address_space.split("pub fn fork", 1)[1]
    require(
        "Result<Self, AddressSpaceForkError>" in fork,
        "address-space fork must expose a typed error",
    )

    driver_root = ROOT / "kernel/src/driver"
    for path in sorted(driver_root.rglob("*.rs")):
        reject_forbidden(str(path.relative_to(ROOT)), production_text(path))

    fatal = read("kernel/src/fatal.rs")
    require("#[cfg(debug_assertions)]" in fatal and "panic!" in fatal, "debug fatal policy missing")
    require(
        "#[cfg(not(debug_assertions))]" in fatal and '"KERNEL_FATAL code={}"' in fatal,
        "release fatal policy must emit a bounded stable record",
    )

    block = read("kernel/src/driver/block.rs")
    register = block.split("pub fn register_block_device", 1)[1].split("pub fn by_id", 1)[0]
    require("RegisterBlockDeviceError" in block, "block registration needs a typed error")
    require(
        "let mut devices = BLOCK_DEVICES.write();" in register
        and "let mut devfs = devfs().write();" in register,
        "block and devfs publication must remain hidden behind their write guards",
    )
    require(
        register.index("register_file") < register.index("devices.insert"),
        "block registry publication must follow all fallible devfs preparation",
    )

    print("ADR-0002 designated-boundary conformance: PASS")


if __name__ == "__main__":
    main()
